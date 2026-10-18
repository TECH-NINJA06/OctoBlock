//! OctoBlock Layer 3 File-System Core (`octoblock-fs`).
//!
//! Implements the `OBF1` on-disk format, copy-on-write B+trees (inode, dentry, extent, xattr,
//! orphan), the 256-page group allocator, canonical JSONL changelog encoding, `mkfs`, `fsck`,
//! `dump`, and the differential in-memory reference model.

pub mod alloc;
pub mod fsck;
pub mod model;
pub mod oplog;
pub mod page;
pub mod tree;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use bytes::Bytes;

use crate::alloc::{InoRange, PageAllocator};
use crate::oplog::{OpKind, OpRecord, PageRunRef, encode_changelog};
use crate::page::{CLIENT_VERSION, CasePolicy, PageId, PageType, PathClass, Superblock};
use crate::tree::{
    CowBTree, DentryItem, EXT_HOLE, EXT_UNWRITTEN, Extent, INO_APPEND, INO_DAMAGED, INO_IMMUTABLE,
    InodeData, InodeRecord, MAX_INLINE_EXTENTS, decode_dentry_chain, dentry_hash,
    encode_dentry_chain, merge_extents, normalize_name,
};

/// Root directory inode number.
pub const ROOT_INO: u64 = 1;
/// Maximum hard links per inode (Section 4.5 / 4.10).
pub const MAX_NLINK: u32 = 65_000;
/// Maximum file name component length in bytes (`NAME_MAX`).
pub const MAX_NAME_LEN: usize = 255;
/// Maximum file size default (`256 MiB`, Section 2.1).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
/// Default soft live-data budget (`800 MB`, Section 2.1).
pub const DEFAULT_BUDGET_SOFT: u64 = 800 * 1024 * 1024;
/// Maximum extended attribute value length (`4,096 B`, Section 4.10).
pub const MAX_XATTR_VALUE: usize = 4096;
/// Maximum total extended attribute bytes per inode (`64 KB`, Section 4.10).
pub const MAX_XATTR_TOTAL: usize = 65_536;

/// POSIX file type mask.
pub const S_IFMT: u32 = 0o170_000;
/// Regular file mode bit.
pub const S_IFREG: u32 = 0o100_000;
/// Directory mode bit.
pub const S_IFDIR: u32 = 0o040_000;
/// Symbolic link mode bit.
pub const S_IFLNK: u32 = 0o120_000;
/// FIFO mode bit.
pub const S_IFIFO: u32 = 0o010_000;
/// Character device mode bit.
pub const S_IFCHR: u32 = 0o020_000;
/// Block device mode bit.
pub const S_IFBLK: u32 = 0o060_000;
/// Socket mode bit.
pub const S_IFSOCK: u32 = 0o140_000;

/// Linux `renameat2` flag: do not overwrite an existing target.
pub const RENAME_NOREPLACE: u32 = 1 << 0;
/// Linux `renameat2` flag: atomically exchange source and target.
pub const RENAME_EXCHANGE: u32 = 1 << 1;

/// Appendix A POSIX `errno` codes returned by `octoblock-fs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Errno {
    /// Operation not permitted (`Immutable` / `Append-only` violation).
    EPERM = 1,
    /// No such file or directory.
    ENOENT = 2,
    /// Input/output error (integrity check failure).
    EIO = 5,
    /// Argument list or extended attribute too long.
    E2BIG = 7,
    /// Try again / would block.
    EAGAIN = 11,
    /// Permission denied (or `exclude` path class).
    EACCES = 13,
    /// File or directory already exists.
    EEXIST = 17,
    /// Invalid cross-device or cross-class link/rename.
    EXDEV = 18,
    /// Not a directory.
    ENOTDIR = 20,
    /// Is a directory.
    EISDIR = 21,
    /// Invalid argument.
    EINVAL = 22,
    /// File too large (`> max_file_size`).
    EFBIG = 27,
    /// No space left on device (live budget or page-id space exhausted).
    ENOSPC = 28,
    /// Read-only file system.
    EROFS = 30,
    /// Too many links (`> 65,000`).
    EMLINK = 31,
    /// File name too long (`> 255` bytes).
    ENAMETOOLONG = 36,
    /// Function not implemented.
    ENOSYS = 38,
    /// Directory not empty.
    ENOTEMPTY = 39,
    /// Too many levels of symbolic links (`> 40`).
    ELOOP = 40,
    /// No data / extended attribute not found (`ENODATA` / `ENOATTR`).
    ENODATA = 61,
    /// Value too large for defined data type.
    EOVERFLOW = 75,
    /// Operation not supported (`EOPNOTSUPP`).
    EOPNOTSUPP = 95,
}

/// An OctoBlock file-system error carrying a canonical `Errno`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{errno:?}: {message}")]
pub struct Error {
    /// The POSIX errno value.
    pub errno: Errno,
    /// Diagnostic explanation.
    pub message: String,
}

impl Error {
    /// Construct a new file-system error with `errno` and `message`.
    pub fn new(errno: Errno, message: impl Into<String>) -> Self {
        Error {
            errno,
            message: message.into(),
        }
    }
}

/// Result alias for `octoblock-fs`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Directory listing entry returned by `Volume::readdir`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// Entry name bytes.
    pub name: Vec<u8>,
    /// Target inode number.
    pub ino: u64,
    /// POSIX `d_type` byte.
    pub file_type: u8,
    /// Stable cookie for resuming `readdir` (`telldir`/`seekdir`, Section 4.6).
    pub cookie: u64,
}

/// Summary produced when `Volume::commit_group` finalizes a commit group.
#[derive(Clone, Debug)]
pub struct CommittedGroup {
    /// New volume epoch.
    pub epoch: u64,
    /// Canonical JSONL changelog bytes for the committed group.
    pub changelog: Bytes,
    /// Number of operations recorded in the group.
    pub ops_count: usize,
}

/// In-memory representation of a mounted OctoBlock volume over a page map (`PageId -> Bytes`).
pub struct Volume {
    pub(crate) sb: Superblock,
    pub(crate) pages: BTreeMap<PageId, Bytes>,
    pub(crate) alloc: PageAllocator,
    mount_id: u64,
    read_only: bool,
    ino_range: Option<InoRange>,
    seq: u64,
    clock_ns: i64,
    open_counts: BTreeMap<u64, u32>,
    pending_ops: Vec<OpRecord>,
    budget_soft: u64,
    max_file_size: u64,
}

impl Volume {
    /// Format a new `OBF1` volume with `page_size` (4096, 8192, or 16384), `uuid`, and `case_policy`.
    pub fn mkfs(
        page_size: usize,
        uuid: [u8; 16],
        case_policy: CasePolicy,
        mount_id: u64,
    ) -> Result<Self> {
        let mut sb = Superblock::new(page_size, uuid, case_policy)?;
        let mut pages = BTreeMap::new();
        let mut alloc = PageAllocator::new(&sb, mount_id);

        let now_ns = 1_791_371_042_000_000_000i64;
        let mut root_inode = InodeRecord {
            ino: ROOT_INO,
            mode: S_IFDIR | 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blocks: 0,
            atime: now_ns,
            mtime: now_ns,
            ctime: now_ns,
            btime: now_ns,
            flags: 0,
            generation: 0,
            xattr_root: None,
            data: InodeData::Inline(Vec::new()),
        };
        root_inode.sync_data_flags();

        let inode_tree = CowBTree::new(PageType::InodeTree, page_size);
        sb.inode_root = inode_tree.insert(
            &mut pages,
            &mut alloc,
            0,
            sb.epoch,
            ROOT_INO.to_be_bytes().to_vec(),
            root_inode.encode(),
        )?;
        sb.inode_count = 1;
        sb.live_pages = alloc.live_pages();
        sb.live_bytes = sb.live_pages * (page_size as u64);

        alloc.write_free_map_pages(&sb, sb.epoch, &mut pages)?;
        pages.insert(PageId::SUPERBLOCK, sb.encode());
        alloc.begin_group();

        Ok(Volume {
            sb,
            pages,
            alloc,
            mount_id,
            read_only: false,
            ino_range: None,
            seq: 18_210,
            clock_ns: now_ns,
            open_counts: BTreeMap::new(),
            pending_ops: Vec::new(),
            budget_soft: DEFAULT_BUDGET_SOFT,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        })
    }

    /// Mount an existing `OBF1` page map and reclaim any orphan inodes from a previous crash (Section 4.8 & 6.9).
    pub fn mount(
        pages: BTreeMap<PageId, Bytes>,
        read_write: bool,
        mount_id: u64,
    ) -> Result<Self> {
        let sb_bytes = pages
            .get(&PageId::SUPERBLOCK)
            .ok_or_else(|| Error::new(Errno::EIO, "missing superblock (page 0)"))?
            .clone();
        let sb = Superblock::decode(sb_bytes)?;
        sb.check_mount(read_write, CLIENT_VERSION)?;

        let alloc = PageAllocator::load_from_store(&sb, mount_id, &pages, &BTreeSet::new())?;
        let mut vol = Volume {
            sb,
            pages,
            alloc,
            mount_id,
            read_only: !read_write,
            ino_range: None,
            seq: 18_210,
            clock_ns: 1_791_371_042_000_000_000,
            open_counts: BTreeMap::new(),
            pending_ops: Vec::new(),
            budget_soft: DEFAULT_BUDGET_SOFT,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        };
        if read_write {
            vol.reclaim_orphans()?;
        }
        Ok(vol)
    }

    /// Mount ID associated with this volume instance.
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    /// Current superblock state.
    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// Clone the underlying page map (for snapshot tests and crash-injection harnesses).
    pub fn clone_storage(&self) -> BTreeMap<PageId, Bytes> {
        self.pages.clone()
    }

    /// Override the soft live-data budget in bytes (EC-S07).
    pub fn set_budget_soft(&mut self, bytes: u64) {
        self.budget_soft = bytes;
    }

    /// Set the `.octoblock/policy.toml` blob SHA in the superblock (Section 4.4).
    pub fn set_policy_sha(&mut self, sha: Vec<u8>) {
        self.sb.policy_sha = sha;
    }

    /// Update the 2-bit [`PathClass`] stored in an inode's flags (Section 5.3).
    pub fn set_inode_path_class(&mut self, ino: u64, class: PathClass) -> Result<()> {
        let mut rec = self.getattr(ino)?;
        rec.set_path_class(class);
        self.put_inode(rec)
    }

    fn check_writable(&self, allocating: bool) -> Result<()> {
        if self.read_only {
            return Err(Error::new(Errno::EROFS, "volume is mounted read-only"));
        }
        if allocating {
            let live_bytes = self.alloc.live_pages() * (self.sb.page_size as u64);
            if live_bytes >= self.budget_soft {
                return Err(Error::new(
                    Errno::ENOSPC,
                    format!(
                        "live bytes ({live_bytes}) reached soft budget ({})",
                        self.budget_soft
                    ),
                ));
            }
        }
        Ok(())
    }

    fn tick_ns(&mut self) -> i64 {
        self.clock_ns += 1_000_000; // +1 ms per op
        self.clock_ns
    }

    fn next_seq(&mut self) -> (u64, f64) {
        self.seq += 1;
        let t = (self.clock_ns as f64) / 1_000_000_000.0;
        (self.seq, t)
    }

    fn allocate_ino(&mut self) -> (u64, [u64; 2]) {
        if self.ino_range.is_none()
            || self.ino_range.as_ref().unwrap().next
                > self.ino_range.as_ref().unwrap().end_inclusive
        {
            self.ino_range = Some(InoRange::reserve(&mut self.sb));
        }
        let range = self.ino_range.as_mut().unwrap();
        let ino = range.allocate().expect("freshly reserved range");
        (ino, [range.start, range.end_inclusive])
    }

    fn inode_tree(&self) -> CowBTree {
        CowBTree::new(PageType::InodeTree, self.sb.page_size as usize)
    }

    fn dentry_tree(&self) -> CowBTree {
        CowBTree::new(PageType::DentryTree, self.sb.page_size as usize)
    }

    fn extent_tree(&self) -> CowBTree {
        CowBTree::new(PageType::ExtentTree, self.sb.page_size as usize)
    }

    fn xattr_tree(&self) -> CowBTree {
        CowBTree::new(PageType::XattrLeaf, self.sb.page_size as usize)
    }

    fn orphan_tree(&self) -> CowBTree {
        CowBTree::new(PageType::OrphanLeaf, self.sb.page_size as usize)
    }

    fn sync_counters(&mut self) {
        self.sb.live_pages = self.alloc.live_pages();
        self.sb.live_bytes = self.sb.live_pages * (self.sb.page_size as u64);
    }

    /// Read an inode record by number (`ENOENT` if absent).
    pub fn getattr(&self, ino: u64) -> Result<InodeRecord> {
        let raw = self
            .inode_tree()
            .get(
                &self.pages,
                self.sb.inode_root,
                self.sb.epoch,
                &ino.to_be_bytes(),
            )?
            .ok_or_else(|| Error::new(Errno::ENOENT, format!("inode {ino} not found")))?;
        InodeRecord::decode(&raw)
    }

    fn put_inode(&mut self, mut rec: InodeRecord) -> Result<()> {
        rec.sync_data_flags();
        let tree = self.inode_tree();
        self.sb.inode_root = tree.insert(
            &mut self.pages,
            &mut self.alloc,
            self.sb.inode_root,
            self.sb.epoch,
            rec.ino.to_be_bytes().to_vec(),
            rec.encode(),
        )?;
        self.sync_counters();
        Ok(())
    }

    fn validate_name(name: &[u8]) -> Result<()> {
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
        {
            return Err(Error::new(Errno::EINVAL, "invalid directory entry name"));
        }
        if name.len() > MAX_NAME_LEN {
            return Err(Error::new(Errno::ENAMETOOLONG, "name exceeds 255 bytes"));
        }
        Ok(())
    }

    fn dentry_key(&self, dir_ino: u64, name: &[u8]) -> [u8; 16] {
        let h = dentry_hash(&self.sb.uuid, name, self.sb.case_policy);
        let mut key = [0u8; 16];
        key[0..8].copy_from_slice(&dir_ino.to_be_bytes());
        key[8..16].copy_from_slice(&h.to_be_bytes());
        key
    }

    fn names_equal(&self, a: &[u8], b: &[u8]) -> bool {
        normalize_name(a, self.sb.case_policy) == normalize_name(b, self.sb.case_policy)
    }

    /// Look up `name` inside `dir_ino` and return the child inode number (`ENOENT` if absent).
    pub fn lookup(&self, dir_ino: u64, name: &[u8]) -> Result<u64> {
        Self::validate_name(name)?;
        let parent = self.getattr(dir_ino)?;
        if (parent.mode & S_IFDIR) == 0 {
            return Err(Error::new(Errno::ENOTDIR, "parent is not a directory"));
        }
        let key = self.dentry_key(dir_ino, name);
        let Some(raw) =
            self.dentry_tree()
                .get(&self.pages, self.sb.dentry_root, self.sb.epoch, &key)?
        else {
            return Err(Error::new(Errno::ENOENT, "entry not found"));
        };
        let chain = decode_dentry_chain(&raw)?;
        chain
            .into_iter()
            .find(|item| self.names_equal(&item.name, name))
            .map(|item| item.child_ino)
            .ok_or_else(|| Error::new(Errno::ENOENT, "entry not found"))
    }

    fn insert_dentry(
        &mut self,
        dir_ino: u64,
        name: &[u8],
        child_ino: u64,
        file_type: u8,
    ) -> Result<()> {
        let key = self.dentry_key(dir_ino, name);
        let tree = self.dentry_tree();
        let mut chain = match tree.get(&self.pages, self.sb.dentry_root, self.sb.epoch, &key)? {
            Some(raw) => decode_dentry_chain(&raw)?,
            None => Vec::new(),
        };
        if chain.iter().any(|i| self.names_equal(&i.name, name)) {
            return Err(Error::new(Errno::EEXIST, "directory entry already exists"));
        }
        let used_indices: BTreeSet<u8> = chain.iter().map(|i| i.collision_idx).collect();
        let collision_idx = (0..=254u8)
            .find(|idx| !used_indices.contains(idx))
            .ok_or_else(|| Error::new(Errno::ENOSPC, "hash bucket collision chain full"))?;
        chain.push(DentryItem {
            collision_idx,
            file_type,
            child_ino,
            name: name.to_vec(),
        });
        chain.sort_by_key(|i| i.collision_idx);
        self.sb.dentry_root = tree.insert(
            &mut self.pages,
            &mut self.alloc,
            self.sb.dentry_root,
            self.sb.epoch,
            key.to_vec(),
            encode_dentry_chain(&chain),
        )?;
        self.sync_counters();
        Ok(())
    }

    fn remove_dentry(&mut self, dir_ino: u64, name: &[u8]) -> Result<DentryItem> {
        let key = self.dentry_key(dir_ino, name);
        let tree = self.dentry_tree();
        let raw = tree
            .get(&self.pages, self.sb.dentry_root, self.sb.epoch, &key)?
            .ok_or_else(|| Error::new(Errno::ENOENT, "directory entry not found"))?;
        let mut chain = decode_dentry_chain(&raw)?;
        let pos = chain
            .iter()
            .position(|i| self.names_equal(&i.name, name))
            .ok_or_else(|| Error::new(Errno::ENOENT, "directory entry not found"))?;
        let removed = chain.remove(pos);
        if chain.is_empty() {
            let (new_root, _) = tree.remove(
                &mut self.pages,
                &mut self.alloc,
                self.sb.dentry_root,
                self.sb.epoch,
                &key,
            )?;
            self.sb.dentry_root = new_root;
        } else {
            self.sb.dentry_root = tree.insert(
                &mut self.pages,
                &mut self.alloc,
                self.sb.dentry_root,
                self.sb.epoch,
                key.to_vec(),
                encode_dentry_chain(&chain),
            )?;
        }
        self.sync_counters();
        Ok(removed)
    }

    /// List entries of `dir_ino` starting after `after_cookie` (`0` = from start).
    pub fn readdir(&self, dir_ino: u64, after_cookie: u64) -> Result<Vec<DirEntry>> {
        let dir = self.getattr(dir_ino)?;
        if (dir.mode & S_IFDIR) == 0 {
            return Err(Error::new(Errno::ENOTDIR, "readdir on non-directory"));
        }
        let prefix = dir_ino.to_be_bytes();
        let buckets = self.dentry_tree().scan_prefix(
            &self.pages,
            self.sb.dentry_root,
            self.sb.epoch,
            &prefix,
        )?;
        let mut out = Vec::new();
        for (k, v) in buckets {
            let bucket_hash = u64::from_be_bytes(k[8..16].try_into().unwrap());
            for item in decode_dentry_chain(&v)? {
                let cookie = item.cookie(bucket_hash);
                if cookie > after_cookie {
                    out.push(DirEntry {
                        name: item.name,
                        ino: item.child_ino,
                        file_type: item.file_type,
                        cookie,
                    });
                }
            }
        }
        out.sort_by_key(|e| e.cookie);
        Ok(out)
    }

    /// Create a regular file inside `parent_ino` and return its new inode number.
    pub fn create(
        &mut self,
        parent_ino: u64,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        self.create_node(
            parent_ino,
            name,
            S_IFREG | (mode & 0o7777),
            uid,
            gid,
            0,
            None,
        )
    }

    /// Create a directory inside `parent_ino` and return its new inode number.
    pub fn mkdir(
        &mut self,
        parent_ino: u64,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        self.create_node(
            parent_ino,
            name,
            S_IFDIR | (mode & 0o7777),
            uid,
            gid,
            0,
            None,
        )
    }

    /// Create a symbolic link inside `parent_ino` pointing to `target`.
    pub fn symlink(
        &mut self,
        parent_ino: u64,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        if target.is_empty() || target.len() > 4096 {
            return Err(Error::new(
                Errno::ENAMETOOLONG,
                "invalid symlink target length",
            ));
        }
        self.create_node(
            parent_ino,
            name,
            S_IFLNK | 0o777,
            uid,
            gid,
            0,
            Some(target),
        )
    }

    /// Create a special node (FIFO, socket, char/block device).
    pub fn mknod(
        &mut self,
        parent_ino: u64,
        name: &[u8],
        mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        self.create_node(parent_ino, name, mode, uid, gid, rdev, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_node(
        &mut self,
        parent_ino: u64,
        name: &[u8],
        full_mode: u32,
        uid: u32,
        gid: u32,
        rdev: u64,
        symlink_target: Option<&[u8]>,
    ) -> Result<u64> {
        self.check_writable(true)?;
        Self::validate_name(name)?;
        let mut parent = self.getattr(parent_ino)?;
        if (parent.mode & S_IFDIR) == 0 {
            return Err(Error::new(Errno::ENOTDIR, "parent is not a directory"));
        }
        if (parent.flags & INO_IMMUTABLE) != 0 {
            return Err(Error::new(Errno::EPERM, "parent directory is immutable"));
        }
        if parent.path_class() == PathClass::Exclude {
            return Err(Error::new(Errno::EACCES, "path is excluded by policy"));
        }
        let is_dir = (full_mode & S_IFMT) == S_IFDIR;
        if is_dir && parent.nlink >= MAX_NLINK {
            return Err(Error::new(Errno::EMLINK, "parent directory max links reached"));
        }

        let now = self.tick_ns();
        let (ino, range) = self.allocate_ino();
        let d_type = ((full_mode & S_IFMT) >> 12) as u8;
        self.insert_dentry(parent_ino, name, ino, d_type)?;

        let mut rec = InodeRecord {
            ino,
            mode: full_mode,
            nlink: if is_dir { 2 } else { 1 },
            uid,
            gid,
            rdev,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            btime: now,
            flags: 0,
            generation: 0,
            xattr_root: None,
            data: InodeData::Inline(Vec::new()),
        };
        rec.set_path_class(parent.path_class());
        self.put_inode(rec)?;
        self.sb.inode_count += 1;

        if is_dir {
            parent.nlink += 1;
        }
        parent.mtime = now;
        parent.ctime = now;
        self.put_inode(parent)?;

        if let Some(target) = symlink_target {
            self.write_internal(ino, 0, target, false)?;
        }

        let op_name = if is_dir {
            "mkdir"
        } else if symlink_target.is_some() {
            "symlink"
        } else if (full_mode & S_IFMT) == S_IFREG {
            "create"
        } else {
            "mknod"
        };
        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid,
            gid,
            kind: OpKind::Create {
                op_name: op_name.into(),
                parent: parent_ino,
                name: String::from_utf8_lossy(name).into_owned(),
                mode: full_mode,
                ino_range: range,
                ino,
                target: symlink_target.map(|b| String::from_utf8_lossy(b).into_owned()),
            },
        });
        Ok(ino)
    }

    /// Create a hard link to `target_ino` under `(new_parent, new_name)` (Section 8, REQ-10).
    pub fn link(&mut self, target_ino: u64, new_parent: u64, new_name: &[u8]) -> Result<()> {
        self.check_writable(true)?;
        Self::validate_name(new_name)?;
        let mut target = self.getattr(target_ino)?;
        if (target.mode & S_IFMT) == S_IFDIR {
            return Err(Error::new(Errno::EPERM, "cannot hard-link a directory"));
        }
        if (target.flags & INO_IMMUTABLE) != 0 {
            return Err(Error::new(Errno::EPERM, "cannot link an immutable inode"));
        }
        if target.nlink >= MAX_NLINK {
            return Err(Error::new(Errno::EMLINK, "inode max links (65,000) reached"));
        }
        let mut parent = self.getattr(new_parent)?;
        if (parent.mode & S_IFDIR) == 0 {
            return Err(Error::new(Errno::ENOTDIR, "new_parent is not a directory"));
        }
        // REQ-10: Cross-class link MUST return EXDEV.
        if target.path_class() != parent.path_class() {
            return Err(Error::new(
                Errno::EXDEV,
                "cross-class link refused (REQ-10)",
            ));
        }

        let d_type = ((target.mode & S_IFMT) >> 12) as u8;
        self.insert_dentry(new_parent, new_name, target_ino, d_type)?;

        let now = self.tick_ns();
        target.nlink += 1;
        target.ctime = now;
        self.put_inode(target)?;

        parent.mtime = now;
        parent.ctime = now;
        self.put_inode(parent)?;

        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Link {
                ino: target_ino,
                parent: new_parent,
                name: String::from_utf8_lossy(new_name).into_owned(),
            },
        });
        Ok(())
    }

    /// Track an open file handle on `ino` (for orphan lifetime across unlinks, EC-O01).
    pub fn open_handle(&mut self, ino: u64) -> Result<()> {
        let _ = self.getattr(ino)?;
        *self.open_counts.entry(ino).or_insert(0) += 1;
        Ok(())
    }

    /// Release an open file handle on `ino`; if `nlink == 0` and last handle closed, reclaim it.
    pub fn close_handle(&mut self, ino: u64) -> Result<()> {
        let Some(count) = self.open_counts.get_mut(&ino) else {
            return Ok(());
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.open_counts.remove(&ino);
            if let Ok(rec) = self.getattr(ino)
                && rec.nlink == 0
            {
                let (new_orphan_root, _) = self.orphan_tree().remove(
                    &mut self.pages,
                    &mut self.alloc,
                    self.sb.orphan_root,
                    self.sb.epoch,
                    &ino.to_be_bytes(),
                )?;
                self.sb.orphan_root = new_orphan_root;
                self.purge_inode(rec)?;
            }
        }
        Ok(())
    }

    /// Unlink a non-directory entry from `parent_ino` (frees space even at soft quota limit, EC-S06).
    pub fn unlink(&mut self, parent_ino: u64, name: &[u8]) -> Result<()> {
        self.check_writable(false)?;
        let child_ino = self.lookup(parent_ino, name)?;
        let mut child = self.getattr(child_ino)?;
        if (child.mode & S_IFMT) == S_IFDIR {
            return Err(Error::new(Errno::EISDIR, "cannot unlink a directory"));
        }
        if (child.flags & (INO_IMMUTABLE | INO_APPEND)) != 0 {
            return Err(Error::new(Errno::EPERM, "cannot unlink immutable/append file"));
        }

        self.remove_dentry(parent_ino, name)?;
        let now = self.tick_ns();
        let mut parent = self.getattr(parent_ino)?;
        parent.mtime = now;
        parent.ctime = now;
        self.put_inode(parent)?;

        child.nlink = child.nlink.saturating_sub(1);
        child.ctime = now;
        if child.nlink > 0 {
            self.put_inode(child)?;
        } else if self.open_counts.get(&child_ino).copied().unwrap_or(0) > 0 {
            // Section 4.8 & EC-O01: Still open -> add to orphan tree.
            self.put_inode(child)?;
            self.sb.orphan_root = self.orphan_tree().insert(
                &mut self.pages,
                &mut self.alloc,
                self.sb.orphan_root,
                self.sb.epoch,
                child_ino.to_be_bytes().to_vec(),
                vec![1],
            )?;
            self.sync_counters();
        } else {
            self.purge_inode(child)?;
        }

        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Unlink {
                op_name: "unlink".into(),
                parent: parent_ino,
                name: String::from_utf8_lossy(name).into_owned(),
                ino: child_ino,
            },
        });
        Ok(())
    }

    /// Remove an empty directory from `parent_ino`.
    pub fn rmdir(&mut self, parent_ino: u64, name: &[u8]) -> Result<()> {
        self.check_writable(false)?;
        let child_ino = self.lookup(parent_ino, name)?;
        if child_ino == ROOT_INO {
            return Err(Error::new(Errno::EINVAL, "cannot rmdir root directory"));
        }
        let child = self.getattr(child_ino)?;
        if (child.mode & S_IFMT) != S_IFDIR {
            return Err(Error::new(Errno::ENOTDIR, "target is not a directory"));
        }
        if !self.readdir(child_ino, 0)?.is_empty() {
            return Err(Error::new(Errno::ENOTEMPTY, "directory is not empty"));
        }

        self.remove_dentry(parent_ino, name)?;
        self.purge_inode(child)?;

        let now = self.tick_ns();
        let mut parent = self.getattr(parent_ino)?;
        parent.nlink = parent.nlink.saturating_sub(1).max(2);
        parent.mtime = now;
        parent.ctime = now;
        self.put_inode(parent)?;

        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Unlink {
                op_name: "rmdir".into(),
                parent: parent_ino,
                name: String::from_utf8_lossy(name).into_owned(),
                ino: child_ino,
            },
        });
        Ok(())
    }

    /// Atomic rename supporting `0`, `RENAME_NOREPLACE`, and `RENAME_EXCHANGE` (Section 3.5, 5.3, 8).
    pub fn rename(
        &mut self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        flags: u32,
    ) -> Result<()> {
        self.check_writable(false)?;
        Self::validate_name(old_name)?;
        Self::validate_name(new_name)?;

        let src_ino = self.lookup(old_parent, old_name)?;
        let src_rec = self.getattr(src_ino)?;
        let dst_parent_rec = self.getattr(new_parent)?;

        // REQ-10: Cross-class rename MUST return EXDEV.
        if src_rec.path_class() != dst_parent_rec.path_class() {
            return Err(Error::new(
                Errno::EXDEV,
                "cross-class rename refused (REQ-10)",
            ));
        }
        if old_parent == new_parent && self.names_equal(old_name, new_name) {
            return Ok(());
        }

        // EC-N10: Prevent moving a directory into its own descendant.
        if (src_rec.mode & S_IFMT) == S_IFDIR && self.is_descendant_dir(new_parent, src_ino)? {
            return Err(Error::new(
                Errno::EINVAL,
                "cannot rename directory into its own descendant (EC-N10)",
            ));
        }

        let dst_lookup = self.lookup(new_parent, new_name).ok();
        if (flags & RENAME_NOREPLACE) != 0 && dst_lookup.is_some() {
            return Err(Error::new(Errno::EEXIST, "target exists (RENAME_NOREPLACE)"));
        }

        if (flags & RENAME_EXCHANGE) != 0 {
            let dst_ino =
                dst_lookup.ok_or_else(|| Error::new(Errno::ENOENT, "exchange target missing"))?;
            let dst_rec = self.getattr(dst_ino)?;
            if (dst_rec.mode & S_IFMT) == S_IFDIR && self.is_descendant_dir(old_parent, dst_ino)? {
                return Err(Error::new(Errno::EINVAL, "exchange would create loop"));
            }
            let src_item = self.remove_dentry(old_parent, old_name)?;
            let dst_item = self.remove_dentry(new_parent, new_name)?;
            self.insert_dentry(old_parent, old_name, dst_ino, dst_item.file_type)?;
            self.insert_dentry(new_parent, new_name, src_ino, src_item.file_type)?;
        } else {
            if let Some(dst_ino) = dst_lookup {
                if dst_ino == src_ino {
                    self.remove_dentry(old_parent, old_name)?;
                    return Ok(());
                }
                let mut dst_rec = self.getattr(dst_ino)?;
                let src_is_dir = (src_rec.mode & S_IFMT) == S_IFDIR;
                let dst_is_dir = (dst_rec.mode & S_IFMT) == S_IFDIR;
                // EC-N11: Type compatibility checks.
                if src_is_dir && !dst_is_dir {
                    return Err(Error::new(Errno::ENOTDIR, "cannot overwrite non-dir with dir"));
                }
                if !src_is_dir && dst_is_dir {
                    return Err(Error::new(Errno::EISDIR, "cannot overwrite dir with non-dir"));
                }
                if dst_is_dir && !self.readdir(dst_ino, 0)?.is_empty() {
                    return Err(Error::new(Errno::ENOTEMPTY, "target directory not empty"));
                }
                self.remove_dentry(new_parent, new_name)?;
                if dst_is_dir {
                    self.purge_inode(dst_rec)?;
                    let mut np = self.getattr(new_parent)?;
                    np.nlink = np.nlink.saturating_sub(1).max(2);
                    self.put_inode(np)?;
                } else {
                    dst_rec.nlink = dst_rec.nlink.saturating_sub(1);
                    if dst_rec.nlink > 0 {
                        self.put_inode(dst_rec)?;
                    } else if self.open_counts.get(&dst_ino).copied().unwrap_or(0) > 0 {
                        self.put_inode(dst_rec)?;
                        self.sb.orphan_root = self.orphan_tree().insert(
                            &mut self.pages,
                            &mut self.alloc,
                            self.sb.orphan_root,
                            self.sb.epoch,
                            dst_ino.to_be_bytes().to_vec(),
                            vec![1],
                        )?;
                    } else {
                        self.purge_inode(dst_rec)?;
                    }
                }
            }
            let src_item = self.remove_dentry(old_parent, old_name)?;
            self.insert_dentry(new_parent, new_name, src_ino, src_item.file_type)?;
            if (src_rec.mode & S_IFMT) == S_IFDIR && old_parent != new_parent {
                let mut op = self.getattr(old_parent)?;
                op.nlink = op.nlink.saturating_sub(1).max(2);
                self.put_inode(op)?;
                let mut np = self.getattr(new_parent)?;
                np.nlink += 1;
                self.put_inode(np)?;
            }
        }

        let now = self.tick_ns();
        for p_ino in [old_parent, new_parent] {
            if let Ok(mut p) = self.getattr(p_ino) {
                p.mtime = now;
                p.ctime = now;
                self.put_inode(p)?;
            }
        }
        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Rename {
                old: (old_parent, String::from_utf8_lossy(old_name).into_owned()),
                new: (new_parent, String::from_utf8_lossy(new_name).into_owned()),
                flags,
            },
        });
        Ok(())
    }

    fn is_descendant_dir(&self, candidate_dir: u64, ancestor_dir: u64) -> Result<bool> {
        if candidate_dir == ancestor_dir {
            return Ok(true);
        }
        let mut stack = vec![ancestor_dir];
        let mut visited = BTreeSet::new();
        while let Some(curr) = stack.pop() {
            if !visited.insert(curr) {
                continue;
            }
            for entry in self.readdir(curr, 0)? {
                if entry.ino == candidate_dir {
                    return Ok(true);
                }
                if let Ok(rec) = self.getattr(entry.ino)
                    && (rec.mode & S_IFMT) == S_IFDIR
                {
                    stack.push(entry.ino);
                }
            }
        }
        Ok(false)
    }

    // ------------------------------------------------------------------ Extents, Data I/O & Orphans

    fn load_extents(&self, rec: &InodeRecord) -> Result<Vec<Extent>> {
        match &rec.data {
            InodeData::Inline(_) => Ok(Vec::new()),
            InodeData::Extents(list) => Ok(list.clone()),
            InodeData::ExtentTree(root_id) => {
                let cells = self.extent_tree().all_entries(
                    &self.pages,
                    root_id.get(),
                    self.sb.epoch,
                )?;
                let mut out = Vec::with_capacity(cells.len());
                for (_, v) in cells {
                    out.push(Extent::decode(&v)?);
                }
                Ok(out)
            }
        }
    }

    fn save_extents(&mut self, rec: &mut InodeRecord, mut extents: Vec<Extent>) -> Result<()> {
        merge_extents(&mut extents);
        rec.blocks = extents
            .iter()
            .filter(|e| !e.is_hole())
            .map(|e| e.len as u64)
            .sum();

        // Free any previous per-file extent B+tree nodes before writing the new state.
        if let InodeData::ExtentTree(old_root) = rec.data {
            let mut old_nodes = BTreeSet::new();
            self.extent_tree().collect_node_ids(
                &self.pages,
                old_root.get(),
                self.sb.epoch,
                &mut old_nodes,
            )?;
            for id in old_nodes {
                self.alloc.free_page(id);
                self.pages.remove(&id);
            }
        }

        if extents.len() <= MAX_INLINE_EXTENTS {
            rec.data = InodeData::Extents(extents);
        } else {
            let tree = self.extent_tree();
            let mut root = 0u32;
            for ext in &extents {
                let mut val = Vec::with_capacity(10);
                ext.encode(&mut val);
                root = tree.insert(
                    &mut self.pages,
                    &mut self.alloc,
                    root,
                    self.sb.epoch,
                    ext.file_page.to_be_bytes().to_vec(),
                    val,
                )?;
            }
            rec.data = InodeData::ExtentTree(PageId::new(root)?);
        }
        rec.sync_data_flags();
        Ok(())
    }

    fn purge_inode(&mut self, rec: InodeRecord) -> Result<()> {
        let extents = self.load_extents(&rec)?;
        for ext in extents {
            if !ext.is_hole() {
                for i in 0..(ext.len as u32) {
                    if let Ok(pid) = PageId::new(ext.page_id.get() + i) {
                        self.alloc.free_page(pid);
                        self.pages.remove(&pid);
                    }
                }
            }
        }
        if let InodeData::ExtentTree(root_id) = rec.data {
            let mut nodes = BTreeSet::new();
            let _ = self.extent_tree().collect_node_ids(
                &self.pages,
                root_id.get(),
                self.sb.epoch,
                &mut nodes,
            );
            for id in nodes {
                self.alloc.free_page(id);
                self.pages.remove(&id);
            }
        }
        if let Some(xroot) = rec.xattr_root {
            let mut nodes = BTreeSet::new();
            let _ = self.xattr_tree().collect_node_ids(
                &self.pages,
                xroot.get(),
                self.sb.epoch,
                &mut nodes,
            );
            for id in nodes {
                self.alloc.free_page(id);
                self.pages.remove(&id);
            }
        }
        let (new_root, _) = self.inode_tree().remove(
            &mut self.pages,
            &mut self.alloc,
            self.sb.inode_root,
            self.sb.epoch,
            &rec.ino.to_be_bytes(),
        )?;
        self.sb.inode_root = new_root;
        self.sb.inode_count = self.sb.inode_count.saturating_sub(1);
        self.sync_counters();
        Ok(())
    }

    /// Reclaim all orphan inodes recorded in the orphan tree (Section 4.8 & 6.9).
    pub fn reclaim_orphans(&mut self) -> Result<usize> {
        let entries =
            self.orphan_tree()
                .all_entries(&self.pages, self.sb.orphan_root, self.sb.epoch)?;
        let mut reclaimed = 0usize;
        for (k, _) in entries {
            if k.len() == 8 {
                let ino = u64::from_be_bytes(k.as_slice().try_into().unwrap());
                let (new_root, _) = self.orphan_tree().remove(
                    &mut self.pages,
                    &mut self.alloc,
                    self.sb.orphan_root,
                    self.sb.epoch,
                    &k,
                )?;
                self.sb.orphan_root = new_root;
                if let Ok(rec) = self.getattr(ino)
                    && rec.nlink == 0
                {
                    self.purge_inode(rec)?;
                    reclaimed += 1;
                }
            }
        }
        self.sync_counters();
        Ok(reclaimed)
    }

    fn read_page_at(&self, extents: &[Extent], file_page: u32) -> Result<Vec<u8>> {
        let page_size = self.sb.page_size as usize;
        for ext in extents {
            if file_page >= ext.file_page && file_page < ext.end_page() {
                if ext.is_hole() || (ext.flags & EXT_UNWRITTEN) != 0 {
                    return Ok(vec![0u8; page_size]);
                }
                let pid = PageId::new(ext.page_id.get() + (file_page - ext.file_page))?;
                let bytes = self.pages.get(&pid).ok_or_else(|| {
                    Error::new(Errno::EIO, format!("missing data page {pid}"))
                })?;
                if bytes.len() != page_size {
                    return Err(Error::new(
                        Errno::EIO,
                        format!("data page {pid} length {} != {page_size}", bytes.len()),
                    ));
                }
                return Ok(bytes.to_vec());
            }
        }
        Ok(vec![0u8; page_size])
    }

    fn set_page_extent(
        mut extents: Vec<Extent>,
        file_page: u32,
        new_pid: PageId,
        flags: u8,
    ) -> Result<Vec<Extent>> {
        let mut out = Vec::with_capacity(extents.len() + 2);
        for ext in extents.drain(..) {
            if file_page < ext.file_page || file_page >= ext.end_page() {
                out.push(ext);
                continue;
            }
            if file_page > ext.file_page {
                let left_len = (file_page - ext.file_page) as u16;
                out.push(Extent {
                    file_page: ext.file_page,
                    page_id: ext.page_id,
                    len: left_len,
                    flags: ext.flags,
                });
            }
            if file_page + 1 < ext.end_page() {
                let right_off = file_page + 1 - ext.file_page;
                let right_len = (ext.end_page() - (file_page + 1)) as u16;
                let right_pid = if (ext.flags & EXT_HOLE) != 0 {
                    PageId::SUPERBLOCK
                } else {
                    PageId::new(ext.page_id.get() + right_off)?
                };
                out.push(Extent {
                    file_page: file_page + 1,
                    page_id: right_pid,
                    len: right_len,
                    flags: ext.flags,
                });
            }
        }
        out.push(Extent {
            file_page,
            page_id: new_pid,
            len: 1,
            flags,
        });
        merge_extents(&mut out);
        Ok(out)
    }

    /// Read up to `len` bytes from `ino` starting at `offset` (Section 3.5).
    pub fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>> {
        let rec = self.getattr(ino)?;
        if (rec.mode & S_IFMT) == S_IFDIR {
            return Err(Error::new(Errno::EISDIR, "cannot read a directory"));
        }
        if (rec.flags & INO_DAMAGED) != 0 {
            return Err(Error::new(Errno::EIO, "inode is marked DAMAGED"));
        }
        if offset >= rec.size || len == 0 {
            return Ok(Vec::new());
        }
        let to_read = len.min((rec.size - offset) as usize);
        if let InodeData::Inline(bytes) = &rec.data {
            let start = offset as usize;
            let end = (start + to_read).min(bytes.len());
            let mut out = vec![0u8; to_read];
            if start < end {
                out[..end - start].copy_from_slice(&bytes[start..end]);
            }
            return Ok(out);
        }

        let page_size = self.sb.page_size as usize;
        let start_page = (offset / (page_size as u64)) as u32;
        let end_page = ((offset + (to_read as u64) - 1) / (page_size as u64)) as u32;
        let extents = self.load_extents(&rec)?;

        let mut buf = Vec::with_capacity(((end_page - start_page + 1) as usize) * page_size);
        for p_idx in start_page..=end_page {
            buf.extend_from_slice(&self.read_page_at(&extents, p_idx)?);
        }
        let rel = (offset as usize) - (start_page as usize) * page_size;
        Ok(buf[rel..rel + to_read].to_vec())
    }

    /// Read the target of a symbolic link (`EINVAL` if not a symlink).
    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>> {
        let rec = self.getattr(ino)?;
        if (rec.mode & S_IFMT) != S_IFLNK {
            return Err(Error::new(Errno::EINVAL, "inode is not a symbolic link"));
        }
        self.read(ino, 0, rec.size as usize)
    }

    /// Write `data` to `ino` at `offset` (Section 3.5, 4.5, 4.7).
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        self.write_internal(ino, offset, data, true)
    }

    fn write_internal(
        &mut self,
        ino: u64,
        offset: u64,
        data: &[u8],
        log_op: bool,
    ) -> Result<usize> {
        self.check_writable(true)?;
        let mut rec = self.getattr(ino)?;
        if (rec.mode & S_IFMT) == S_IFDIR {
            return Err(Error::new(Errno::EISDIR, "cannot write to a directory"));
        }
        if (rec.flags & INO_IMMUTABLE) != 0 {
            return Err(Error::new(Errno::EPERM, "inode is immutable"));
        }
        if (rec.flags & INO_APPEND) != 0 && offset != rec.size {
            return Err(Error::new(Errno::EPERM, "inode is append-only"));
        }
        if data.is_empty() {
            return Ok(0);
        }
        let end_off = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::new(Errno::EFBIG, "write offset overflow"))?;
        if end_off > self.max_file_size {
            return Err(Error::new(
                Errno::EFBIG,
                format!("write exceeds max_file_size ({})", self.max_file_size),
            ));
        }

        let page_size = self.sb.page_size as usize;
        let max_inline = page_size / 4; // 1,024 B at 4 KB (quarter-page rule, Section 4.5)
        let new_size = rec.size.max(end_off);

        if new_size <= (max_inline as u64) && matches!(rec.data, InodeData::Inline(_)) {
            let InodeData::Inline(mut buf) = rec.data else {
                unreachable!()
            };
            if buf.len() < (new_size as usize) {
                buf.resize(new_size as usize, 0);
            }
            let off_u = offset as usize;
            buf[off_u..off_u + data.len()].copy_from_slice(data);
            rec.data = InodeData::Inline(buf);
            rec.size = new_size;
            rec.blocks = 0;
            let now = self.tick_ns();
            rec.mtime = now;
            rec.ctime = now;
            self.put_inode(rec)?;
            if log_op {
                let (seq, t) = self.next_seq();
                self.pending_ops.push(OpRecord {
                    seq,
                    t,
                    uid: 0,
                    gid: 0,
                    kind: OpKind::Write {
                        ino,
                        off: offset,
                        len: data.len() as u64,
                        pages: PageRunRef {
                            file_page: 0,
                            count: 1,
                        },
                        size: new_size,
                    },
                });
            }
            return Ok(data.len());
        }

        // Promote from inline bytes to page 0 extent if crossing the quarter-page threshold.
        let mut extents = if let InodeData::Inline(inline_bytes) = &rec.data {
            if inline_bytes.is_empty() && rec.size == 0 {
                Vec::new()
            } else {
                let pid = self.alloc.allocate_one()?;
                let mut page_buf = vec![0u8; page_size];
                let copy_len = inline_bytes.len().min(page_size);
                page_buf[..copy_len].copy_from_slice(&inline_bytes[..copy_len]);
                self.pages.insert(pid, Bytes::from(page_buf));
                vec![Extent {
                    file_page: 0,
                    page_id: pid,
                    len: 1,
                    flags: 0,
                }]
            }
        } else {
            self.load_extents(&rec)?
        };

        let start_page = (offset / (page_size as u64)) as u32;
        let end_page = ((end_off - 1) / (page_size as u64)) as u32;
        let mut pos = 0usize;

        for p_idx in start_page..=end_page {
            let page_off = if p_idx == start_page {
                (offset as usize) % page_size
            } else {
                0
            };
            let take = (page_size - page_off).min(data.len() - pos);
            let mut page_bytes = if page_off == 0 && take == page_size {
                vec![0u8; page_size]
            } else {
                self.read_page_at(&extents, p_idx)?
            };
            page_bytes[page_off..page_off + take].copy_from_slice(&data[pos..pos + take]);
            pos += take;

            // Free any old physical page mapped at `p_idx`.
            for ext in &extents {
                if p_idx >= ext.file_page && p_idx < ext.end_page() && !ext.is_hole() {
                    if let Ok(old_pid) = PageId::new(ext.page_id.get() + (p_idx - ext.file_page)) {
                        self.alloc.free_page(old_pid);
                        self.pages.remove(&old_pid);
                    }
                }
            }
            let new_pid = self.alloc.allocate_one()?;
            self.pages.insert(new_pid, Bytes::from(page_bytes));
            extents = Self::set_page_extent(extents, p_idx, new_pid, 0)?;
        }

        self.save_extents(&mut rec, extents)?;
        rec.size = new_size;
        let now = self.tick_ns();
        rec.mtime = now;
        rec.ctime = now;
        self.put_inode(rec)?;

        if log_op {
            let (seq, t) = self.next_seq();
            self.pending_ops.push(OpRecord {
                seq,
                t,
                uid: 0,
                gid: 0,
                kind: OpKind::Write {
                    ino,
                    off: offset,
                    len: data.len() as u64,
                    pages: PageRunRef {
                        file_page: start_page,
                        count: end_page - start_page + 1,
                    },
                    size: new_size,
                },
            });
        }
        Ok(data.len())
    }

    /// Resize `ino` to `new_size`, zeroing any partial tail page on shrink (Section 8, EC-Z04, EC-Z06).
    pub fn truncate(&mut self, ino: u64, new_size: u64) -> Result<()> {
        if new_size > self.max_file_size {
            return Err(Error::new(Errno::EFBIG, "truncate exceeds max_file_size"));
        }
        let mut rec = self.getattr(ino)?;
        self.check_writable(new_size > rec.size)?;
        if (rec.mode & S_IFMT) == S_IFDIR {
            return Err(Error::new(Errno::EISDIR, "cannot truncate a directory"));
        }
        if (rec.flags & (INO_IMMUTABLE | INO_APPEND)) != 0 {
            return Err(Error::new(Errno::EPERM, "cannot truncate immutable/append inode"));
        }

        let page_size = self.sb.page_size as usize;
        let max_inline = page_size / 4;

        if let InodeData::Inline(mut buf) = rec.data.clone()
            && new_size <= (max_inline as u64)
        {
            buf.resize(new_size as usize, 0);
            rec.data = InodeData::Inline(buf);
            rec.size = new_size;
            rec.blocks = 0;
            let now = self.tick_ns();
            rec.mtime = now;
            rec.ctime = now;
            self.put_inode(rec)?;
            let (seq, t) = self.next_seq();
            self.pending_ops.push(OpRecord {
                seq,
                t,
                uid: 0,
                gid: 0,
                kind: OpKind::Truncate {
                    op_name: "truncate".into(),
                    ino,
                    off: 0,
                    size: new_size,
                    mode: 0,
                },
            });
            return Ok(());
        }

        let mut extents = if let InodeData::Inline(inline_bytes) = &rec.data {
            if inline_bytes.is_empty() {
                Vec::new()
            } else {
                let pid = self.alloc.allocate_one()?;
                let mut page_buf = vec![0u8; page_size];
                page_buf[..inline_bytes.len()].copy_from_slice(inline_bytes);
                self.pages.insert(pid, Bytes::from(page_buf));
                vec![Extent {
                    file_page: 0,
                    page_id: pid,
                    len: 1,
                    flags: 0,
                }]
            }
        } else {
            self.load_extents(&rec)?
        };

        let keep_pages = new_size.div_ceil(page_size as u64) as u32;
        let mut trimmed = Vec::new();
        for ext in extents.drain(..) {
            if ext.file_page >= keep_pages {
                if !ext.is_hole() {
                    for i in 0..(ext.len as u32) {
                        if let Ok(pid) = PageId::new(ext.page_id.get() + i) {
                            self.alloc.free_page(pid);
                            self.pages.remove(&pid);
                        }
                    }
                }
            } else if ext.end_page() > keep_pages {
                let keep_len = (keep_pages - ext.file_page) as u16;
                if !ext.is_hole() {
                    for i in (keep_len as u32)..(ext.len as u32) {
                        if let Ok(pid) = PageId::new(ext.page_id.get() + i) {
                            self.alloc.free_page(pid);
                            self.pages.remove(&pid);
                        }
                    }
                }
                trimmed.push(Extent {
                    file_page: ext.file_page,
                    page_id: ext.page_id,
                    len: keep_len,
                    flags: ext.flags,
                });
            } else {
                trimmed.push(ext);
            }
        }

        // EC-Z06: Zero the tail bytes of the boundary page when shrinking inside a page.
        let rem = (new_size as usize) % page_size;
        if new_size > 0 && rem != 0 {
            let last_page = keep_pages - 1;
            let mut page_bytes = self.read_page_at(&trimmed, last_page)?;
            if page_bytes[rem..].iter().any(|&b| b != 0) {
                page_bytes[rem..].fill(0);
                for ext in &trimmed {
                    if last_page >= ext.file_page
                        && last_page < ext.end_page()
                        && !ext.is_hole()
                        && let Ok(old_pid) =
                            PageId::new(ext.page_id.get() + (last_page - ext.file_page))
                    {
                        self.alloc.free_page(old_pid);
                        self.pages.remove(&old_pid);
                    }
                }
                let new_pid = self.alloc.allocate_one()?;
                self.pages.insert(new_pid, Bytes::from(page_bytes));
                trimmed = Self::set_page_extent(trimmed, last_page, new_pid, 0)?;
            }
        }

        self.save_extents(&mut rec, trimmed)?;
        rec.size = new_size;
        let now = self.tick_ns();
        rec.mtime = now;
        rec.ctime = now;
        self.put_inode(rec)?;

        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Truncate {
                op_name: "truncate".into(),
                ino,
                off: 0,
                size: new_size,
                mode: 0,
            },
        });
        Ok(())
    }

    /// Punch a hole `[offset .. offset + len)` in `ino`, freeing full pages in that range (Section 8).
    pub fn punch_hole(&mut self, ino: u64, offset: u64, len: u64) -> Result<()> {
        self.check_writable(false)?;
        if len == 0 {
            return Ok(());
        }
        let mut rec = self.getattr(ino)?;
        if (rec.mode & S_IFMT) != S_IFREG {
            return Err(Error::new(Errno::EOPNOTSUPP, "punch_hole requires regular file"));
        }
        if (rec.flags & (INO_IMMUTABLE | INO_APPEND)) != 0 {
            return Err(Error::new(Errno::EPERM, "inode is immutable or append-only"));
        }
        if offset >= rec.size {
            return Ok(());
        }
        let end = (offset + len).min(rec.size);
        if let InodeData::Inline(mut buf) = rec.data.clone() {
            let s = (offset as usize).min(buf.len());
            let e = (end as usize).min(buf.len());
            if s < e {
                buf[s..e].fill(0);
            }
            rec.data = InodeData::Inline(buf);
            let now = self.tick_ns();
            rec.mtime = now;
            rec.ctime = now;
            self.put_inode(rec)?;
            return Ok(());
        }

        let page_size = self.sb.page_size as u64;
        let start_page = (offset / page_size) as u32;
        let end_page = ((end - 1) / page_size) as u32;
        let mut extents = self.load_extents(&rec)?;

        for p_idx in start_page..=end_page {
            let p_start = (p_idx as u64) * page_size;
            let p_end = p_start + page_size;
            if offset <= p_start && end >= p_end {
                // Full page hole: free any backing page and mark EXT_HOLE.
                for ext in &extents {
                    if p_idx >= ext.file_page
                        && p_idx < ext.end_page()
                        && !ext.is_hole()
                        && let Ok(old_pid) = PageId::new(ext.page_id.get() + (p_idx - ext.file_page))
                    {
                        self.alloc.free_page(old_pid);
                        self.pages.remove(&old_pid);
                    }
                }
                extents = Self::set_page_extent(extents, p_idx, PageId::SUPERBLOCK, EXT_HOLE)?;
            } else {
                // Partial page zeroing.
                let mut page_bytes = self.read_page_at(&extents, p_idx)?;
                let z_start = offset.saturating_sub(p_start) as usize;
                let z_end = (end - p_start).min(page_size) as usize;
                page_bytes[z_start..z_end].fill(0);
                for ext in &extents {
                    if p_idx >= ext.file_page
                        && p_idx < ext.end_page()
                        && !ext.is_hole()
                        && let Ok(old_pid) = PageId::new(ext.page_id.get() + (p_idx - ext.file_page))
                    {
                        self.alloc.free_page(old_pid);
                        self.pages.remove(&old_pid);
                    }
                }
                let new_pid = self.alloc.allocate_one()?;
                self.pages.insert(new_pid, Bytes::from(page_bytes));
                extents = Self::set_page_extent(extents, p_idx, new_pid, 0)?;
            }
        }

        self.save_extents(&mut rec, extents)?;
        let now = self.tick_ns();
        rec.mtime = now;
        rec.ctime = now;
        self.put_inode(rec)?;

        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Truncate {
                op_name: "punch_hole".into(),
                ino,
                off: offset,
                size: len,
                mode: 0,
            },
        });
        Ok(())
    }

    /// Update inode attributes (`chmod`, `chown`, `utimens`, `chattr`, Section 8).
    #[allow(clippy::too_many_arguments)]
    pub fn setattr(
        &mut self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        mtime: Option<i64>,
        flags: Option<u32>,
    ) -> Result<()> {
        self.check_writable(false)?;
        if let Some(sz) = size {
            self.truncate(ino, sz)?;
        }
        let mut rec = self.getattr(ino)?;
        if (rec.flags & INO_IMMUTABLE) != 0 && flags.is_none() {
            return Err(Error::new(Errno::EPERM, "inode is immutable"));
        }
        if let Some(m) = mode {
            rec.mode = (rec.mode & S_IFMT) | (m & 0o7777);
        }
        if let Some(u) = uid {
            rec.uid = u;
        }
        if let Some(g) = gid {
            rec.gid = g;
        }
        if let Some(mt) = mtime {
            rec.mtime = mt;
        }
        if let Some(fl) = flags {
            let preserve = rec.flags & !(INO_IMMUTABLE | INO_APPEND);
            rec.flags = preserve | (fl & (INO_IMMUTABLE | INO_APPEND));
        }
        rec.ctime = self.tick_ns();
        self.put_inode(rec)?;

        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Setattr {
                ino,
                mode,
                uid,
                gid,
                size,
                mtime,
                flags,
            },
        });
        Ok(())
    }

    /// Set an extended attribute on `ino` (`4 KB` value limit, `64 KB` per-inode limit, EC-Z11).
    pub fn setxattr(&mut self, ino: u64, name: &str, value: &[u8]) -> Result<()> {
        self.check_writable(true)?;
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::new(Errno::EINVAL, "invalid xattr name"));
        }
        if value.len() > MAX_XATTR_VALUE {
            return Err(Error::new(Errno::E2BIG, "xattr value exceeds 4096 bytes"));
        }
        let mut rec = self.getattr(ino)?;
        if (rec.flags & INO_IMMUTABLE) != 0 {
            return Err(Error::new(Errno::EPERM, "inode is immutable"));
        }

        let tree = self.xattr_tree();
        let cur_root = rec.xattr_root.map_or(0, PageId::get);
        let existing = tree.all_entries(&self.pages, cur_root, self.sb.epoch)?;
        let total: usize = existing
            .iter()
            .filter(|(k, _)| k.as_slice() != name.as_bytes())
            .map(|(k, v)| k.len() + v.len())
            .sum();
        if total + name.len() + value.len() > MAX_XATTR_TOTAL {
            return Err(Error::new(
                Errno::ENOSPC,
                "per-inode 64 KB xattr limit exceeded",
            ));
        }

        let new_root = tree.insert(
            &mut self.pages,
            &mut self.alloc,
            cur_root,
            self.sb.epoch,
            name.as_bytes().to_vec(),
            value.to_vec(),
        )?;
        rec.xattr_root = Some(PageId::new(new_root)?);
        rec.ctime = self.tick_ns();
        self.put_inode(rec)?;

        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Xattr {
                op_name: "setxattr".into(),
                ino,
                name: name.into(),
                value_len: Some(value.len()),
            },
        });
        Ok(())
    }

    /// Read an extended attribute from `ino` (`ENODATA` if absent).
    pub fn getxattr(&self, ino: u64, name: &str) -> Result<Vec<u8>> {
        let rec = self.getattr(ino)?;
        let Some(root) = rec.xattr_root else {
            return Err(Error::new(Errno::ENODATA, "attribute not found"));
        };
        self.xattr_tree()
            .get(&self.pages, root.get(), self.sb.epoch, name.as_bytes())?
            .ok_or_else(|| Error::new(Errno::ENODATA, "attribute not found"))
    }

    /// Remove an extended attribute from `ino` (`ENODATA` if absent).
    pub fn removexattr(&mut self, ino: u64, name: &str) -> Result<()> {
        self.check_writable(false)?;
        let mut rec = self.getattr(ino)?;
        let Some(root) = rec.xattr_root else {
            return Err(Error::new(Errno::ENODATA, "attribute not found"));
        };
        let (new_root, old) = self.xattr_tree().remove(
            &mut self.pages,
            &mut self.alloc,
            root.get(),
            self.sb.epoch,
            name.as_bytes(),
        )?;
        if old.is_none() {
            return Err(Error::new(Errno::ENODATA, "attribute not found"));
        }
        rec.xattr_root = (new_root != 0).then(|| PageId::new(new_root).unwrap());
        rec.ctime = self.tick_ns();
        self.put_inode(rec)?;

        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Xattr {
                op_name: "removexattr".into(),
                ino,
                name: name.into(),
                value_len: None,
            },
        });
        Ok(())
    }

    /// Finalize the current commit group, writing updated FreeMap pages and Page 0 Superblock (Section 6.2, REQ-1, REQ-11).
    /// Finalize the current commit group, writing updated FreeMap pages and Page 0 Superblock (Section 6.2, REQ-1, REQ-11).
    pub fn commit_group(&mut self) -> Result<Option<CommittedGroup>> {
        if self.pending_ops.is_empty() {
            return Ok(None); // REQ-11: Empty groups MUST NOT be committed.
        }
        let (seq, t) = self.next_seq();
        self.pending_ops.push(OpRecord {
            seq,
            t,
            uid: 0,
            gid: 0,
            kind: OpKind::Barrier {
                kind: "group_end".into(),
            },
        });
        let ops = std::mem::take(&mut self.pending_ops);
        let ops_count = ops.len();
        let changelog = Bytes::from(encode_changelog(&ops));

        self.sb.epoch += 1;
        let committed_epoch = self.sb.epoch;
        self.sync_counters();
        self.alloc
            .write_free_map_pages(&self.sb, committed_epoch, &mut self.pages)?;
        self.pages.insert(PageId::SUPERBLOCK, self.sb.encode());
        self.alloc.begin_group();

        Ok(Some(CommittedGroup {
            epoch: committed_epoch,
            changelog,
            ops_count,
        }))
    }

    /// Diagnostic dump of the volume superblock and all inodes (Section 20 Phase B).
    pub fn dump(&self) -> Result<String> {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "OBF1 v{}.{} page_size={} epoch={} inodes={} live_pages={} live_bytes={}",
            self.sb.version_major,
            self.sb.version_minor,
            self.sb.page_size,
            self.sb.epoch,
            self.sb.inode_count,
            self.sb.live_pages,
            self.sb.live_bytes
        );
        let entries =
            self.inode_tree()
                .all_entries(&self.pages, self.sb.inode_root, self.sb.epoch)?;
        for (_, v) in entries {
            let rec = InodeRecord::decode(&v)?;
            let _ = writeln!(
                out,
                "  ino={} mode={:06o} nlink={} size={} blocks={} class={:?}",
                rec.ino,
                rec.mode,
                rec.nlink,
                rec.size,
                rec.blocks,
                rec.path_class()
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{run_crash_injection_suite, run_differential_model, run_fsx};
    use crate::oplog::decode_changelog;

    #[test]
    fn phase_b_edge_cases_and_orphans() {
        let mut vol = Volume::mkfs(4096, [0xAB; 16], CasePolicy::Sensitive, 1).unwrap();

        // EC-N01: 255-byte name works; 256-byte name returns ENAMETOOLONG.
        let n255 = vec![b'x'; 255];
        let n256 = vec![b'x'; 256];
        let ino = vol.create(ROOT_INO, &n255, 0o644, 1000, 1000).unwrap();
        assert_eq!(
            vol.create(ROOT_INO, &n256, 0o644, 1000, 1000).unwrap_err().errno,
            Errno::ENAMETOOLONG
        );

        // Quarter-page inline rule (<= 1,024 B inline, > 1,024 B promoted to extents).
        vol.write(ino, 0, &vec![0x55; 512]).unwrap();
        assert_eq!(vol.getattr(ino).unwrap().blocks, 0);
        vol.write(ino, 512, &vec![0xAA; 4096]).unwrap();
        assert_eq!(vol.getattr(ino).unwrap().blocks, 2);

        // EC-Z06: Truncate inside a page zeroes the cut tail when extended later.
        vol.truncate(ino, 600).unwrap();
        vol.truncate(ino, 2048).unwrap();
        let read_back = vol.read(ino, 0, 2048).unwrap();
        assert_eq!(&read_back[..512], &vec![0x55; 512][..]);
        assert_eq!(&read_back[512..600], &vec![0xAA; 88][..]);
        assert!(read_back[600..].iter().all(|&b| b == 0));

        // EC-O01: Unlink while open keeps data readable and records in orphan tree; remount reclaims.
        vol.open_handle(ino).unwrap();
        vol.unlink(ROOT_INO, &n255).unwrap();
        assert_eq!(vol.read(ino, 0, 64).unwrap().len(), 64);
        let group = vol.commit_group().unwrap().unwrap();
        let decoded_ops = decode_changelog(&group.changelog).unwrap();
        assert!(!decoded_ops.is_empty());

        let remounted = Volume::mount(vol.clone_storage(), true, 2).unwrap();
        assert_eq!(remounted.getattr(ino).unwrap_err().errno, Errno::ENOENT);
        assert!(remounted. dump().unwrap().contains("OBF1 v1.0"));
    }

    #[test]
    fn phase_b_fsx_suite() {
        run_fsx(500, 2026_10_18).unwrap();
    }

    #[test]
    fn phase_b_differential_model_3000_steps() {
        run_differential_model(3_000, 0x0C70_B10C).unwrap();
    }

    #[test]
    fn phase_b_crash_injection_1000_points() {
        run_crash_injection_suite(1_000, 0xCAFE_BABE).unwrap();
    }

    #[test]
    fn phase_b_fsck_detect_and_repair() {
        let mut vol = Volume::mkfs(4096, [0x77; 16], CasePolicy::Sensitive, 1).unwrap();
        let ino = vol.create(ROOT_INO, b"check.txt", 0o644, 1000, 1000).unwrap();
        vol.write(ino, 0, &vec![0x33; 8192]).unwrap();
        vol.commit_group().unwrap();

        // Inject EC-D04 (live_bytes drift) and EC-D06 (orphan with nlink > 0)
        vol.sb.live_bytes += 4096 * 10;
        vol.sb.orphan_root = vol
            .orphan_tree()
            .insert(
                &mut vol.pages,
                &mut vol.alloc,
                vol.sb.orphan_root,
                vol.sb.epoch,
                ino.to_be_bytes().to_vec(),
                vec![1],
            )
            .unwrap();

        let scan = vol.fsck(false).unwrap();
        assert!(!scan.is_clean(), "fsck must detect injected drift and bogus orphan");

        let repaired = vol.fsck(true).unwrap();
        assert!(repaired.repaired >= 2);

        let verify = vol.fsck(false).unwrap();
        assert!(verify.is_clean(), "fsck after repair must be 100% clean: {:?}", verify.problems);
    }
}