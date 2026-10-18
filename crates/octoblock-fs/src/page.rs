//! OBF1 page types, 32-byte metadata page headers, and superblock encoding.

use std::fmt;

use bytes::Bytes;

use crate::{Errno, Error, Result};

/// The 4-byte magic at the start of every OctoBlock metadata page.
pub const MAGIC: &[u8; 4] = b"OBF1";
/// Size of the metadata page header in bytes.
pub const HEADER_LEN: usize = 32;
/// Maximum 24-bit page identifier (`16,777,215`).
pub const MAX_PAGE_ID: u32 = (1 << 24) - 1;
/// Allowed volume page sizes fixed at `mkfs` time.
pub const PAGE_SIZES: [usize; 3] = [4096, 8192, 16384];
/// Current major format version.
pub const VERSION_MAJOR: u16 = 1;
/// Current minor format version.
pub const VERSION_MINOR: u16 = 0;
/// Current client implementation version.
pub const CLIENT_VERSION: u32 = 1;

/// Page header flag indicating a B+tree leaf node (unset for interior nodes).
pub const PAGE_FLAG_LEAF: u8 = 1 << 0;

/// Known compatible feature mask supported by this build.
pub const KNOWN_COMPAT: u32 = 0;
/// Known read-only-compatible feature mask supported by this build.
pub const KNOWN_RO_COMPAT: u32 = 0;
/// Known incompatible feature mask supported by this build.
pub const KNOWN_INCOMPAT: u32 = 0;

const OFF_TYPE: usize = 4;
const OFF_FLAGS: usize = 5;
const OFF_CELLS: usize = 6;
const OFF_ID: usize = 8;
const OFF_FREE: usize = 12;
const OFF_EPOCH: usize = 16;

/// A 24-bit page identifier (`pages/AA/BB/CC`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PageId(u32);

impl PageId {
    /// Page 0 is always the volume superblock.
    pub const SUPERBLOCK: PageId = PageId(0);

    /// Construct a validated 24-bit page ID.
    pub fn new(id: u32) -> Result<Self> {
        if id > MAX_PAGE_ID {
            return Err(Error::new(
                Errno::EINVAL,
                format!("page id {id:#x} exceeds 24 bits"),
            ));
        }
        Ok(PageId(id))
    }

    /// Raw numeric value of the page ID.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The three fan-out bytes (`AA`, `BB`, `CC`).
    pub const fn bytes(self) -> [u8; 3] {
        [(self.0 >> 16) as u8, (self.0 >> 8) as u8, self.0 as u8]
    }

    /// Reconstruct a page ID from its three fan-out bytes.
    pub const fn from_bytes(b: [u8; 3]) -> Self {
        PageId(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }
}

impl fmt::Display for PageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06x}", self.0)
    }
}

impl fmt::Debug for PageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PageId({:06x})", self.0)
    }
}

/// OctoBlock v0.2 Section 4.2 page types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PageType {
    /// Page 0: format version, feature flags, roots, counters, encryption metadata.
    Superblock = 1,
    /// Copy-on-write B+tree interior or leaf keyed by inode number.
    InodeTree = 2,
    /// Copy-on-write B+tree interior or leaf keyed by `(dir_ino, name_hash)`.
    DentryTree = 3,
    /// Per-file B+tree interior or leaf keyed by file page index.
    ExtentTree = 4,
    /// Extended attribute B+tree page.
    XattrLeaf = 5,
    /// Headerless raw file data page.
    Data = 6,
    /// Unlinked open inodes awaiting reclamation.
    OrphanLeaf = 7,
    /// Allocation bitmap page (1 bit per page ID).
    FreeMap = 8,
    /// Chain page for changelogs exceeding 1 MB.
    ChangelogIndex = 9,
}

impl PageType {
    /// Convert a raw byte into a `PageType`.
    pub const fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => PageType::Superblock,
            2 => PageType::InodeTree,
            3 => PageType::DentryTree,
            4 => PageType::ExtentTree,
            5 => PageType::XattrLeaf,
            6 => PageType::Data,
            7 => PageType::OrphanLeaf,
            8 => PageType::FreeMap,
            9 => PageType::ChangelogIndex,
            _ => return None,
        })
    }
}

/// Directory name case-sensitivity policy fixed at `mkfs` (Section 4.4, EC-N05).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum CasePolicy {
    /// Exact byte-string matching (POSIX default).
    #[default]
    Sensitive = 0,
    /// Case-folding lookups while preserving case on storage.
    Fold = 1,
}

impl CasePolicy {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(CasePolicy::Sensitive),
            1 => Some(CasePolicy::Fold),
            _ => None,
        }
    }
}

/// Per-path persistence policy class stored in two bits of inode flags (Section 5.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum PathClass {
    /// Journaled and committed to the remote repository.
    #[default]
    Persist = 0,
    /// Kept on local disk only.
    Local = 1,
    /// Kept in RAM only.
    Volatile = 2,
    /// Creation refused with `EACCES`.
    Exclude = 3,
}

impl PathClass {
    /// Decode from the 2-bit field.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => PathClass::Persist,
            1 => PathClass::Local,
            2 => PathClass::Volatile,
            _ => PathClass::Exclude,
        }
    }
}

pub(crate) fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A validated 32-byte-headered metadata page (`OBF1`).
#[derive(Clone, PartialEq, Eq)]
pub struct MetaPage(Bytes);

impl MetaPage {
    /// Parse and validate a metadata page against expected `PageId`, `page_size`, and `max_epoch`.
    pub fn parse(
        bytes: Bytes,
        page_size: usize,
        expected_id: PageId,
        max_epoch: u64,
    ) -> Result<Self> {
        let corrupt = |reason: String| {
            Error::new(
                Errno::EIO,
                format!("corrupt metadata page {expected_id}: {reason}"),
            )
        };
        if bytes.len() != page_size {
            return Err(corrupt(format!(
                "length {} != page_size {page_size}",
                bytes.len()
            )));
        }
        if &bytes[..4] != MAGIC {
            return Err(corrupt("bad magic (expected OBF1)".into()));
        }
        let Some(pt) = PageType::from_u8(bytes[OFF_TYPE]) else {
            return Err(corrupt(format!("unknown page type {}", bytes[OFF_TYPE])));
        };
        if pt == PageType::Data {
            return Err(corrupt(
                "data pages do not carry a metadata header".into(),
            ));
        }
        let id = u32_at(&bytes, OFF_ID);
        if id != expected_id.get() {
            return Err(corrupt(format!("header page_id {id:06x} != {expected_id}")));
        }
        let epoch = u64_at(&bytes, OFF_EPOCH);
        if epoch > max_epoch {
            return Err(corrupt(format!(
                "page epoch {epoch} exceeds snapshot epoch {max_epoch}"
            )));
        }
        let free_off = u32_at(&bytes, OFF_FREE) as usize;
        if free_off > page_size - HEADER_LEN {
            return Err(corrupt(format!(
                "free_offset {free_off} exceeds payload size {}",
                page_size - HEADER_LEN
            )));
        }
        Ok(MetaPage(bytes))
    }

    /// The metadata page's type.
    pub fn page_type(&self) -> PageType {
        PageType::from_u8(self.0[OFF_TYPE]).expect("validated in parse")
    }

    /// Header flags byte.
    pub fn flags(&self) -> u8 {
        self.0[OFF_FLAGS]
    }

    /// Number of cells stored in the page.
    pub fn cell_count(&self) -> u16 {
        u16_at(&self.0, OFF_CELLS)
    }

    /// The page ID stamped in the header.
    pub fn id(&self) -> PageId {
        PageId(u32_at(&self.0, OFF_ID))
    }

    /// End of used cell space inside `payload()`.
    pub fn free_offset(&self) -> u32 {
        u32_at(&self.0, OFF_FREE)
    }

    /// Commit epoch that wrote this page.
    pub fn epoch(&self) -> u64 {
        u64_at(&self.0, OFF_EPOCH)
    }

    /// Slice of the page following the 32-byte header.
    pub fn payload(&self) -> &[u8] {
        &self.0[HEADER_LEN..]
    }

    /// Full raw page bytes including header.
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }
}

impl fmt::Debug for MetaPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MetaPage({} {:?} cells={} epoch={})",
            self.id(),
            self.page_type(),
            self.cell_count(),
            self.epoch()
        )
    }
}

/// Mutable builder for an `OBF1` metadata page.
#[derive(Clone, PartialEq, Eq)]
pub struct MetaPageBuf(Vec<u8>);

impl MetaPageBuf {
    /// Allocate a zeroed metadata page buffer with `OBF1` magic and `page_type`.
    pub fn new(page_type: PageType, page_size: usize) -> Self {
        let mut buf = vec![0u8; page_size];
        buf[..4].copy_from_slice(MAGIC);
        buf[OFF_TYPE] = page_type as u8;
        MetaPageBuf(buf)
    }

    /// Set the 1-byte page flags.
    pub fn set_flags(&mut self, flags: u8) {
        self.0[OFF_FLAGS] = flags;
    }

    /// Set the 16-bit cell count.
    pub fn set_cell_count(&mut self, count: u16) {
        self.0[OFF_CELLS..OFF_CELLS + 2].copy_from_slice(&count.to_le_bytes());
    }

    /// Set the 32-bit payload free offset.
    pub fn set_free_offset(&mut self, offset: u32) {
        self.0[OFF_FREE..OFF_FREE + 4].copy_from_slice(&offset.to_le_bytes());
    }

    /// Mutable access to the payload after the 32-byte header.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0[HEADER_LEN..]
    }

    /// Immutable access to the payload after the 32-byte header.
    pub fn payload(&self) -> &[u8] {
        &self.0[HEADER_LEN..]
    }

    /// Stamp `id` and `epoch` into the header and freeze into `Bytes`.
    pub fn stamp(mut self, id: PageId, epoch: u64) -> Bytes {
        self.0[OFF_ID..OFF_ID + 4].copy_from_slice(&id.get().to_le_bytes());
        self.0[OFF_EPOCH..OFF_EPOCH + 8].copy_from_slice(&epoch.to_le_bytes());
        Bytes::from(self.0)
    }
}

/// OctoBlock Section 4.4 Superblock (stored at Page 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Superblock {
    /// Format major version.
    pub version_major: u16,
    /// Format minor version.
    pub version_minor: u16,
    /// Safe-to-ignore feature flags.
    pub compat_flags: u32,
    /// Mount read-only if unknown bits are present.
    pub ro_compat_flags: u32,
    /// Refuse to mount if unknown bits are present.
    pub incompat_flags: u32,
    /// 16-byte volume UUID (also salts directory name hashes).
    pub uuid: [u8; 16],
    /// Page size in bytes (4096, 8192, or 16384).
    pub page_size: u32,
    /// Root page of the inode B+tree (0 if empty).
    pub inode_root: u32,
    /// Root page of the dentry B+tree (0 if empty).
    pub dentry_root: u32,
    /// Root page of the extended attribute B+tree (0 if empty).
    pub xattr_root: u32,
    /// Root page of the orphan B+tree (0 if empty).
    pub orphan_root: u32,
    /// First page of the free-map bitmap (`1`).
    pub free_map_root: u32,
    /// Next unreserved inode number counter.
    pub next_ino: u64,
    /// Count of live allocated pages at head (excluding system free-map/superblock).
    pub live_pages: u64,
    /// Live bytes charged against the volume budget (`live_pages * page_size`).
    pub live_bytes: u64,
    /// Total live inodes in the inode tree.
    pub inode_count: u64,
    /// Commit sequence number.
    pub epoch: u64,
    /// Object hash algorithm (`1` = SHA-1, `2` = SHA-256).
    pub hash_algo: u8,
    /// Directory case-sensitivity policy.
    pub case_policy: CasePolicy,
    /// Encryption mode (`0` = plain, `1` = random nonce, `2` = convergent).
    pub encryption_mode: u8,
    /// Writer client version that created the volume.
    pub created_by: u32,
    /// Minimum client version allowed to mount read-write.
    pub min_client: u32,
    /// Number of dedicated free-map pages starting at `free_map_root`.
    pub map_pages: u32,
    /// Optional policy blob SHA (length-prefixed up to 32 bytes).
    pub policy_sha: Vec<u8>,
}

/// Number of free-map bitmap pages required for a given `page_size`.
pub const fn map_pages_for(page_size: usize) -> u32 {
    let bits_per_page = ((page_size - HEADER_LEN) * 8) as u32;
    (MAX_PAGE_ID + 1).div_ceil(bits_per_page)
}

impl Superblock {
    /// Construct a fresh superblock for `mkfs`.
    pub fn new(page_size: usize, uuid: [u8; 16], case_policy: CasePolicy) -> Result<Self> {
        if !PAGE_SIZES.contains(&page_size) {
            return Err(Error::new(
                Errno::EINVAL,
                format!("unsupported page size {page_size}; must be one of {PAGE_SIZES:?}"),
            ));
        }
        let map_pages = map_pages_for(page_size);
        Ok(Superblock {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            compat_flags: 0,
            ro_compat_flags: 0,
            incompat_flags: 0,
            uuid,
            page_size: page_size as u32,
            inode_root: 0,
            dentry_root: 0,
            xattr_root: 0,
            orphan_root: 0,
            free_map_root: 1,
            next_ino: 65_536,
            live_pages: 0,
            live_bytes: 0,
            inode_count: 0,
            epoch: 1,
            hash_algo: 1,
            case_policy,
            encryption_mode: 1,
            created_by: CLIENT_VERSION,
            min_client: CLIENT_VERSION,
            map_pages,
            policy_sha: Vec::new(),
        })
    }

    /// First page ID available for non-system trees and file data (`1 + map_pages`).
    pub const fn first_usable_page(&self) -> u32 {
        1 + self.map_pages
    }

    /// Whether `id` is Page 0 or one of the fixed free-map pages (`1..=map_pages`).
    pub const fn is_system_page(&self, id: PageId) -> bool {
        id.get() <= self.map_pages
    }

    /// Validate feature flags and `min_client` for a mount (Section 4.11, REQ-6, EC-U01, EC-U04).
    pub fn check_mount(&self, read_write: bool, client_version: u32) -> Result<()> {
        if self.incompat_flags & !KNOWN_INCOMPAT != 0 {
            return Err(Error::new(
                Errno::EINVAL,
                format!("unknown incompat feature flags {:#x}", self.incompat_flags),
            ));
        }
        if read_write {
            if self.ro_compat_flags & !KNOWN_RO_COMPAT != 0 {
                return Err(Error::new(
                    Errno::EROFS,
                    format!(
                        "unknown ro_compat feature flags {:#x}; mount read-only",
                        self.ro_compat_flags
                    ),
                ));
            }
            if client_version < self.min_client {
                return Err(Error::new(
                    Errno::EROFS,
                    format!(
                        "client version {client_version} is older than min_client {}",
                        self.min_client
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Section 4.4: Commit validator ignores `epoch`, `live_*`, and `next_*` counters when
    /// checking whether two concurrent superblock updates conflict on structural fields.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.version_major != other.version_major
            || self.version_minor != other.version_minor
            || self.compat_flags != other.compat_flags
            || self.ro_compat_flags != other.ro_compat_flags
            || self.incompat_flags != other.incompat_flags
            || self.uuid != other.uuid
            || self.page_size != other.page_size
            || self.case_policy != other.case_policy
            || self.min_client != other.min_client
            || self.policy_sha != other.policy_sha
    }

    /// Encode the superblock into Page 0.
    pub fn encode(&self) -> Bytes {
        let mut buf = MetaPageBuf::new(PageType::Superblock, self.page_size as usize);
        let p = buf.payload_mut();
        p[0..2].copy_from_slice(&self.version_major.to_le_bytes());
        p[2..4].copy_from_slice(&self.version_minor.to_le_bytes());
        p[4..8].copy_from_slice(&self.compat_flags.to_le_bytes());
        p[8..12].copy_from_slice(&self.ro_compat_flags.to_le_bytes());
        p[12..16].copy_from_slice(&self.incompat_flags.to_le_bytes());
        p[16..32].copy_from_slice(&self.uuid);
        p[32..36].copy_from_slice(&self.page_size.to_le_bytes());
        p[36..40].copy_from_slice(&self.inode_root.to_le_bytes());
        p[40..44].copy_from_slice(&self.dentry_root.to_le_bytes());
        p[44..48].copy_from_slice(&self.xattr_root.to_le_bytes());
        p[48..52].copy_from_slice(&self.orphan_root.to_le_bytes());
        p[52..56].copy_from_slice(&self.free_map_root.to_le_bytes());
        p[56..64].copy_from_slice(&self.next_ino.to_le_bytes());
        p[64..72].copy_from_slice(&self.live_pages.to_le_bytes());
        p[72..80].copy_from_slice(&self.live_bytes.to_le_bytes());
        p[80..88].copy_from_slice(&self.inode_count.to_le_bytes());
        p[88..96].copy_from_slice(&self.epoch.to_le_bytes());
        p[96] = self.hash_algo;
        p[97] = self.case_policy as u8;
        p[98] = self.encryption_mode;
        p[100..104].copy_from_slice(&self.created_by.to_le_bytes());
        p[104..108].copy_from_slice(&self.min_client.to_le_bytes());
        p[108..112].copy_from_slice(&self.map_pages.to_le_bytes());
        let sha_len = self.policy_sha.len().min(32);
        p[112] = sha_len as u8;
        p[113..113 + sha_len].copy_from_slice(&self.policy_sha[..sha_len]);
        buf.set_cell_count(1);
        buf.set_free_offset(145);
        buf.stamp(PageId::SUPERBLOCK, self.epoch)
    }

    /// Decode and validate Page 0.
    pub fn decode(bytes: Bytes) -> Result<Self> {
        let len = bytes.len();
        if !PAGE_SIZES.contains(&len) {
            return Err(Error::new(
                Errno::EIO,
                format!("invalid superblock size {len}"),
            ));
        }
        let page = MetaPage::parse(bytes, len, PageId::SUPERBLOCK, u64::MAX)?;
        if page.page_type() != PageType::Superblock {
            return Err(Error::new(
                Errno::EIO,
                format!("page 0 has type {:?}, expected Superblock", page.page_type()),
            ));
        }
        let p = page.payload();
        let version_major = u16_at(p, 0);
        let version_minor = u16_at(p, 2);
        if version_major != VERSION_MAJOR {
            return Err(Error::new(
                Errno::EINVAL,
                format!("unsupported OBF1 major version {version_major}"),
            ));
        }
        let page_size = u32_at(p, 32);
        if page_size as usize != len {
            return Err(Error::new(
                Errno::EIO,
                format!("superblock page_size {page_size} != actual length {len}"),
            ));
        }
        let case_policy = CasePolicy::from_u8(p[97]).ok_or_else(|| {
            Error::new(Errno::EIO, format!("invalid case_policy byte {}", p[97]))
        })?;
        let sha_len = (p[112] as usize).min(32);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&p[16..32]);
        Ok(Superblock {
            version_major,
            version_minor,
            compat_flags: u32_at(p, 4),
            ro_compat_flags: u32_at(p, 8),
            incompat_flags: u32_at(p, 12),
            uuid,
            page_size,
            inode_root: u32_at(p, 36),
            dentry_root: u32_at(p, 40),
            xattr_root: u32_at(p, 44),
            orphan_root: u32_at(p, 48),
            free_map_root: u32_at(p, 52),
            next_ino: u64_at(p, 56),
            live_pages: u64_at(p, 64),
            live_bytes: u64_at(p, 72),
            inode_count: u64_at(p, 80),
            epoch: u64_at(p, 88),
            hash_algo: p[96],
            case_policy,
            encryption_mode: p[98],
            created_by: u32_at(p, 100),
            min_client: u32_at(p, 104),
            map_pages: u32_at(p, 108),
            policy_sha: p[113..113 + sha_len].to_vec(),
        })
    }
}