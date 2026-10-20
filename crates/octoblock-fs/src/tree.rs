use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;

use crate::alloc::PageAllocator;
use crate::page::{
    CasePolicy, HEADER_LEN, MetaPage, MetaPageBuf, PAGE_FLAG_LEAF, PageId, PageType, PathClass,
    u16_at, u32_at, u64_at,
};
use crate::{Errno, Error, Result};

pub const INO_IMMUTABLE: u32 = 1 << 0;
pub const INO_APPEND: u32 = 1 << 1;
pub const INO_INLINE: u32 = 1 << 2;
pub const INO_EXTENT_TREE: u32 = 1 << 3;
pub const INO_DAMAGED: u32 = 1 << 4;
pub const INO_CLASS_SHIFT: u32 = 5;
pub const INO_NODUMP: u32 = 1 << 7;

/// Maximum inline extents stored directly inside an inode before flipping to `EXTENT_TREE`.
pub const MAX_INLINE_EXTENTS: usize = 6;

// --------------------------------------------------------------------------- Extent flags & records

pub const EXT_HOLE: u8 = 1 << 0;
pub const EXT_UNWRITTEN: u8 = 1 << 1;
pub const EXT_COMPRESSED: u8 = 1 << 2;
pub const EXT_ENCRYPTED: u8 = 1 << 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub file_page: u32,
    pub page_id: PageId,
    pub len: u16,
    pub flags: u8,
}

impl Extent {
    /// Exclusive end file page index (`file_page + len`).
    pub const fn end_page(&self) -> u32 {
        self.file_page + (self.len as u32)
    }

    /// Whether this extent is a sparse hole with no backing pages.
    pub const fn is_hole(&self) -> bool {
        (self.flags & EXT_HOLE) != 0
    }

    /// Encode into 10 bytes: `file_page: u32`, `page_id: u24`, `len: u16`, `flags: u8`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.file_page.to_le_bytes());
        let p = self.page_id.bytes();
        out.extend_from_slice(&p);
        out.extend_from_slice(&self.len.to_le_bytes());
        out.push(self.flags);
    }

    /// Decode a 10-byte extent record.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 10 {
            return Err(Error::new(Errno::EIO, "truncated extent record"));
        }
        let file_page = u32_at(bytes, 0);
        let page_id = PageId::from_bytes([bytes[4], bytes[5], bytes[6]]);
        let len = u16_at(bytes, 7);
        let flags = bytes[9];
        if len == 0 {
            return Err(Error::new(Errno::EIO, "extent with zero length"));
        }
        Ok(Extent {
            file_page,
            page_id,
            len,
            flags,
        })
    }
}

/// Merge adjacent compatible extents in a sorted extent list (EC-Z07).
pub fn merge_extents(extents: &mut Vec<Extent>) {
    extents.sort_by_key(|e| e.file_page);
    let mut merged: Vec<Extent> = Vec::with_capacity(extents.len());
    for ext in extents.drain(..) {
        if let Some(prev) = merged.last_mut() {
            let contiguous_file = prev.end_page() == ext.file_page;
            let same_flags = prev.flags == ext.flags;
            let combined_len = (prev.len as u32) + (ext.len as u32);
            let contiguous_phys = prev.is_hole()
                || (prev.page_id.get() + (prev.len as u32) == ext.page_id.get());
            if contiguous_file && same_flags && contiguous_phys && combined_len <= (u16::MAX as u32)
            {
                prev.len = combined_len as u16;
                continue;
            }
        }
        merged.push(ext);
    }
    *extents = merged;
}

/// Payload union stored inside an `InodeRecord`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InodeData {
    /// Inline file or symlink bytes up to `page_size / 4` (1,024 B at 4 KB).
    Inline(Vec<u8>),
    /// Up to 6 inline extents.
    Extents(Vec<Extent>),
    /// Root page ID of a per-file extent B+tree when the file has more than 6 extents.
    ExtentTree(PageId),
}

/// Section 4.5 Inode record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InodeRecord {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub btime: i64,
    pub flags: u32,
    pub generation: u64,
    pub xattr_root: Option<PageId>,
    pub data: InodeData,
}

impl InodeRecord {
    /// Extract the `PathClass` stored in bits `5..=6` of `flags`.
    pub const fn path_class(&self) -> PathClass {
        PathClass::from_bits(((self.flags >> INO_CLASS_SHIFT) & 0b11) as u8)
    }

    /// Set the `PathClass` bits in `flags`.
    pub fn set_path_class(&mut self, class: PathClass) {
        self.flags &= !(0b11 << INO_CLASS_SHIFT);
        self.flags |= (class as u32) << INO_CLASS_SHIFT;
    }

    /// Synchronize `INO_INLINE` and `INO_EXTENT_TREE` flags with `self.data`.
    pub fn sync_data_flags(&mut self) {
        self.flags &= !(INO_INLINE | INO_EXTENT_TREE);
        match &self.data {
            InodeData::Inline(_) => self.flags |= INO_INLINE,
            InodeData::Extents(_) => {}
            InodeData::ExtentTree(_) => self.flags |= INO_EXTENT_TREE,
        }
    }

    /// Serialize the inode record into bytes for the inode B+tree leaf cell.
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = self.flags & !(INO_INLINE | INO_EXTENT_TREE);
        match &self.data {
            InodeData::Inline(_) => flags |= INO_INLINE,
            InodeData::Extents(_) => {}
            InodeData::ExtentTree(_) => flags |= INO_EXTENT_TREE,
        }
        let mut out = Vec::with_capacity(112);
        out.extend_from_slice(&self.ino.to_le_bytes());
        out.extend_from_slice(&self.mode.to_le_bytes());
        out.extend_from_slice(&self.nlink.to_le_bytes());
        out.extend_from_slice(&self.uid.to_le_bytes());
        out.extend_from_slice(&self.gid.to_le_bytes());
        out.extend_from_slice(&self.rdev.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.blocks.to_le_bytes());
        out.extend_from_slice(&self.atime.to_le_bytes());
        out.extend_from_slice(&self.mtime.to_le_bytes());
        out.extend_from_slice(&self.ctime.to_le_bytes());
        out.extend_from_slice(&self.btime.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        let xattr_bytes = self.xattr_root.unwrap_or(PageId::SUPERBLOCK).bytes();
        out.extend_from_slice(&xattr_bytes);
        match &self.data {
            InodeData::Inline(bytes) => {
                out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            InodeData::Extents(extents) => {
                out.extend_from_slice(&(extents.len() as u16).to_le_bytes());
                for ext in extents {
                    ext.encode(&mut out);
                }
            }
            InodeData::ExtentTree(root_id) => {
                out.extend_from_slice(&root_id.get().to_le_bytes());
            }
        }
        out
    }

    /// Deserialize an inode record from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 95 { 
            return Err(Error::new(Errno::EIO, "truncated inode record"));
        }
        let ino = u64_at(bytes, 0);
        let mode = u32_at(bytes, 8);
        let nlink = u32_at(bytes, 12);
        let uid = u32_at(bytes, 16);
        let gid = u32_at(bytes, 20);
        let rdev = u64_at(bytes, 24);
        let size = u64_at(bytes, 32);
        let blocks = u64_at(bytes, 40);
        let atime = i64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let mtime = i64::from_le_bytes(bytes[56..64].try_into().unwrap());
        let ctime = i64::from_le_bytes(bytes[64..72].try_into().unwrap());
        let btime = i64::from_le_bytes(bytes[72..80].try_into().unwrap());
        let flags = u32_at(bytes, 80);
        let generation = u64_at(bytes, 84);
        let xattr_raw = PageId::from_bytes([bytes[92], bytes[93], bytes[94]]);
        let xattr_root = (xattr_raw.get() != 0).then_some(xattr_raw);

        let tail = &bytes[95..];
        let data = if (flags & INO_INLINE) != 0 {
            if tail.len() < 2 {
                return Err(Error::new(Errno::EIO, "truncated inline inode data"));
            }
            let len = u16_at(tail, 0) as usize;
            if tail.len() < 2 + len {
                return Err(Error::new(Errno::EIO, "inline inode data out of bounds"));
            }
            InodeData::Inline(tail[2..2 + len].to_vec())
        } else if (flags & INO_EXTENT_TREE) != 0 {
            if tail.len() < 4 {
                return Err(Error::new(Errno::EIO, "truncated extent-tree root pointer"));
            }
            InodeData::ExtentTree(PageId::new(u32_at(tail, 0))?)
        } else {
            if tail.len() < 2 {
                return Err(Error::new(Errno::EIO, "truncated inline extent list"));
            }
            let count = u16_at(tail, 0) as usize;
            if tail.len() < 2 + count * 10 {
                return Err(Error::new(Errno::EIO, "inline extent list out of bounds"));
            }
            let mut extents = Vec::with_capacity(count);
            for i in 0..count {
                extents.push(Extent::decode(&tail[2 + i * 10..2 + (i + 1) * 10])?);
            }
            InodeData::Extents(extents)
        };

        Ok(InodeRecord {
            ino,
            mode,
            nlink,
            uid,
            gid,
            rdev,
            size,
            blocks,
            atime,
            mtime,
            ctime,
            btime,
            flags,
            generation,
            xattr_root,
            data,
        })
    }
}

// --------------------------------------------------------------------------- Directory entries

/// Normalize a file name according to the volume's `CasePolicy`
pub fn normalize_name(name: &[u8], policy: CasePolicy) -> Vec<u8> {
    match policy {
        CasePolicy::Sensitive => name.to_vec(),
        CasePolicy::Fold => match std::str::from_utf8(name) {
            Ok(s) => s.to_lowercase().into_bytes(),
            Err(_) => name.iter().map(|b| b.to_ascii_lowercase()).collect(),
        },
    }
}

/// Section 4.6 salted 64-bit directory entry name hash `hash64(volume_uuid, name_bytes)`.
pub fn dentry_hash(uuid: &[u8; 16], name: &[u8], policy: CasePolicy) -> u64 {
    let norm = normalize_name(name, policy);
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in uuid.iter().chain(norm.iter()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    // Keep the lowest 8 bits free for the 1-byte collision index in `readdir` cookies.
    h & !0xFF
}

/// One directory entry inside a hash bucket chain 
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DentryItem {
    pub collision_idx: u8,
    pub file_type: u8,
    pub child_ino: u64,
    pub name: Vec<u8>,
}

impl DentryItem {
    /// Stable 64-bit `readdir` cookie combining the bucket hash `h` and `collision_idx`.
    pub const fn cookie(&self, bucket_hash: u64) -> u64 {
        (bucket_hash & !0xFF) | (self.collision_idx as u64)
    }
}

/// Encode a bucket chain of `DentryItem`s sharing the same `(dir_ino, hash)`.
pub fn encode_dentry_chain(items: &[DentryItem]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(items.len() as u16).to_le_bytes());
    for item in items {
        out.push(item.collision_idx);
        out.push(item.file_type);
        out.extend_from_slice(&item.child_ino.to_le_bytes());
        out.push(item.name.len() as u8);
        out.extend_from_slice(&item.name);
    }
    out
}

/// Decode a bucket chain of `DentryItem`s.
pub fn decode_dentry_chain(bytes: &[u8]) -> Result<Vec<DentryItem>> {
    if bytes.len() < 2 {
        return Err(Error::new(Errno::EIO, "truncated dentry chain"));
    }
    let count = u16_at(bytes, 0) as usize;
    let mut at = 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if at + 11 > bytes.len() {
            return Err(Error::new(Errno::EIO, "truncated dentry item header"));
        }
        let collision_idx = bytes[at];
        let file_type = bytes[at + 1];
        let child_ino = u64_at(bytes, at + 2);
        let name_len = bytes[at + 10] as usize;
        at += 11;
        if at + name_len > bytes.len() {
            return Err(Error::new(Errno::EIO, "truncated dentry item name"));
        }
        let name = bytes[at..at + name_len].to_vec();
        at += name_len;
        out.push(DentryItem {
            collision_idx,
            file_type,
            child_ino,
            name,
        });
    }
    Ok(out)
}

// --------------------------------------------------------------------------- Multi-level CoW B+Tree

/// Generic Copy-on-Write slotted B+tree stored in `OBF1` metadata pages.
pub struct CowBTree {
    page_type: PageType,
    page_size: usize,
}

type KVPairs = Vec<(Vec<u8>, Vec<u8>)>;
type SepList = Vec<(Vec<u8>, PageId)>;

impl CowBTree {
    /// Create a B+tree handle for `page_type` and `page_size`.
    pub const fn new(page_type: PageType, page_size: usize) -> Self {
        CowBTree {
            page_type,
            page_size,
        }
    }

    /// Look up `key` starting from `root` (`0` = empty tree).
    pub fn get(
        &self,
        pages: &BTreeMap<PageId, Bytes>,
        root: u32,
        max_epoch: u64,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if root == 0 {
            return Ok(None);
        }
        let mut curr = PageId::new(root)?;
        for _depth in 0..32 {
            let page = self.read_node(pages, curr, max_epoch)?;
            if (page.flags() & PAGE_FLAG_LEAF) != 0 {
                let entries = decode_leaf(&page)?;
                return Ok(entries
                    .binary_search_by(|(k, _)| k.as_slice().cmp(key))
                    .ok()
                    .map(|idx| entries[idx].1.clone()));
            }
            let (first_child, seps) = decode_interior(&page)?;
            let mut next = first_child;
            for (sep, right_child) in seps {
                if key >= sep.as_slice() {
                    next = right_child;
                } else {
                    break;
                }
            }
            curr = next;
        }
        Err(Error::new(Errno::EIO, "B+tree depth exceeded 32 levels"))
    }

    /// Return all `(key, value)` pairs in `[start_prefix ..]` where keys start with `prefix`.
    pub fn scan_prefix(
        &self,
        pages: &BTreeMap<PageId, Bytes>,
        root: u32,
        max_epoch: u64,
        prefix: &[u8],
    ) -> Result<KVPairs> {
        let mut all = Vec::new();
        if root == 0 {
            return Ok(all);
        }
        self.collect_range(pages, PageId::new(root)?, max_epoch, prefix, &mut all)?;
        Ok(all)
    }

    /// Return every `(key, value)` pair in key order across the entire tree.
    pub fn all_entries(
        &self,
        pages: &BTreeMap<PageId, Bytes>,
        root: u32,
        max_epoch: u64,
    ) -> Result<KVPairs> {
        self.scan_prefix(pages, root, max_epoch, &[])
    }

    fn collect_range(
        &self,
        pages: &BTreeMap<PageId, Bytes>,
        node_id: PageId,
        max_epoch: u64,
        prefix: &[u8],
        out: &mut KVPairs,
    ) -> Result<()> {
        let page = self.read_node(pages, node_id, max_epoch)?;
        if (page.flags() & PAGE_FLAG_LEAF) != 0 {
            for (k, v) in decode_leaf(&page)? {
                if k.starts_with(prefix) {
                    out.push((k, v));
                }
            }
            return Ok(());
        }
        let (first_child, seps) = decode_interior(&page)?;
        // Prune subtrees that cannot possibly contain `prefix`.
        let first_may_match = seps
            .first()
            .is_none_or(|(sep, _)| prefix <= &sep[..prefix.len().min(sep.len())]);
        if first_may_match {
            self.collect_range(pages, first_child, max_epoch, prefix, out)?;
        }
        for (i, (sep, child)) in seps.iter().enumerate() {
            let cmp_len = prefix.len().min(sep.len());
            if !prefix.is_empty() && &sep[..cmp_len] > prefix {
                // Even if `sep` is past `prefix`, the previous separator might have landed inside `prefix`.
                if sep.starts_with(prefix) {
                    self.collect_range(pages, *child, max_epoch, prefix, out)?;
                }
                break;
            }
            let next_starts_after = seps.get(i + 1).is_some_and(|(next_sep, _)| {
                let nlen = prefix.len().min(next_sep.len());
                &next_sep[..nlen] < prefix
            });
            if !next_starts_after {
                self.collect_range(pages, *child, max_epoch, prefix, out)?;
            }
        }
        Ok(())
    }

    /// Insert or replace `(key, value)` copy-on-write and return the new root page ID.
    pub fn insert(
        &self,
        pages: &mut BTreeMap<PageId, Bytes>,
        alloc: &mut PageAllocator,
        root: u32,
        epoch: u64,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<u32> {
        if root == 0 {
            let new_id = alloc.allocate_one()?;
            let leaf = encode_leaf(self.page_type, self.page_size, new_id, epoch, &[(key, value)])?;
            pages.insert(new_id, leaf);
            return Ok(new_id.get());
        }
        let root_id = PageId::new(root)?;
        let mut splits = self.insert_rec(pages, alloc, root_id, epoch, key, value)?;
        if splits.len() == 1 {
            return Ok(splits.pop().unwrap().1.get());
        }
        self.write_interior_layers(pages, alloc, epoch, splits)
    }

    fn insert_rec(
        &self,
        pages: &mut BTreeMap<PageId, Bytes>,
        alloc: &mut PageAllocator,
        node_id: PageId,
        epoch: u64,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<SepList> {
        let page = self.read_node(pages, node_id, epoch)?;
        alloc.free_page(node_id);
        pages.remove(&node_id);

        if (page.flags() & PAGE_FLAG_LEAF) != 0 {
            let mut entries = decode_leaf(&page)?;
            match entries.binary_search_by(|(k, _)| k.as_slice().cmp(&key)) {
                Ok(idx) => entries[idx].1 = value,
                Err(idx) => entries.insert(idx, (key, value)),
            }
            return self.write_leaf_chunks(pages, alloc, epoch, &entries);
        }

        let (first_child, seps) = decode_interior(&page)?;
        let mut children: SepList = Vec::with_capacity(1 + seps.len());
        children.push((Vec::new(), first_child));
        children.extend(seps);

        let mut target_idx = 0;
        for (i, (sep, _)) in children.iter().enumerate().skip(1) {
            if key.as_slice() >= sep.as_slice() {
                target_idx = i;
            } else {
                break;
            }
        }
        let target_child = children[target_idx].1;
        let mut replacement = self.insert_rec(pages, alloc, target_child, epoch, key, value)?;
        if target_idx == 0 {
            replacement[0].0 = Vec::new();
        }
        children.splice(target_idx..=target_idx, replacement);
        self.write_interior_chunks(pages, alloc, epoch, &children)
    }

    /// Remove `key` copy-on-write and return `(new_root, old_value)`.
    pub fn remove(
        &self,
        pages: &mut BTreeMap<PageId, Bytes>,
        alloc: &mut PageAllocator,
        root: u32,
        epoch: u64,
        key: &[u8],
    ) -> Result<(u32, Option<Vec<u8>>)> {
        if root == 0 {
            return Ok((0, None));
        }
        let old = self.get(pages, root, epoch, key)?;
        if old.is_none() {
            return Ok((root, None));
        }
        let mut entries = self.all_entries(pages, root, epoch)?;
        // Free all old tree nodes before writing the updated CoW tree.
        let mut old_nodes = BTreeSet::new();
        self.collect_node_ids(pages, root, epoch, &mut old_nodes)?;
        for id in old_nodes {
            alloc.free_page(id);
            pages.remove(&id);
        }
        entries.retain(|(k, _)| k.as_slice() != key);
        if entries.is_empty() {
            return Ok((0, old));
        }
        let leaf_splits = self.write_leaf_chunks(pages, alloc, epoch, &entries)?;
        let new_root = if leaf_splits.len() == 1 {
            leaf_splits[0].1.get()
        } else {
            self.write_interior_layers(pages, alloc, epoch, leaf_splits)?
        };
        Ok((new_root, old))
    }

    /// Collect all metadata `PageId`s belonging to this B+tree for `fsck` and tree deletion.
    pub fn collect_node_ids(
        &self,
        pages: &BTreeMap<PageId, Bytes>,
        root: u32,
        max_epoch: u64,
        out: &mut BTreeSet<PageId>,
    ) -> Result<()> {
        if root == 0 {
            return Ok(());
        }
        let mut stack = vec![PageId::new(root)?];
        while let Some(id) = stack.pop() {
            if !out.insert(id) {
                return Err(Error::new(
                    Errno::EIO,
                    format!("cycle detected in {:?} at page {id}", self.page_type),
                ));
            }
            let page = self.read_node(pages, id, max_epoch)?;
            if (page.flags() & PAGE_FLAG_LEAF) != 0 {
                let entries = decode_leaf(&page)?;
                for w in entries.windows(2) {
                    if w[0].0 >= w[1].0 {
                        return Err(Error::new(
                            Errno::EIO,
                            format!("unsorted keys in {:?} leaf {id}", self.page_type),
                        ));
                    }
                }
            } else {
                let (first_child, seps) = decode_interior(&page)?;
                stack.push(first_child);
                for (_, child) in seps {
                    stack.push(child);
                }
            }
        }
        Ok(())
    }

    fn read_node(
        &self,
        pages: &BTreeMap<PageId, Bytes>,
        id: PageId,
        max_epoch: u64,
    ) -> Result<MetaPage> {
        let raw = pages.get(&id).ok_or_else(|| {
            Error::new(
                Errno::EIO,
                format!("missing {:?} node page {id}", self.page_type),
            )
        })?;
        let page = MetaPage::parse(raw.clone(), self.page_size, id, max_epoch)?;
        if page.page_type() != self.page_type {
            return Err(Error::new(
                Errno::EIO,
                format!(
                    "page {id} has type {:?}, expected {:?}",
                    page.page_type(),
                    self.page_type
                ),
            ));
        }
        Ok(page)
    }

    fn write_leaf_chunks(
        &self,
        pages: &mut BTreeMap<PageId, Bytes>,
        alloc: &mut PageAllocator,
        epoch: u64,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<SepList> {
        let max_payload = self.page_size - HEADER_LEN;
        let mut out = Vec::new();
        let mut start = 0;
        while start < entries.len() {
            let mut end = start;
            let mut used = 0;
            while end < entries.len() {
                let (k, v) = &entries[end];
                let cell_len = 4 + k.len() + v.len();
                if cell_len > max_payload {
                    return Err(Error::new(
                        Errno::E2BIG,
                        format!("B+tree cell ({cell_len} B) exceeds page payload ({max_payload} B)"),
                    ));
                }
                if used + cell_len > max_payload {
                    break;
                }
                used += cell_len;
                end += 1;
            }
            let slice = &entries[start..end];
            let page_id = alloc.allocate_one()?;
            let bytes = encode_leaf(self.page_type, self.page_size, page_id, epoch, slice)?;
            pages.insert(page_id, bytes);
            out.push((slice[0].0.clone(), page_id));
            start = end;
        }
        Ok(out)
    }

    fn write_interior_chunks(
        &self,
        pages: &mut BTreeMap<PageId, Bytes>,
        alloc: &mut PageAllocator,
        epoch: u64,
        children: &[(Vec<u8>, PageId)],
    ) -> Result<SepList> {
        let max_payload = self.page_size - HEADER_LEN;
        let mut out = Vec::new();
        let mut start = 0;
        while start < children.len() {
            let mut end = start + 1;
            let mut used = 4; // first_child u32
            while end < children.len() {
                let (sep, _) = &children[end];
                let cell_len = 6 + sep.len();
                if used + cell_len > max_payload {
                    break;
                }
                used += cell_len;
                end += 1;
            }
            let slice = &children[start..end];
            let page_id = alloc.allocate_one()?;
            let bytes = encode_interior(
                self.page_type,
                self.page_size,
                page_id,
                epoch,
                slice[0].1,
                &slice[1..],
            )?;
            pages.insert(page_id, bytes);
            out.push((slice[0].0.clone(), page_id));
            start = end;
        }
        Ok(out)
    }

    fn write_interior_layers(
        &self,
        pages: &mut BTreeMap<PageId, Bytes>,
        alloc: &mut PageAllocator,
        epoch: u64,
        mut level: SepList,
    ) -> Result<u32> {
        while level.len() > 1 {
            level = self.write_interior_chunks(pages, alloc, epoch, &level)?;
        }
        Ok(level[0].1.get())
    }
}

fn encode_leaf(
    page_type: PageType,
    page_size: usize,
    id: PageId,
    epoch: u64,
    entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<Bytes> {
    let mut buf = MetaPageBuf::new(page_type, page_size);
    buf.set_flags(PAGE_FLAG_LEAF);
    let payload = buf.payload_mut();
    let mut at = 0usize;
    for (k, v) in entries {
        let need = 4 + k.len() + v.len();
        if at + need > payload.len() {
            return Err(Error::new(Errno::E2BIG, "leaf cell overflow"));
        }
        payload[at..at + 2].copy_from_slice(&(k.len() as u16).to_le_bytes());
        payload[at + 2..at + 2 + k.len()].copy_from_slice(k);
        at += 2 + k.len();
        payload[at..at + 2].copy_from_slice(&(v.len() as u16).to_le_bytes());
        payload[at + 2..at + 2 + v.len()].copy_from_slice(v);
        at += 2 + v.len();
    }
    buf.set_cell_count(entries.len() as u16);
    buf.set_free_offset(at as u32);
    Ok(buf.stamp(id, epoch))
}

fn decode_leaf(page: &MetaPage) -> Result<KVPairs> {
    let payload = page.payload();
    let end = page.free_offset() as usize;
    let count = page.cell_count() as usize;
    let mut at = 0usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if at + 2 > end {
            return Err(Error::new(Errno::EIO, "corrupt leaf key length"));
        }
        let klen = u16_at(payload, at) as usize;
        at += 2;
        if at + klen + 2 > end {
            return Err(Error::new(Errno::EIO, "corrupt leaf key bytes"));
        }
        let k = payload[at..at + klen].to_vec();
        at += klen;
        let vlen = u16_at(payload, at) as usize;
        at += 2;
        if at + vlen > end {
            return Err(Error::new(Errno::EIO, "corrupt leaf value bytes"));
        }
        let v = payload[at..at + vlen].to_vec();
        at += vlen;
        out.push((k, v));
    }
    Ok(out)
}

fn encode_interior(
    page_type: PageType,
    page_size: usize,
    id: PageId,
    epoch: u64,
    first_child: PageId,
    seps: &[(Vec<u8>, PageId)],
) -> Result<Bytes> {
    let mut buf = MetaPageBuf::new(page_type, page_size);
    let payload = buf.payload_mut();
    payload[0..4].copy_from_slice(&first_child.get().to_le_bytes());
    let mut at = 4usize;
    for (sep, child) in seps {
        let need = 6 + sep.len();
        if at + need > payload.len() {
            return Err(Error::new(Errno::E2BIG, "interior cell overflow"));
        }
        payload[at..at + 2].copy_from_slice(&(sep.len() as u16).to_le_bytes());
        payload[at + 2..at + 2 + sep.len()].copy_from_slice(sep);
        at += 2 + sep.len();
        payload[at..at + 4].copy_from_slice(&child.get().to_le_bytes());
        at += 4;
    }
    buf.set_cell_count(seps.len() as u16);
    buf.set_free_offset(at as u32);
    Ok(buf.stamp(id, epoch))
}

fn decode_interior(page: &MetaPage) -> Result<(PageId, SepList)> {
    let payload = page.payload();
    let end = page.free_offset() as usize;
    if end < 4 {
        return Err(Error::new(Errno::EIO, "corrupt interior node"));
    }
    let first_child = PageId::new(u32_at(payload, 0))?;
    let count = page.cell_count() as usize;
    let mut at = 4usize;
    let mut seps = Vec::with_capacity(count);
    for _ in 0..count {
        if at + 2 > end {
            return Err(Error::new(Errno::EIO, "corrupt interior sep length"));
        }
        let klen = u16_at(payload, at) as usize;
        at += 2;
        if at + klen + 4 > end {
            return Err(Error::new(Errno::EIO, "corrupt interior cell"));
        }
        let sep = payload[at..at + klen].to_vec();
        at += klen;
        let child = PageId::new(u32_at(payload, at))?;
        at += 4;
        seps.push((sep, child));
    }
    Ok((first_child, seps))
}