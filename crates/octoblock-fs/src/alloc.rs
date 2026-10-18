//! Section 4.9 Page and Inode Allocator: 256-page allocation groups, free-map bitmaps,
//! reachability guards (EC-D05), and 65,536-inode reservation ranges.

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;

use crate::page::{HEADER_LEN, MAX_PAGE_ID, MetaPage, MetaPageBuf, PageId, PageType, Superblock};
use crate::{Errno, Error, Result};

/// Pages per allocation group (1 fan-out leaf = 256 pages = 1 MiB at 4 KB).
pub const GROUP_PAGES: u32 = 256;
/// Number of inodes reserved at a time by a mount (Section 4.9).
pub const INO_RANGE_SIZE: u64 = 65_536;

/// A reserved half-open inode range `[start, end_inclusive]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InoRange {
    /// First inode number in the reservation.
    pub start: u64,
    /// Last inode number in the reservation (inclusive).
    pub end_inclusive: u64,
    /// Next inode number to hand out from this range.
    pub next: u64,
}

impl InoRange {
    /// Reserve a new 65,536-inode range from `superblock.next_ino`.
    pub fn reserve(sb: &mut Superblock) -> Self {
        let start = sb.next_ino.max(65_536);
        let end_inclusive = start + INO_RANGE_SIZE - 1;
        sb.next_ino = end_inclusive + 1;
        InoRange {
            start,
            end_inclusive,
            next: start,
        }
    }

    /// Take the next inode from this reservation, or `None` if exhausted.
    pub fn allocate(&mut self) -> Option<u64> {
        if self.next > self.end_inclusive {
            return None;
        }
        let ino = self.next;
        self.next += 1;
        Some(ino)
    }
}

/// Read bit `bit_idx` from a free-map page payload.
pub fn map_bit(payload: &[u8], bit_idx: u32) -> bool {
    let byte_idx = (bit_idx / 8) as usize;
    payload
        .get(byte_idx)
        .is_some_and(|b| (b & (1 << (bit_idx % 8))) != 0)
}

/// Set or clear `bit_idx` in a free-map page payload.
pub fn set_map_bit(payload: &mut [u8], bit_idx: u32, used: bool) {
    let byte_idx = (bit_idx / 8) as usize;
    if let Some(byte) = payload.get_mut(byte_idx) {
        if used {
            *byte |= 1 << (bit_idx % 8);
        } else {
            *byte &= !(1 << (bit_idx % 8));
        }
    }
}

/// Deterministic 64-bit FNV-1a hash for mount group selection.
pub fn hash_mount_id(mount_id: u64) -> u64 {
    mount_id
        .to_le_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
            (h ^ (b as u64)).wrapping_mul(0x0100_0000_01b3)
        })
}

/// Tracks allocated and freed pages across a commit group and persists to `FreeMap` pages.
#[derive(Clone, Debug)]
pub struct PageAllocator {
    page_size: usize,
    first_usable: u32,
    preferred_group: u32,
    cursor: u32,
    /// Set of all currently allocated non-system pages (`first_usable..=MAX_PAGE_ID`).
    used: BTreeSet<u32>,
    /// Pages reachable in the base snapshot that must not be overwritten in-place (CoW + EC-D05).
    protected_base: BTreeSet<u32>,
    /// Maximum page ID allocated so far, to bound free-map page materialization.
    high_water: u32,
}

impl PageAllocator {
    /// Create a new allocator for `sb` and `mount_id`.
    pub fn new(sb: &Superblock, mount_id: u64) -> Self {
        let first_usable = sb.first_usable_page();
        // Spread mounts across the first 4,096 groups (1M pages) by default so fan-out trees stay compact
        // while avoiding concurrent writer collisions.
        let group_span = 256u32;
        let preferred_group =
            (first_usable / GROUP_PAGES) + ((hash_mount_id(mount_id) as u32) % group_span);
        let cursor = (preferred_group * GROUP_PAGES).max(first_usable);
        PageAllocator {
            page_size: sb.page_size as usize,
            first_usable,
            preferred_group,
            cursor,
            used: BTreeSet::new(),
            protected_base: BTreeSet::new(),
            high_water: first_usable,
        }
    }

    /// Load allocator state from the free-map pages stored in `pages` and protect `reachable`.
    pub fn load_from_store(
        sb: &Superblock,
        mount_id: u64,
        pages: &BTreeMap<PageId, Bytes>,
        reachable: &BTreeSet<PageId>,
    ) -> Result<Self> {
        let mut alloc = Self::new(sb, mount_id);
        let bits_per_page = ((alloc.page_size - HEADER_LEN) * 8) as u32;
        for (&id, raw) in pages {
            if id == PageId::SUPERBLOCK || id.get() > sb.map_pages {
                continue;
            }
            let meta = MetaPage::parse(raw.clone(), alloc.page_size, id, sb.epoch)?;
            if meta.page_type() != PageType::FreeMap {
                return Err(Error::new(
                    Errno::EIO,
                    format!(
                        "system page {id} has type {:?}, expected FreeMap",
                        meta.page_type()
                    ),
                ));
            }
            let base_id = (id.get() - 1) * bits_per_page;
            for (byte_i, &b) in meta.payload().iter().enumerate() {
                if b == 0 {
                    continue;
                }
                for bit in 0..8u32 {
                    if (b & (1 << bit)) != 0 {
                        let pid = base_id + (byte_i as u32) * 8 + bit;
                        if pid >= alloc.first_usable && pid <= MAX_PAGE_ID {
                            alloc.used.insert(pid);
                            alloc.high_water = alloc.high_water.max(pid + 1);
                        }
                    }
                }
            }
        }
        // EC-D05: Never hand out a page that is reachable from the current tree even if the free-map was stale.
        for &r in reachable {
            if r.get() >= alloc.first_usable {
                alloc.used.insert(r.get());
                alloc.protected_base.insert(r.get());
                alloc.high_water = alloc.high_water.max(r.get() + 1);
            }
        }
        Ok(alloc)
    }

    /// Begin a new commit group: lock in the currently used pages as `protected_base` so CoW
    /// updates within the group never overwrite a page from the parent commit.
    pub fn begin_group(&mut self) {
        self.protected_base = self.used.clone();
    }

    /// Number of currently allocated non-system pages (`live_pages`).
    pub fn live_pages(&self) -> u64 {
        self.used.len() as u64
    }

    /// Whether `id` is marked allocated in the current free-map state.
    pub fn is_allocated(&self, id: PageId) -> bool {
        if id.get() < self.first_usable {
            return true;
        }
        self.used.contains(&id.get())
    }

    /// Allocate a single free page ID, preferring the mount's 256-page allocation group.
    pub fn allocate_one(&mut self) -> Result<PageId> {
        let mut run = self.allocate_run(1)?;
        Ok(run.pop().expect("run of 1"))
    }

    /// Allocate up to `count` contiguous page IDs inside a 256-page group (Section 4.9).
    pub fn allocate_run(&mut self, count: usize) -> Result<Vec<PageId>> {
        let want = count.max(1) as u32;
        if let Some(run) = self.find_contiguous(self.cursor, MAX_PAGE_ID, want) {
            return self.claim_run(run, want);
        }
        if self.cursor > self.first_usable
            && let Some(run) = self.find_contiguous(self.first_usable, self.cursor - 1, want)
        {
            return self.claim_run(run, want);
        }
        // If no single contiguous run of `want` exists, fall back to individual pages.
        if want > 1 {
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                out.push(self.allocate_one()?);
            }
            return Ok(out);
        }
        Err(Error::new(
            Errno::ENOSPC,
            "24-bit page address space exhausted",
        ))
    }

    fn find_contiguous(&self, start: u32, end_inclusive: u32, want: u32) -> Option<u32> {
        let mut candidate = start.max(self.first_usable);
        while candidate.saturating_add(want - 1) <= end_inclusive {
            // Keep sequential runs aligned inside a single 256-page fan-out leaf when possible.
            if want <= GROUP_PAGES {
                let group_end = ((candidate / GROUP_PAGES) + 1) * GROUP_PAGES - 1;
                if candidate + want - 1 > group_end {
                    candidate = group_end + 1;
                    continue;
                }
            }
            let mut conflict_at = None;
            for offset in 0..want {
                let pid = candidate + offset;
                if self.used.contains(&pid) || self.protected_base.contains(&pid) {
                    conflict_at = Some(pid);
                    break;
                }
            }
            match conflict_at {
                None => return Some(candidate),
                Some(busy) => candidate = busy + 1,
            }
        }
        None
    }

    fn claim_run(&mut self, start: u32, len: u32) -> Result<Vec<PageId>> {
        let mut out = Vec::with_capacity(len as usize);
        for i in 0..len {
            let pid = start + i;
            self.used.insert(pid);
            self.high_water = self.high_water.max(pid + 1);
            out.push(PageId::new(pid)?);
        }
        self.cursor = (start + len).min(MAX_PAGE_ID);
        Ok(out)
    }

    /// Free a page ID so it disappears from the live tree and becomes reusable in the next commit.
    pub fn free_page(&mut self, id: PageId) {
        let raw = id.get();
        if raw >= self.first_usable {
            self.used.remove(&raw);
            if !self.protected_base.contains(&raw) && raw < self.cursor {
                let preferred_start =
                    (self.preferred_group * GROUP_PAGES).max(self.first_usable);
                if raw >= preferred_start {
                    self.cursor = raw;
                }
            }
        }
    }

    /// Replace the allocator's used set with the exact reachable set (used by `fsck --repair`).
    pub fn rebuild_from_reachable(&mut self, reachable: &BTreeSet<PageId>) {
        self.used.clear();
        self.high_water = self.first_usable;
        for &id in reachable {
            if id.get() >= self.first_usable {
                self.used.insert(id.get());
                self.high_water = self.high_water.max(id.get() + 1);
            }
        }
        self.protected_base = self.used.clone();
    }

    /// Materialize the touched `FreeMap` metadata pages into `pages` for `epoch`.
    pub fn write_free_map_pages(
        &self,
        sb: &Superblock,
        epoch: u64,
        pages: &mut BTreeMap<PageId, Bytes>,
    ) -> Result<()> {
        let bits_per_page = ((self.page_size - HEADER_LEN) * 8) as u32;
        let max_id = self.high_water.max(self.first_usable);
        let needed_map_pages = (max_id + 1).div_ceil(bits_per_page).max(1);

        // Remove any old higher free-map pages that are now completely empty.
        let existing_maps: Vec<PageId> = pages
            .keys()
            .copied()
            .filter(|id| id.get() >= 1 && id.get() <= sb.map_pages)
            .collect();
        for id in existing_maps {
            if id.get() > needed_map_pages {
                pages.remove(&id);
            }
        }

        for map_idx in 0..needed_map_pages {
            let map_page_id = PageId::new(1 + map_idx)?;
            let base_pid = map_idx * bits_per_page;
            let end_pid = ((map_idx + 1) * bits_per_page).min(MAX_PAGE_ID + 1);

            let mut buf = MetaPageBuf::new(PageType::FreeMap, self.page_size);
            let mut set_count = 0u32;
            // System pages `0..first_usable` are always marked in use in map page 1.
            let sys_end = self.first_usable.min(end_pid);
            if base_pid < sys_end {
                for pid in base_pid..sys_end {
                    set_map_bit(buf.payload_mut(), pid - base_pid, true);
                    set_count += 1;
                }
            }
            for &pid in self.used.range(base_pid.max(self.first_usable)..end_pid) {
                set_map_bit(buf.payload_mut(), pid - base_pid, true);
                set_count += 1;
            }
            if set_count > 0 || map_idx == 0 {
                buf.set_cell_count((set_count.min(u16::MAX as u32)) as u16);
                buf.set_free_offset((self.page_size - HEADER_LEN) as u32);
                pages.insert(map_page_id, buf.stamp(map_page_id, epoch));
            } else {
                pages.remove(&map_page_id);
            }
        }
        Ok(())
    }
}