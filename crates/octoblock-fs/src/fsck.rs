//! Section 16.1 & 18.9 File-system consistency checker (`fsck`) and repair engine.

use std::collections::{BTreeMap, BTreeSet};

use crate::page::{MetaPage, PageId, PageType};
use crate::tree::{CowBTree, Extent, InodeData, InodeRecord, decode_dentry_chain};
use crate::{Result, S_IFDIR, Volume};

/// Outcome of running `fsck` on a `Volume`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckReport {
    /// Total reachable pages (metadata + data) verified.
    pub reachable_pages: usize,
    /// Total inodes verified in the inode tree.
    pub inodes_checked: usize,
    /// Human-readable descriptions of any inconsistencies found.
    pub problems: Vec<String>,
    /// Number of inconsistencies automatically repaired when `repair = true`.
    pub repaired: usize,
}

impl FsckReport {
    /// Whether the volume passed every check with zero problems.
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }
}

impl Volume {
    /// Walk all trees from the superblock; verify headers, extents, link counts, orphans,
    /// free-map bits, and live counters (Section 16.1 & 18.9).
    pub fn fsck(&mut self, repair: bool) -> Result<FsckReport> {
        let mut report = FsckReport::default();
        let page_size = self.sb.page_size as usize;
        let epoch = self.sb.epoch;
        let mut reachable: BTreeSet<PageId> = BTreeSet::new();

        // 1. Walk and collect node IDs of global B+trees (inode, dentry, orphan).
        let inode_tree = CowBTree::new(PageType::InodeTree, page_size);
        let dentry_tree = CowBTree::new(PageType::DentryTree, page_size);
        let extent_tree = CowBTree::new(PageType::ExtentTree, page_size);
        let xattr_tree = CowBTree::new(PageType::XattrLeaf, page_size);
        let orphan_tree = CowBTree::new(PageType::OrphanLeaf, page_size);

        for (tree, root, label) in [
            (&inode_tree, self.sb.inode_root, "inode_tree"),
            (&dentry_tree, self.sb.dentry_root, "dentry_tree"),
            (&orphan_tree, self.sb.orphan_root, "orphan_tree"),
        ] {
            if let Err(e) = tree.collect_node_ids(&self.pages, root, epoch, &mut reachable) {
                report.problems.push(format!("{label}: {e}"));
            }
        }

        // 2. Decode all inodes, verify extents, per-file extent trees, and per-inode xattr trees.
        let mut inodes: BTreeMap<u64, InodeRecord> = BTreeMap::new();
        let mut computed_blocks: BTreeMap<u64, u64> = BTreeMap::new();
        if let Ok(entries) = inode_tree.all_entries(&self.pages, self.sb.inode_root, epoch) {
            for (k, v) in entries {
                if k.len() != 8 {
                    report.problems.push("malformed inode key length".into());
                    continue;
                }
                let key_ino = u64::from_be_bytes(k.try_into().unwrap());
                let Ok(rec) = InodeRecord::decode(&v) else {
                    report
                        .problems
                        .push(format!("inode {key_ino}: corrupt record"));
                    continue;
                };
                if rec.ino != key_ino {
                    report.problems.push(format!(
                        "inode key {key_ino} != record ino {}",
                        rec.ino
                    ));
                }
                report.inodes_checked += 1;

                // Collect per-inode xattr tree pages
                if let Some(xroot) = rec.xattr_root
                    && let Err(e) =
                        xattr_tree.collect_node_ids(&self.pages, xroot.get(), epoch, &mut reachable)
                {
                    report
                        .problems
                        .push(format!("inode {key_ino} xattr tree: {e}"));
                }

                let extents: Vec<Extent> = match &rec.data {
                    InodeData::Inline(_) => Vec::new(),
                    InodeData::Extents(list) => list.clone(),
                    InodeData::ExtentTree(root_id) => {
                        if let Err(e) = extent_tree.collect_node_ids(
                            &self.pages,
                            root_id.get(),
                            epoch,
                            &mut reachable,
                        ) {
                            report
                                .problems
                                .push(format!("inode {key_ino} extent tree: {e}"));
                        }
                        let mut list = Vec::new();
                        if let Ok(ext_cells) =
                            extent_tree.all_entries(&self.pages, root_id.get(), epoch)
                        {
                            for (_, ev) in ext_cells {
                                if let Ok(ext) = Extent::decode(&ev) {
                                    list.push(ext);
                                }
                            }
                        }
                        list
                    }
                };

                let mut file_blocks = 0u64;
                for ext in extents {
                    if !ext.is_hole() {
                        file_blocks += ext.len as u64;
                        for i in 0..(ext.len as u32) {
                            let Ok(pid) = PageId::new(ext.page_id.get() + i) else {
                                report
                                    .problems
                                    .push(format!("inode {key_ino}: invalid extent page id"));
                                continue;
                            };
                            if !reachable.insert(pid) {
                                report.problems.push(format!(
                                    "data page {pid} referenced by multiple extents"
                                ));
                            }
                            match self.pages.get(&pid) {
                                Some(bytes) if bytes.len() == page_size => {}
                                Some(bytes) => report.problems.push(format!(
                                    "data page {pid} has length {}, expected {page_size}",
                                    bytes.len()
                                )),
                                None => report.problems.push(format!(
                                    "inode {key_ino} extent references missing data page {pid}"
                                )),
                            }
                        }
                    }
                }
                if rec.blocks != file_blocks {
                    report.problems.push(format!(
                        "inode {key_ino}: blocks counter is {}, actual allocated pages {file_blocks}",
                        rec.blocks
                    ));
                }
                computed_blocks.insert(key_ino, file_blocks);
                inodes.insert(key_ino, rec);
            }
        }

        // 3. Walk dentry tree and compute expected link counts (EC-D03).
        let mut expected_nlink: BTreeMap<u64, u32> = BTreeMap::new();
        if inodes.contains_key(&crate::ROOT_INO) {
            expected_nlink.insert(crate::ROOT_INO, 2);
        }
        if let Ok(dentries) = dentry_tree.all_entries(&self.pages, self.sb.dentry_root, epoch) {
            for (k, v) in dentries {
                if k.len() != 16 {
                    report.problems.push("malformed dentry key length".into());
                    continue;
                }
                let dir_ino = u64::from_be_bytes(k[0..8].try_into().unwrap());
                if !inodes.contains_key(&dir_ino) {
                    report.problems.push(format!(
                        "dentry references non-existent parent directory {dir_ino}"
                    ));
                }
                let Ok(chain) = decode_dentry_chain(&v) else {
                    report
                        .problems
                        .push(format!("corrupt dentry chain in dir {dir_ino}"));
                    continue;
                };
                for item in chain {
                    match inodes.get(&item.child_ino) {
                        None => report.problems.push(format!(
                            "dentry {:?} in dir {dir_ino} points to missing inode {}",
                            String::from_utf8_lossy(&item.name),
                            item.child_ino
                        )),
                        Some(child_rec) => {
                            if (child_rec.mode & S_IFDIR) != 0 {
                                *expected_nlink.entry(item.child_ino).or_insert(1) += 1;
                                *expected_nlink.entry(dir_ino).or_insert(2) += 1;
                            } else {
                                *expected_nlink.entry(item.child_ino).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
        }

        // 4. Check orphans (EC-D06: orphan with nlink > 0 or missing inode must be cleared).
        let mut orphans_in_tree: BTreeSet<u64> = BTreeSet::new();
        if let Ok(orphan_entries) =
            orphan_tree.all_entries(&self.pages, self.sb.orphan_root, epoch)
        {
            for (k, _) in orphan_entries {
                if k.len() == 8 {
                    let ino = u64::from_be_bytes(k.try_into().unwrap());
                    let exists = inodes.contains_key(&ino);
                    let ref_links = expected_nlink.get(&ino).copied().unwrap_or(0);
                    if !exists || ref_links > 0 {
                        report.problems.push(format!(
                            "orphan inode {ino} invalid (exists={exists}, ref_links={ref_links}) (EC-D06)"
                        ));
                        if repair
                            && let Ok((new_root, _)) = orphan_tree.remove(
                                &mut self.pages,
                                &mut self.alloc,
                                self.sb.orphan_root,
                                epoch,
                                &ino.to_be_bytes(),
                            )
                        {
                            self.sb.orphan_root = new_root;
                            report.repaired += 1;
                        }
                    } else {
                        orphans_in_tree.insert(ino);
                    }
                }
            }
        }

        // Compare inode link counts and blocks against computed values (EC-D03).
        let mut purged_inodes = 0usize;
        for (&ino, rec) in &inodes {
            let want_nlink = expected_nlink.get(&ino).copied().unwrap_or(0);
            let want_blocks = computed_blocks.get(&ino).copied().unwrap_or(rec.blocks);

            if want_nlink == 0 && !orphans_in_tree.contains(&ino) {
                report.problems.push(format!(
                    "inode {ino} has 0 directory references and is not in orphan tree (EC-D03)"
                ));
                if repair && self.purge_inode(rec.clone()).is_ok() {
                    purged_inodes += 1;
                    report.repaired += 1;
                }
                continue;
            }

            let nlink_bad = !orphans_in_tree.contains(&ino) && rec.nlink != want_nlink;
            let blocks_bad = rec.blocks != want_blocks;
            if nlink_bad && !orphans_in_tree.contains(&ino) {
                report.problems.push(format!(
                    "inode {ino}: nlink is {}, directory references count is {want_nlink} (EC-D03)",
                    rec.nlink
                ));
            }
            if repair && (nlink_bad || blocks_bad) {
                let mut fixed = rec.clone();
                if nlink_bad {
                    fixed.nlink = want_nlink;
                }
                fixed.blocks = want_blocks;
                if let Ok(new_root) = inode_tree.insert(
                    &mut self.pages,
                    &mut self.alloc,
                    self.sb.inode_root,
                    epoch,
                    ino.to_be_bytes().to_vec(),
                    fixed.encode(),
                ) {
                    self.sb.inode_root = new_root;
                    report.repaired += 1;
                }
            }
        }

        // 5. Recompute reachable pages if repair mutated trees.
        if repair && report.repaired > 0 {
            reachable.clear();
            for (tree, root) in [
                (&inode_tree, self.sb.inode_root),
                (&dentry_tree, self.sb.dentry_root),
                (&orphan_tree, self.sb.orphan_root),
            ] {
                let _ = tree.collect_node_ids(&self.pages, root, epoch, &mut reachable);
            }
            if let Ok(entries) = inode_tree.all_entries(&self.pages, self.sb.inode_root, epoch) {
                for (_, v) in entries {
                    if let Ok(rec) = InodeRecord::decode(&v) {
                        if let Some(xroot) = rec.xattr_root {
                            let _ = xattr_tree.collect_node_ids(
                                &self.pages,
                                xroot.get(),
                                epoch,
                                &mut reachable,
                            );
                        }
                        match rec.data {
                            InodeData::Inline(_) => {}
                            InodeData::Extents(list) => {
                                for ext in list {
                                    if !ext.is_hole() {
                                        for i in 0..(ext.len as u32) {
                                            if let Ok(pid) = PageId::new(ext.page_id.get() + i) {
                                                reachable.insert(pid);
                                            }
                                        }
                                    }
                                }
                            }
                            InodeData::ExtentTree(root_id) => {
                                let _ = extent_tree.collect_node_ids(
                                    &self.pages,
                                    root_id.get(),
                                    epoch,
                                    &mut reachable,
                                );
                                if let Ok(cells) =
                                    extent_tree.all_entries(&self.pages, root_id.get(), epoch)
                                {
                                    for (_, ev) in cells {
                                        if let Ok(ext) = Extent::decode(&ev)
                                            && !ext.is_hole()
                                        {
                                            for i in 0..(ext.len as u32) {
                                                if let Ok(pid) = PageId::new(ext.page_id.get() + i)
                                                {
                                                    reachable.insert(pid);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        report.reachable_pages = reachable.len();

        // 6. Verify FreeMap and stored non-system pages vs reachable set (EC-D05).
        for &pid in &reachable {
            if !self.alloc.is_allocated(pid) {
                report.problems.push(format!(
                    "reachable page {pid} is marked free in allocator/free-map (EC-D05)"
                ));
            }
        }
        let leaked_pages: Vec<PageId> = self
            .pages
            .keys()
            .copied()
            .filter(|id| !self.sb.is_system_page(*id) && !reachable.contains(id))
            .collect();
        if !leaked_pages.is_empty() {
            report.problems.push(format!(
                "{} unreachable non-system page(s) present in page map",
                leaked_pages.len()
            ));
            if repair {
                for id in leaked_pages {
                    self.pages.remove(&id);
                }
                report.repaired += 1;
            }
        }
        if self.alloc.live_pages() != reachable.len() as u64
            || reachable.iter().any(|&p| !self.alloc.is_allocated(p))
        {
            report.problems.push(format!(
                "allocator live_pages ({}) != reachable pages ({}) (EC-D04/EC-D05)",
                self.alloc.live_pages(),
                reachable.len()
            ));
            if repair {
                self.alloc.rebuild_from_reachable(&reachable);
                report.repaired += 1;
            }
        }

        // 7. Verify Superblock live_pages, live_bytes, and inode_count counters (EC-D04).
        let actual_live_pages = reachable.len() as u64;
        let actual_live_bytes = actual_live_pages * (page_size as u64);
        if self.sb.live_pages != actual_live_pages || self.sb.live_bytes != actual_live_bytes {
            report.problems.push(format!(
                "superblock live_bytes={} (pages={}), actual live_bytes={} (pages={}) (EC-D04)",
                self.sb.live_bytes, self.sb.live_pages, actual_live_bytes, actual_live_pages
            ));
            if repair {
                self.sb.live_pages = actual_live_pages;
                self.sb.live_bytes = actual_live_bytes;
                report.repaired += 1;
            }
        }
        let expected_inodes = (inodes.len() - purged_inodes) as u64;
        if self.sb.inode_count != expected_inodes {
            report.problems.push(format!(
                "superblock inode_count={} != actual {expected_inodes}",
                self.sb.inode_count
            ));
            if repair {
                self.sb.inode_count = expected_inodes;
                report.repaired += 1;
            }
        }

        // 8. Check raw metadata headers on all system pages in store.
        for (&id, bytes) in &self.pages {
            if self.sb.is_system_page(id)
                && let Err(e) = MetaPage::parse(bytes.clone(), page_size, id, self.sb.epoch)
            {
                report.problems.push(format!("system page {id}: {e}"));
            }
        }

        if repair && report.repaired > 0 {
            self.alloc
                .write_free_map_pages(&self.sb, self.sb.epoch, &mut self.pages)?;
            self.pages.insert(PageId::SUPERBLOCK, self.sb.encode());
            self.alloc.begin_group();
        }
        Ok(report)
    }
}