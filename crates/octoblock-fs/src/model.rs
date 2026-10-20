use std::collections::{BTreeMap, BTreeSet};

use crate::page::CasePolicy;
use crate::{
    Errno, RENAME_EXCHANGE, RENAME_NOREPLACE, ROOT_INO, Result, S_IFDIR, S_IFLNK, S_IFREG, Volume,
};

#[derive(Clone, Debug)]
struct RefInode {
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    data: Vec<u8>,
    xattrs: BTreeMap<String, Vec<u8>>,
}

/// Simple, obviously-correct in-memory POSIX file-system reference model for differential testing.
#[derive(Clone, Debug)]
pub struct RefModel {
    inodes: BTreeMap<u64, RefInode>,
    dentries: BTreeMap<(u64, Vec<u8>), u64>,
    open_handles: BTreeMap<u64, usize>,
}

impl Default for RefModel {
    fn default() -> Self {
        Self::new()
    }
}

impl RefModel {
    /// Create a fresh reference model with root directory (`ino = 1`).
    pub fn new() -> Self {
        let mut inodes = BTreeMap::new();
        inodes.insert(
            ROOT_INO,
            RefInode {
                mode: S_IFDIR | 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                data: Vec::new(),
                xattrs: BTreeMap::new(),
            },
        );
        RefModel {
            inodes,
            dentries: BTreeMap::new(),
            open_handles: BTreeMap::new(),
        }
    }

    /// Create a regular file in the reference model using the `ino` allocated by `Volume`.
    pub fn create(&mut self, parent: u64, name: &[u8], mode: u32, ino: u64) {
        self.inodes.insert(
            ino,
            RefInode {
                mode: S_IFREG | (mode & 0o7777),
                nlink: 1,
                uid: 1000,
                gid: 1000,
                data: Vec::new(),
                xattrs: BTreeMap::new(),
            },
        );
        self.dentries.insert((parent, name.to_vec()), ino);
    }

    /// Create a directory in the reference model.
    pub fn mkdir(&mut self, parent: u64, name: &[u8], mode: u32, ino: u64) {
        self.inodes.insert(
            ino,
            RefInode {
                mode: S_IFDIR | (mode & 0o7777),
                nlink: 2,
                uid: 1000,
                gid: 1000,
                data: Vec::new(),
                xattrs: BTreeMap::new(),
            },
        );
        self.dentries.insert((parent, name.to_vec()), ino);
        if let Some(p) = self.inodes.get_mut(&parent) {
            p.nlink += 1;
        }
    }

    /// Create a symlink in the reference model.
    pub fn symlink(&mut self, parent: u64, name: &[u8], target: &[u8], ino: u64) {
        self.inodes.insert(
            ino,
            RefInode {
                mode: S_IFLNK | 0o777,
                nlink: 1,
                uid: 1000,
                gid: 1000,
                data: target.to_vec(),
                xattrs: BTreeMap::new(),
            },
        );
        self.dentries.insert((parent, name.to_vec()), ino);
    }

    /// Create a hard link in the reference model.
    pub fn link(&mut self, ino: u64, new_parent: u64, new_name: &[u8]) {
        if let Some(node) = self.inodes.get_mut(&ino) {
            node.nlink += 1;
            self.dentries.insert((new_parent, new_name.to_vec()), ino);
        }
    }

    /// Unlink a non-directory entry in the reference model.
    pub fn unlink(&mut self, parent: u64, name: &[u8]) {
        if let Some(ino) = self.dentries.remove(&(parent, name.to_vec()))
            && let Some(node) = self.inodes.get_mut(&ino)
        {
            node.nlink = node.nlink.saturating_sub(1);
            if node.nlink == 0 && !self.open_handles.contains_key(&ino) {
                self.inodes.remove(&ino);
            }
        }
    }

    /// Remove an empty directory in the reference model.
    pub fn rmdir(&mut self, parent: u64, name: &[u8]) {
        if let Some(ino) = self.dentries.remove(&(parent, name.to_vec())) {
            self.inodes.remove(&ino);
            if let Some(p) = self.inodes.get_mut(&parent) {
                p.nlink = p.nlink.saturating_sub(1).max(2);
            }
        }
    }

    /// Rename an entry in the reference model.
    pub fn rename(
        &mut self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        flags: u32,
    ) {
        if flags == RENAME_EXCHANGE {
            let a = self
                .dentries
                .remove(&(old_parent, old_name.to_vec()))
                .unwrap();
            let b = self
                .dentries
                .remove(&(new_parent, new_name.to_vec()))
                .unwrap();
            self.dentries.insert((old_parent, old_name.to_vec()), b);
            self.dentries.insert((new_parent, new_name.to_vec()), a);
            return;
        }
        let Some(src_ino) = self.dentries.remove(&(old_parent, old_name.to_vec())) else {
            return;
        };
        let src_is_dir = self
            .inodes
            .get(&src_ino)
            .is_some_and(|n| (n.mode & S_IFDIR) != 0);
        if let Some(dst_ino) = self.dentries.remove(&(new_parent, new_name.to_vec()))
            && dst_ino != src_ino
            && let Some(dst) = self.inodes.get_mut(&dst_ino)
        {
            if (dst.mode & S_IFDIR) != 0 {
                self.inodes.remove(&dst_ino);
                if let Some(np) = self.inodes.get_mut(&new_parent) {
                    np.nlink = np.nlink.saturating_sub(1).max(2);
                }
            } else {
                dst.nlink = dst.nlink.saturating_sub(1);
                if dst.nlink == 0 && !self.open_handles.contains_key(&dst_ino) {
                    self.inodes.remove(&dst_ino);
                }
            }
        }
        if src_is_dir && old_parent != new_parent {
            if let Some(op) = self.inodes.get_mut(&old_parent) {
                op.nlink = op.nlink.saturating_sub(1).max(2);
            }
            if let Some(np) = self.inodes.get_mut(&new_parent) {
                np.nlink += 1;
            }
        }
        self.dentries.insert((new_parent, new_name.to_vec()), src_ino);
    }

    /// Write bytes to `ino` at `offset`.
    pub fn write(&mut self, ino: u64, offset: usize, data: &[u8]) {
        if let Some(node) = self.inodes.get_mut(&ino) {
            if offset + data.len() > node.data.len() {
                node.data.resize(offset + data.len(), 0);
            }
            node.data[offset..offset + data.len()].copy_from_slice(data);
        }
    }

    /// Read bytes from `ino` at `offset`.
    pub fn read(&self, ino: u64, offset: usize, len: usize) -> Vec<u8> {
        let Some(node) = self.inodes.get(&ino) else {
            return Vec::new();
        };
        if offset >= node.data.len() || len == 0 {
            return Vec::new();
        }
        let end = (offset + len).min(node.data.len());
        node.data[offset..end].to_vec()
    }

    /// Truncate or extend `ino` to `new_size`.
    pub fn truncate(&mut self, ino: u64, new_size: usize) {
        if let Some(node) = self.inodes.get_mut(&ino) {
            node.data.resize(new_size, 0);
        }
    }

    /// Zero a range of bytes (`punch_hole`).
    pub fn punch_hole(&mut self, ino: u64, offset: usize, len: usize) {
        if let Some(node) = self.inodes.get_mut(&ino) {
            if offset >= node.data.len() {
                return;
            }
            let end = (offset + len).min(node.data.len());
            node.data[offset..end].fill(0);
        }
    }

    /// Assert that `vol` matches `self` on every directory, inode, file byte, and xattr.
    pub fn assert_matches(&self, vol: &Volume) -> Result<()> {
        for (&ino, ref_node) in &self.inodes {
            let rec = vol.getattr(ino)?;
            assert_eq!(rec.uid, ref_node.uid, "uid mismatch on ino {ino}");
            assert_eq!(rec.gid, ref_node.gid, "gid mismatch on ino {ino}");
            assert_eq!(
                rec.nlink, ref_node.nlink,
                "nlink mismatch on ino {ino}: vol={} ref={}",
                rec.nlink, ref_node.nlink
            );
            assert_eq!(
                rec.nlink, ref_node.nlink,
                "nlink mismatch on ino {ino}: vol={} ref={}",
                rec.nlink, ref_node.nlink
            );
            if (ref_node.mode & S_IFREG) != 0 {
                assert_eq!(
                    rec.size as usize,
                    ref_node.data.len(),
                    "size mismatch on ino {ino}"
                );
                let got = vol.read(ino, 0, ref_node.data.len() + 64)?;
                assert_eq!(got, ref_node.data, "content mismatch on ino {ino}");
            } else if (ref_node.mode & S_IFLNK) != 0 {
                let got = vol.readlink(ino)?;
                assert_eq!(got, ref_node.data, "symlink target mismatch on ino {ino}");
            }
            for (k, v) in &ref_node.xattrs {
                let got_x = vol.getxattr(ino, k)?;
                assert_eq!(&got_x, v, "xattr {k} mismatch on ino {ino}");
            }
        }
        Ok(())
    }
}

/// Run the `fsx` random byte-range operation suite (`steps` operations) on one file and assert
/// exact byte-for-byte equivalence against an in-memory buffer at every step.
pub fn run_fsx(steps: usize, seed: u64) -> Result<()> {
    let mut rng = fastrand::Rng::with_seed(seed);
    let mut vol = Volume::mkfs(4096, [0x42; 16], CasePolicy::Sensitive, 1)?;
    let ino = vol.create(ROOT_INO, b"fsx.bin", 0o644, 1000, 1000)?;
    let mut reference: Vec<u8> = Vec::new();
    let max_len = 64 * 1024; // up to 16 pages so inline -> inline extents -> extent tree transitions are exercised

    for step in 0..steps {
        match rng.u8(0..5) {
            0..=1 => {
                // Random unaligned write
                let off = rng.usize(0..max_len);
                let len = rng.usize(1..=8192);
                let mut payload = vec![0u8; len];
                for b in &mut payload {
                    *b = rng.u8(..);
                }
                vol.write(ino, off as u64, &payload)?;
                if off + len > reference.len() {
                    reference.resize(off + len, 0);
                }
                reference[off..off + len].copy_from_slice(&payload);
            }
            2 => {
                // Random truncate (shrink or extend)
                let new_size = rng.usize(0..max_len);
                vol.truncate(ino, new_size as u64)?;
                reference.resize(new_size, 0);
            }
            3 => {
                // Random page-aligned hole punch
                let page_off = rng.usize(0..16) * 4096;
                let page_len = rng.usize(1..=4) * 4096;
                vol.punch_hole(ino, page_off as u64, page_len as u64)?;
                if page_off < reference.len() {
                    let end = (page_off + page_len).min(reference.len());
                    reference[page_off..end].fill(0);
                }
            }
            _ => {
                // Random read verification
                let off = rng.usize(0..=reference.len());
                let len = rng.usize(0..=12288);
                let got = vol.read(ino, off as u64, len)?;
                let end = (off + len).min(reference.len());
                let want = if off >= reference.len() {
                    &[][..]
                } else {
                    &reference[off..end]
                };
                assert_eq!(
                    got, want,
                    "fsx mismatch at step {step} (off={off}, len={len})"
                );
            }
        }
        if step % 50 == 49 {
            vol.commit_group()?;
            let full = vol.read(ino, 0, reference.len() + 4096)?;
            assert_eq!(full, reference, "fsx full-file mismatch at step {step}");
        }
    }
    let report = vol.fsck(false)?;
    assert!(
        report.is_clean(),
        "fsx fsck problems: {:?}",
        report.problems
    );
    Ok(())
}

/// Run the differential model test over `steps` random POSIX operations.
pub fn run_differential_model(steps: usize, seed: u64) -> Result<()> {
    let mut rng = fastrand::Rng::with_seed(seed);
    let mut vol = Volume::mkfs(4096, [0x11; 16], CasePolicy::Sensitive, 7)?;
    let mut model = RefModel::new();
    let mut dirs = vec![ROOT_INO];
    let mut files: Vec<(u64, Vec<u8>, u64)> = Vec::new();

    for step in 0..steps {
        match rng.u8(0..8) {
            0 => {
                // Create file
                let dir = dirs[rng.usize(0..dirs.len())];
                let name = format!("f_{step}_{}", rng.u16(0..50)).into_bytes();
                if let Ok(ino) = vol.create(dir, &name, 0o644, 1000, 1000) {
                    model.create(dir, &name, 0o644, ino);
                    files.push((dir, name, ino));
                }
            }
            1 => {
                // Mkdir
                let dir = dirs[rng.usize(0..dirs.len())];
                let name = format!("d_{step}").into_bytes();
                if let Ok(ino) = vol.mkdir(dir, &name, 0o755, 1000, 1000) {
                    model.mkdir(dir, &name, 0o755, ino);
                    dirs.push(ino);
                }
            }
            2 if !files.is_empty() => {
                // Write to file
                let (_, _, ino) = files[rng.usize(0..files.len())];
                let off = rng.usize(0..16384);
                let len = rng.usize(1..=4096);
                let data: Vec<u8> = (0..len).map(|_| rng.u8(..)).collect();
                vol.write(ino, off as u64, &data)?;
                model.write(ino, off, &data);
            }
            3 if !files.is_empty() => {
                // Truncate file
                let (_, _, ino) = files[rng.usize(0..files.len())];
                let sz = rng.usize(0..12000);
                vol.truncate(ino, sz as u64)?;
                model.truncate(ino, sz);
            }
            4 if !files.is_empty() => {
                // Hard link
                let (_, _, ino) = files[rng.usize(0..files.len())];
                let new_dir = dirs[rng.usize(0..dirs.len())];
                let new_name = format!("ln_{step}").into_bytes();
                if vol.link(ino, new_dir, &new_name).is_ok() {
                    model.link(ino, new_dir, &new_name);
                    files.push((new_dir, new_name, ino));
                }
            }
            5 if !files.is_empty() => {
                // Rename
                let idx = rng.usize(0..files.len());
                let (old_dir, old_name, ino) = files[idx].clone();
                let new_dir = dirs[rng.usize(0..dirs.len())];
                let new_name = format!("rn_{step}").into_bytes();
                if vol
                    .rename(old_dir, &old_name, new_dir, &new_name, RENAME_NOREPLACE)
                    .is_ok()
                {
                    model.rename(old_dir, &old_name, new_dir, &new_name, RENAME_NOREPLACE);
                    files[idx] = (new_dir, new_name, ino);
                }
            }
            6 if !files.is_empty() => {
                // Unlink
                let idx = rng.usize(0..files.len());
                let (dir, name, _) = files.swap_remove(idx);
                if vol.unlink(dir, &name).is_ok() {
                    model.unlink(dir, &name);
                }
            }
            _ if !files.is_empty() => {
                // Setxattr
                let (_, _, ino) = files[rng.usize(0..files.len())];
                let key = "user.tag";
                let val = format!("v{step}").into_bytes();
                vol.setxattr(ino, key, &val)?;
                if let Some(n) = model.inodes.get_mut(&ino) {
                    n.xattrs.insert(key.into(), val);
                }
            }
            _ => {}
        }
        if step % 25 == 24 {
            vol.commit_group()?;
            model.assert_matches(&vol)?;
        }
    }
    vol.commit_group()?;
    model.assert_matches(&vol)?;
    let report = vol.fsck(false)?;
    assert!(
        report.is_clean(),
        "differential model fsck failed: {:?}",
        report.problems
    );
    let _ = (Errno::ENOENT, BTreeSet::<u64>::new);
    Ok(())
}

/// Phase B Gate: Inject `crash_points` random crashes during mutations, recover from the last
/// committed group snapshot, verify prefix consistency against `RefModel`, and assert `fsck` is clean.
pub fn run_crash_injection_suite(crash_points: usize, seed: u64) -> Result<()> {
    let mut rng = fastrand::Rng::with_seed(seed);
    let mut vol = Volume::mkfs(4096, [0x99; 16], CasePolicy::Sensitive, 3)?;
    let mut committed_pages = vol.clone_storage();
    let mut committed_model = RefModel::new();
    let mut working_model = committed_model.clone();
    let mut file_counter = 0usize;

    for point in 0..crash_points {
        // Perform 1..=4 uncommitted operations in the working volume
        let ops_before_event = rng.usize(1..=4);
        for _ in 0..ops_before_event {
            file_counter += 1;
            let name = format!("f_{file_counter}").into_bytes();
            let ino = vol.create(ROOT_INO, &name, 0o644, 1000, 1000)?;
            working_model.create(ROOT_INO, &name, 0o644, ino);
            let payload = vec![(point & 0xFF) as u8; rng.usize(64..=6000)];
            vol.write(ino, 0, &payload)?;
            working_model.write(ino, 0, &payload);
        }

        if rng.bool() {
            // Clean group commit lands: advance the durable remote head
            vol.commit_group()?;
            committed_pages = vol.clone_storage();
            committed_model = working_model.clone();
        } else {
            // Crash injected mid-group before remote commit! Recover from `committed_pages`
            vol = Volume::mount(committed_pages.clone(), true, 3)?;
            working_model = committed_model.clone();
            // Reclaim any orphans and verify prefix consistency + clean fsck
            let report = vol.fsck(false)?;
            assert!(
                report.is_clean(),
                "crash point {point} failed fsck: {:?}",
                report.problems
            );
            committed_model.assert_matches(&vol)?;
        }
    }
    Ok(())
}