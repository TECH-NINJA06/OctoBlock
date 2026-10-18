//! Section 6.3 & 6.8 Operation coalescing, write elision, and atomic regions (`REQ-3`).

use std::collections::{BTreeMap, BTreeSet};

use octoblock_fs::oplog::{OpKind, OpRecord};
use octoblock_fs::{Errno, Error, Result};

/// Maximum size of an un-splittable atomic region: 128 MiB (Section 6.8, Appendix B, EC-Z08).
pub const ATOMIC_MAX_BYTES: u64 = 128 * 1024 * 1024;
/// Maximum size of a normal commit group before splitting: 64 MiB (Section 6.2, Appendix B, EC-Z08).
pub const MAX_GROUP_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum ops in a normal commit group before splitting: 50,000 (Section 6.2, Appendix B, EC-Z08).
pub const MAX_GROUP_OPS: usize = 50_000;

/// Tracks an active `octoblock atomic` region (Section 6.8, REQ-3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AtomicRegion {
    /// Whether an atomic region is currently open.
    pub active: bool,
    /// Bytes accumulated inside the current atomic region.
    pub bytes: u64,
}

impl AtomicRegion {
    /// Begin an atomic region (`OBX_ATOMIC_BEGIN`).
    pub fn begin(&mut self) -> Result<()> {
        if self.active {
            return Err(Error::new(Errno::EINVAL, "atomic region already active"));
        }
        self.active = true;
        self.bytes = 0;
        Ok(())
    }

    /// Record `n` dirty bytes inside the atomic region, failing with `EFBIG` above 128 MiB (Section 6.8).
    pub fn record_bytes(&mut self, n: u64) -> Result<()> {
        if self.active {
            self.bytes = self.bytes.saturating_add(n);
            if self.bytes > ATOMIC_MAX_BYTES {
                self.active = false;
                self.bytes = 0;
                return Err(Error::new(
                    Errno::EFBIG,
                    "atomic region exceeded 128 MiB limit (Section 6.8)",
                ));
            }
        }
        Ok(())
    }

    /// Close an atomic region (`OBX_ATOMIC_END`).
    pub fn end(&mut self) -> Result<()> {
        if !self.active {
            return Err(Error::new(Errno::EINVAL, "no active atomic region"));
        }
        self.active = false;
        self.bytes = 0;
        Ok(())
    }
}

/// Apply Section 6.3 coalescing and write elision to a window of [`OpRecord`]s.
///
/// Elision and coalescing never cross a `barrier` op (`REQ-3` / Section 6.3).
pub fn coalesce_and_elide(ops: &[OpRecord]) -> Vec<OpRecord> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, op) in ops.iter().enumerate() {
        if matches!(op.kind, OpKind::Barrier { .. }) {
            out.extend(coalesce_window(&ops[start..i]));
            out.push(op.clone());
            start = i + 1;
        }
    }
    if start < ops.len() {
        out.extend(coalesce_window(&ops[start..]));
    }
    out
}

fn coalesce_window(window: &[OpRecord]) -> Vec<OpRecord> {
    // 1. Identify files created and unlinked inside the same barrier-free window (Write Elision, Section 6.3).
    let mut created_in_group: BTreeMap<(u64, String), u64> = BTreeMap::new();
    let mut link_counts: BTreeMap<u64, u32> = BTreeMap::new();
    let mut elided_inodes: BTreeSet<u64> = BTreeSet::new();

    for op in window {
        match &op.kind {
            OpKind::Create {
                op_name,
                parent,
                name,
                ino,
                ..
            } if op_name == "create" => {
                created_in_group.insert((*parent, name.clone()), *ino);
                link_counts.insert(*ino, 1);
            }
            OpKind::Link {
                ino,
                parent,
                name,
            } => {
                if let Some(c) = link_counts.get_mut(ino) {
                    *c += 1;
                    created_in_group.insert((*parent, name.clone()), *ino);
                }
            }
            OpKind::Rename { old, new, flags } if *flags == 0 => {
                if let Some(ino) = created_in_group.remove(&(old.0, old.1.clone())) {
                    created_in_group.insert((new.0, new.1.clone()), ino);
                }
            }
            OpKind::Unlink {
                op_name,
                parent,
                name,
                ino,
            } if op_name == "unlink" => {
                if let Some(created_ino) = created_in_group.remove(&(*parent, name.clone()))
                    && created_ino == *ino
                    && let Some(c) = link_counts.get_mut(&created_ino)
                {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        elided_inodes.insert(created_ino);
                    }
                }
            }
            _ => {}
        }
    }

    // 2. Filter out all ops belonging to elided temporary inodes, drop zero-length writes,
    // and coalesce identical page-range overwrites.
    let mut filtered: Vec<OpRecord> = Vec::with_capacity(window.len());
    for op in window {
        match &op.kind {
            OpKind::Create { ino, .. }
            | OpKind::Link { ino, .. }
            | OpKind::Unlink { ino, .. }
            | OpKind::Write { ino, .. }
            | OpKind::Truncate { ino, .. }
            | OpKind::Setattr { ino, .. }
            | OpKind::Xattr { ino, .. }
                if elided_inodes.contains(ino) =>
            {
                continue;
            }
            OpKind::Write { len: 0, .. } => {
                // Section 6.3: zero-length writes are dropped.
                continue;
            }
            OpKind::Write {
                ino,
                off,
                len,
                size,
                ..
            } => {
                // Overwrite coalescing: if a prior write in the same window wrote the exact same
                // (ino, off, len), replace it with the newer state.
                if let Some(prev) = filtered.iter_mut().rev().find(| prev_op | {
                    matches!(
                        &prev_op.kind,
                        OpKind::Write {
                            ino: p_ino,
                            off: p_off,
                            len: p_len,
                            ..
                        } if p_ino == ino && p_off == off && p_len == len
                    )
                }) {
                    prev.t = op.t;
                    if let OpKind::Write { size: p_size, .. } = &mut prev.kind {
                        *p_size = *size;
                    }
                    continue;
                }
                filtered.push(op.clone());
            }
            _ => filtered.push(op.clone()),
        }
    }
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;
    use octoblock_fs::oplog::PageRunRef;

    #[test]
    fn temp_file_create_write_unlink_is_completely_elided() {
        let ops = vec![
            OpRecord {
                seq: 1,
                t: 1.0,
                uid: 1000,
                gid: 1000,
                kind: OpKind::Create {
                    op_name: "create".into(),
                    parent: 1,
                    name: ".swp".into(),
                    mode: 0o100644,
                    ino_range: [65536, 131071],
                    ino: 65537,
                    target: None,
                },
            },
            OpRecord {
                seq: 2,
                t: 1.1,
                uid: 1000,
                gid: 1000,
                kind: OpKind::Write {
                    ino: 65537,
                    off: 0,
                    len: 4096,
                    pages: PageRunRef {
                        file_page: 0,
                        count: 1,
                    },
                    size: 4096,
                },
            },
            OpRecord {
                seq: 3,
                t: 1.2,
                uid: 1000,
                gid: 1000,
                kind: OpKind::Unlink {
                    op_name: "unlink".into(),
                    parent: 1,
                    name: ".swp".into(),
                    ino: 65537,
                },
            },
        ];
        let coalesced = coalesce_and_elide(&ops);
        assert!(
            coalesced.is_empty(),
            "temp file created and deleted inside one group must be elided"
        );
    }
}