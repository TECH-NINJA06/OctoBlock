use std::collections::{BTreeMap, BTreeSet};

use octoblock_fs::oplog::{OpKind, OpRecord};
use serde::{Deserialize, Serialize};

pub const MAX_CONSECUTIVE_RACES: u32 = 8;

/// Reason a replayed operation could not be applied cleanly onto the new remote head
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictReason {
    CreateCollision,
    ConcurrentModify,
    ModifyDeleted,
    DeleteModified,
    RenameCollision,
}

/// Machine-readable conflict record stored in `/.octoblock/conflicts/<batch>/index.json`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub batch_id: String,
    pub seq: u64,
    pub base_commit: String,
    pub remote_commit: String,
    pub path: String,
    pub preserved_copy: Option<String>,
    pub reason: ConflictReason,
}

/// Summary of all conflict batches recorded on the volume (`/.octoblock/conflicts/index.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictLog {
    pub records: Vec<ConflictRecord>,
}

impl ConflictLog {
    /// Record a new conflict entry (`REQ-4`).
    pub fn push(&mut self, record: ConflictRecord) {
        self.records.push(record);
    }

    /// Number of unresolved conflict records.
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether there are no recorded conflicts.
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Serialize the conflict log as pretty JSON for `/.octoblock/conflicts/index.json`.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }
}

/// Summary of remote mutations extracted from commits between `base_head` and `remote_head`.
#[derive(Clone, Debug, Default)]
pub struct RemoteDiffSummary {
    pub created_names: BTreeSet<(u64, String)>,
    pub unlinked_names: BTreeSet<(u64, String)>,
    pub modified_inodes: BTreeSet<u64>,
    pub name_to_ino: BTreeMap<(u64, String), u64>,
}

impl RemoteDiffSummary {
    /// Parse a newline-delimited `changelog` blob and accumulate its mutated paths and inodes.
    pub fn absorb_changelog(&mut self, changelog_bytes: &[u8]) {
        let text = String::from_utf8_lossy(changelog_bytes);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(op) = OpRecord::parse_json_line(trimmed) else {
                continue;
            };
            self.absorb_op(&op);
        }
    }

    /// Accumulate a single remote [`OpRecord`] into the diff summary.
    pub fn absorb_op(&mut self, op: &OpRecord) {
        match &op.kind {
            OpKind::Create {
                parent, name, ino, ..
            } => {
                self.created_names.insert((*parent, name.clone()));
                self.name_to_ino.insert((*parent, name.clone()), *ino);
            }
            OpKind::Link {
                ino, parent, name, ..
            } => {
                self.created_names.insert((*parent, name.clone()));
                self.modified_inodes.insert(*ino);
            }
            OpKind::Unlink {
                parent, name, ino, ..
            } => {
                self.unlinked_names.insert((*parent, name.clone()));
                self.modified_inodes.insert(*ino);
            }
            OpKind::Rename { old, new, .. } => {
                self.unlinked_names.insert((old.0, old.1.clone()));
                self.created_names.insert((new.0, new.1.clone()));
            }
            OpKind::Write { ino, .. }
            | OpKind::Truncate { ino, .. }
            | OpKind::Setattr { ino, .. }
            | OpKind::Xattr { ino, .. } => {
                self.modified_inodes.insert(*ino);
            }
            OpKind::Barrier { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_diff_parses_changelog_mutations() {
        let changelog = br#"{"seq":1,"t":1.0,"uid":1000,"gid":1000,"op":"create","parent":1,"name":"app.conf","mode":33188,"ino_range":[65536,131071],"ino":65536}
{"seq":2,"t":1.1,"uid":1000,"gid":1000,"op":"write","ino":65536,"off":0,"len":12,"pages":{"file_page":0,"count":1},"size":12}
"#;
        let mut diff = RemoteDiffSummary::default();
        diff.absorb_changelog(changelog);
        assert!(diff.created_names.contains(&(1, "app.conf".to_string())));
        assert!(diff.modified_inodes.contains(&65536));
    }
}