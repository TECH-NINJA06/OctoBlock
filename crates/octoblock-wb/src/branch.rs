//! Section 7.4 Follower close-to-open coherence and Section 9 Zero-copy branches,
//! named snapshots (`refs/tags/octoblock/<name>`), and time-travel resolution (`--as-of`).

use std::collections::BTreeMap;

use octoblock_fs::{Errno, Error, Result};
use octopage_git::{Commit, ObjectId, ObjectKind, RefUpdate, Transport};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Metadata describing a branch or named snapshot ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefInfo {
    /// Short name (e.g., `"main"` or `"v1.0"`).
    pub name: String,
    /// Full Git reference (e.g., `"refs/heads/main"` or `"refs/tags/octoblock/v1.0"`).
    pub full_ref: String,
    /// Target commit SHA.
    pub commit_id: ObjectId,
}

// Manual Serialize/Deserialize implementation for RefInfo to handle ObjectId hex encoding
impl Serialize for RefInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct RefInfoHelper<'a> {
            name: &'a str,
            full_ref: &'a str,
            commit_id: String,
        }
        let helper = RefInfoHelper {
            name: &self.name,
            full_ref: &self.full_ref,
            commit_id: self.commit_id.to_hex(),
        };
        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RefInfo {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Handled via helper struct
        let helper = RefInfoHelperHex::deserialize(deserializer)?;
        let commit_id = ObjectId::from_hex(&helper.commit_id)
            .map_err(serde::de::Error::custom)?;
        Ok(RefInfo {
            name: helper.name,
            full_ref: helper.full_ref,
            commit_id,
        })
    }
}

#[derive(Deserialize)]
struct RefInfoHelperHex {
    name: String,
    full_ref: String,
    commit_id: String,
}

pub const SNAPSHOT_TAG_PREFIX: &str = "refs/tags/octoblock/";
pub const BRANCH_REF_PREFIX: &str = "refs/heads/";
///
pub const fn encode_snapshot_ino(slot: u16, local_ino: u64) -> u64 {
    ((slot as u64) << 48) | (local_ino & 0x0000_FFFF_FFFF_FFFF)
}

/// Decode a 64-bit inode number into `(snapshot_slot, local_ino)`
pub const fn decode_snapshot_ino(ino: u64) -> (u16, u64) {
    let slot = (ino >> 48) as u16;
    let local = ino & 0x0000_FFFF_FFFF_FFFF;
    (slot, local)
}

/// Tracks open file handles and their pinned commit SHAs for close-to-open follower coherence
#[derive(Clone, Debug, Default)]
pub struct OpenFileTable {
    next_fh: u64,
    /// Maps `fh -> (normalized_path, pinned_commit_id)`.
    handles: BTreeMap<u64, (String, ObjectId)>,
}

impl OpenFileTable {
    /// Allocate a new file handle pinned to `commit_id` at `open()` time.
    pub fn open_handle(&mut self, path: impl Into<String>, commit_id: ObjectId) -> u64 {
        self.next_fh += 1;
        let fh = self.next_fh;
        self.handles.insert(fh, (path.into(), commit_id));
        fh
    }

    /// Look up the `(path, pinned_commit_id)` for an open file handle.
    pub fn get(&self, fh: u64) -> Option<&(String, ObjectId)> {
        self.handles.get(&fh)
    }

    /// Release a file handle on `close()`.
    pub fn close_handle(&mut self, fh: u64) -> Option<(String, ObjectId)> {
        self.handles.remove(&fh)
    }

    /// Return all commit SHAs currently pinned by at least one open file handle.
    pub fn pinned_commits(&self) -> Vec<ObjectId> {
        let mut out: Vec<ObjectId> = self.handles.values().map(|(_, cid)| *cid).collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// Create a zero-copy branch `refs/heads/<branch_name>` pointing at `from_commit` in one round trip
pub async fn create_branch<T: Transport>(
    transport: &T,
    branch_name: &str,
    from_commit: ObjectId,
) -> Result<RefInfo> {
    let short = branch_name
        .strip_prefix(BRANCH_REF_PREFIX)
        .unwrap_or(branch_name);
    let full_ref = format!("{BRANCH_REF_PREFIX}{short}");
    transport
        .push(&[RefUpdate::create(&full_ref, from_commit)], &[])
        .await
        .map_err(|e| Error::new(Errno::EEXIST, format!("create branch {full_ref}: {e}")))?;
    Ok(RefInfo {
        name: short.to_string(),
        full_ref,
        commit_id: from_commit,
    })
}

/// List all branches (`refs/heads/*`) on the remote repository.
pub async fn list_branches<T: Transport>(transport: &T) -> Result<Vec<RefInfo>> {
    let refs = transport
        .list_refs(&[BRANCH_REF_PREFIX])
        .await
        .map_err(|e| Error::new(Errno::EIO, format!("list_branches: {e}")))?;
    Ok(refs
        .into_iter()
        .filter_map(|r| {
            let short = r.name.strip_prefix(BRANCH_REF_PREFIX)?.to_string();
            Some(RefInfo {
                name: short,
                full_ref: r.name,
                commit_id: r.id,
            })
        })
        .collect())
}

/// Create a named immutable snapshot `refs/tags/octoblock/<snapshot_name>` at `commit_id`
pub async fn create_snapshot<T: Transport>(
    transport: &T,
    snapshot_name: &str,
    commit_id: ObjectId,
) -> Result<RefInfo> {
    let short = snapshot_name
        .strip_prefix(SNAPSHOT_TAG_PREFIX)
        .unwrap_or(snapshot_name);
    let full_ref = format!("{SNAPSHOT_TAG_PREFIX}{short}");
    transport
        .push(&[RefUpdate::create(&full_ref, commit_id)], &[])
        .await
        .map_err(|e| Error::new(Errno::EEXIST, format!("create snapshot {full_ref}: {e}")))?;
    Ok(RefInfo {
        name: short.to_string(),
        full_ref,
        commit_id,
    })
}

/// List all named snapshots (`refs/tags/octoblock/*`) on the remote repository.
pub async fn list_snapshots<T: Transport>(transport: &T) -> Result<Vec<RefInfo>> {
    let refs = transport
        .list_refs(&[SNAPSHOT_TAG_PREFIX])
        .await
        .map_err(|e| Error::new(Errno::EIO, format!("list_snapshots: {e}")))?;
    Ok(refs
        .into_iter()
        .filter_map(|r| {
            let short = r.name.strip_prefix(SNAPSHOT_TAG_PREFIX)?.to_string();
            Some(RefInfo {
                name: short,
                full_ref: r.name,
                commit_id: r.id,
            })
        })
        .collect())
}

/// Selector for time-travel mounts
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsOfSelector {
    /// Exact commit SHA.
    Commit(ObjectId),
    /// Named snapshot tag under `refs/tags/octoblock/<name>`.
    SnapshotTag(String),
    /// Latest commit on `branch` whose committer timestamp is `<= unix_seconds`.
    Timestamp(i64),
}

/// Resolve an [`AsOfSelector`] to a concrete `ObjectId` commit on `transport`
pub async fn resolve_as_of<T: Transport>(
    transport: &T,
    branch_ref: &str,
    selector: &AsOfSelector,
) -> Result<ObjectId> {
    match selector {
        AsOfSelector::Commit(id) => Ok(*id),
        AsOfSelector::SnapshotTag(tag) => {
            let full = if tag.starts_with(SNAPSHOT_TAG_PREFIX) {
                tag.clone()
            } else {
                format!("{SNAPSHOT_TAG_PREFIX}{tag}")
            };
            let refs = transport
                .list_refs(&[&full])
                .await
                .map_err(|e| Error::new(Errno::EIO, format!("list_refs({full}): {e}")))?;
            refs.into_iter()
                .find(|r| r.name == full)
                .map(|r| r.id)
                .ok_or_else(|| Error::new(Errno::ENOENT, format!("snapshot {tag:?} not found")))
        }
        AsOfSelector::Timestamp(max_ts) => {
            let refs = transport
                .list_refs(&[branch_ref])
                .await
                .map_err(|e| Error::new(Errno::EIO, format!("list_refs({branch_ref}): {e}")))?;
            let tip = refs
                .into_iter()
                .find(|r| r.name == branch_ref)
                .map(|r| r.id)
                .ok_or_else(|| Error::new(Errno::ENOENT, "branch not found"))?;

            let mut curr = Some(tip);
            let mut best: Option<(i64, ObjectId)> = None;
            while let Some(cid) = curr {
                let objs = transport
                    .fetch(&[cid])
                    .await
                    .map_err(|e| Error::new(Errno::EIO, format!("fetch commit {cid}: {e}")))?;
                let Some(obj) = objs.into_iter().find(|o| o.id() == cid) else {
                    break;
                };
                if obj.kind() != ObjectKind::Commit {
                    break;
                }
                let commit = Commit::decode(obj.data())
                    .map_err(|e| Error::new(Errno::EIO, format!("decode commit: {e}")))?;
                let ts = commit.committer.seconds;
                if ts <= *max_ts && best.is_none_or(|(best_ts, _)| ts > best_ts) {
                    best = Some((ts, cid));
                }
                curr = commit.parents.first().copied();
            }
            best.map(|(_, id)| id).ok_or_else(|| {
                Error::new(
                    Errno::ENOENT,
                    format!("no commit found at or before timestamp {max_ts}"),
                )
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_inode_namespacing_round_trips() {
        let live_ino = 65_537u64;
        assert_eq!(decode_snapshot_ino(live_ino), (0, live_ino));
        let snap_ino = encode_snapshot_ino(7, live_ino);
        assert_ne!(snap_ino, live_ino);
        assert_eq!(decode_snapshot_ino(snap_ino), (7, live_ino));
    }
}