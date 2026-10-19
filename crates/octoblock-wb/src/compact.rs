//! Section 8 Repository budget accounting, quota enforcement (`DegradedQuota`), and
//! history compaction / generation rollover (`refs/tags/octoblock/gen-<N>`, `REQ-6`).

use octoblock_fs::{Errno, Error, Result};
use octopage_git::{Commit, ObjectId, ObjectKind, RefUpdate, Transport};
use serde::{Deserialize, Serialize};

/// Prefix for archived generation tags created before history compaction (Section 8.2).
pub const GENERATION_TAG_PREFIX: &str = "refs/tags/octoblock/gen-";

/// Result of running a history compaction / generation squash (`octoblock compact`, Section 8.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionReport {
    /// Generation number assigned to the archived history (`1`, `2`, ...).
    pub generation: u64,
    /// Optional tag ref where the pre-compaction commit chain was archived.
    pub archived_ref: Option<String>,
    /// Previous branch head commit SHA (hex) before compaction.
    pub old_head: String,
    /// New squashed root commit SHA (hex) after compaction.
    pub new_head: String,
    /// Volume epoch preserved in the squashed root commit (`REQ-5`).
    pub epoch: u64,
    /// Live bytes in the compacted volume.
    pub live_bytes: u64,
}

/// Archive `old_head` under `refs/tags/octoblock/gen-<generation>` before squashing history (Section 8.2).
pub async fn archive_generation_tag<T: Transport>(
    transport: &T,
    generation: u64,
    old_head: ObjectId,
) -> Result<String> {
    let tag_ref = format!("{GENERATION_TAG_PREFIX}{generation}");
    transport
        .push(&[RefUpdate::create(&tag_ref, old_head)], &[])
        .await
        .map_err(|e| Error::new(Errno::EIO, format!("archive generation tag {tag_ref}: {e}")))?;
    Ok(tag_ref)
}

/// Check whether `commit_id` carries a `Compacted-From: <ancestor_hex>` trailer linking it to
/// the pre-compaction commit history so legitimate compactions do not trigger false `Diverged` alarms.
pub async fn is_compacted_continuation<T: Transport>(
    transport: &T,
    tip: ObjectId,
    ancestor: ObjectId,
) -> Result<bool> {
    let objs = transport
        .fetch(&[tip])
        .await
        .map_err(|e| Error::new(Errno::EIO, format!("fetch tip for compaction check: {e}")))?;
    let Some(obj) = objs.into_iter().find(|o| o.id() == tip) else {
        return Ok(false);
    };
    if obj.kind() != ObjectKind::Commit {
        return Ok(false);
    }
    let commit = Commit::decode(obj.data())
        .map_err(|e| Error::new(Errno::EIO, format!("decode commit: {e}")))?;
    let text = String::from_utf8_lossy(&commit.message);
    let target_hex = ancestor.to_hex();
    for line in text.lines() {
        if let Some(prev) = line.trim().strip_prefix("Compacted-From:")
            && prev.trim() == target_hex
        {
            return Ok(true);
        }
    }
    Ok(false)
}