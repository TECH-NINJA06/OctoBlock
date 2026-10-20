use octoblock_fs::{Errno, Error, Result};
use octopage_git::{Commit, ObjectId, ObjectKind, RefUpdate, Transport};
use serde::{Deserialize, Serialize};

pub const GENERATION_TAG_PREFIX: &str = "refs/tags/octoblock/gen-";

/// Result of running a history compaction / generation squash 
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionReport {
    pub generation: u64,
    pub archived_ref: Option<String>,
    pub old_head: String,
    pub new_head: String,
    pub epoch: u64,
    pub live_bytes: u64,
}

/// Archive `old_head` under `refs/tags/octoblock/gen-<generation>` before squashing history
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
    for line in text.lines() {
        if let Some(prev) = line.trim().strip_prefix("Compacted-From:")
            && let Ok(prev_id) = ObjectId::from_hex(prev.trim())
        {
            if prev_id == ancestor {
                return Ok(true);
            }
            let hist = transport
                .history(prev_id, Some(ancestor), false)
                .await
                .map_err(|e| Error::new(Errno::EIO, format!("history: {e}")))?;
            for h_obj in hist {
                if h_obj.kind() == ObjectKind::Commit
                    && let Ok(c) = Commit::decode(h_obj.data())
                    && c.parents.contains(&ancestor)
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}