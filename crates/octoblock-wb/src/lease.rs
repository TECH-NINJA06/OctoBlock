//! Section 7.1 & 7.2 Writer lease (`refs/octopage/lease`), mount roles, fencing (`EC-C04`),
//! and forced lease break (`octoblock lease break`).

use std::time::{SystemTime, UNIX_EPOCH};

use octoblock_fs::{Errno, Error, Result};
use octopage_git::{Commit, ObjectId, ObjectKind, RefUpdate, Signature, Transport, Tree};
use serde::{Deserialize, Serialize};

/// Git reference used for the volume writer lease (Section 7.1, 7.2).
pub const LEASE_REF: &str = "refs/octopage/lease";
/// Default writer lease expiry in milliseconds: 60 seconds (Section 7.2, Appendix B).
pub const DEFAULT_LEASE_EXPIRY_MS: i64 = 60_000;
/// Default writer lease renewal interval in milliseconds: 20 seconds (Section 7.2, Appendix B).
pub const DEFAULT_LEASE_RENEW_MS: i64 = 20_000;

/// Mount concurrency role (Section 7.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountRole {
    /// Holds the writer lease and is allowed to push commits.
    #[default]
    Writer,
    /// Read-only mount (`EROFS` on writes) that follows remote head movements.
    Follower,
    /// Opt-in multi-writer mode (`--lease advisory`) using logical replay on race loss.
    MultiWriter,
}

/// Writer lease enforcement policy (Section 7.2, Appendix B).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeasePolicy {
    /// The mount refuses to push without holding a live lease on `refs/octopage/lease` (default).
    #[default]
    Required,
    /// Pushes proceed without the lease; head compare-and-swap + replay protects consistency.
    Advisory,
    /// Single-user personal volume where the user guarantees exclusivity.
    Off,
}

/// On-remote lease payload stored in the commit message of `refs/octopage/lease` (Section 7.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    /// Human-readable holder identity (e.g., hostname or user).
    pub holder: String,
    /// Unique identifier for the mounted daemon instance.
    pub mount_uuid: String,
    /// Lease expiration timestamp in milliseconds since the Unix epoch.
    pub expires_ms: i64,
    /// Commit SHA of the lease ref on the remote (`None` when synthesized locally).
    #[serde(skip)]
    pub commit_id: Option<ObjectId>,
}

impl LeaseRecord {
    /// Whether this lease is still live at `now_ms`.
    pub const fn is_live_at(&self, now_ms: i64) -> bool {
        self.expires_ms > now_ms
    }

    /// Whether this lease belongs to `mount_uuid`.
    pub fn is_held_by(&self, mount_uuid: &str) -> bool {
        self.mount_uuid == mount_uuid
    }
}

/// Outcome of a lease acquisition or renewal attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseOutcome {
    /// This mount holds a live lease.
    Acquired(LeaseRecord),
    /// Another mount holds a live lease (`EC-C03`).
    HeldByOther(LeaseRecord),
    /// This mount previously held the lease, but lost it or expired (`FENCED`, `EC-C04`).
    Fenced(Option<LeaseRecord>),
}

/// Current wall-clock time in milliseconds since the Unix epoch.
pub fn unix_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Manages writer lease acquisition, renewal, fencing, and takeover on `refs/octopage/lease`.
#[derive(Clone, Debug)]
pub struct LeaseManager {
    /// Holder name.
    pub holder: String,
    /// Unique daemon mount UUID.
    pub mount_uuid: String,
    /// Lease policy (`required`, `advisory`, `off`).
    pub policy: LeasePolicy,
    /// Lease TTL in milliseconds (default 60,000 ms).
    pub expiry_ms: i64,
    /// Renewal interval in milliseconds (default 20,000 ms).
    pub renew_ms: i64,
    /// Last known lease state observed or written by this client.
    known: Option<LeaseRecord>,
    /// Whether this mount has ever successfully held the writer lease.
    ever_held: bool,
    /// Optional clock override in milliseconds for deterministic unit testing (`EC-C04`).
    clock_override_ms: Option<i64>,
}

impl LeaseManager {
    /// Create a new lease manager for `holder` and `mount_uuid`.
    pub fn new(
        holder: impl Into<String>,
        mount_uuid: impl Into<String>,
        policy: LeasePolicy,
    ) -> Self {
        LeaseManager {
            holder: holder.into(),
            mount_uuid: mount_uuid.into(),
            policy,
            expiry_ms: DEFAULT_LEASE_EXPIRY_MS,
            renew_ms: DEFAULT_LEASE_RENEW_MS,
            known: None,
            ever_held: false,
            clock_override_ms: None,
        }
    }

    /// Current timestamp in milliseconds (uses test clock if set, otherwise wall clock).
    pub fn now_ms(&self) -> i64 {
        self.clock_override_ms.unwrap_or_else(unix_ms_now)
    }

    /// Set or advance a deterministic test clock in milliseconds (`EC-C04` testing).
    pub fn set_test_clock_ms(&mut self, ms: i64) {
        self.clock_override_ms = Some(ms);
    }

    /// Last known lease record cached by this mount.
    pub fn known_lease(&self) -> Option<&LeaseRecord> {
        self.known.as_ref()
    }

    /// Whether this mount currently holds an unexpired lease at `now_ms()`.
    pub fn holds_live_lease(&self) -> bool {
        let now = self.now_ms();
        self.known
            .as_ref()
            .is_some_and(|l| l.is_held_by(&self.mount_uuid) && l.is_live_at(now))
    }

    /// Read and decode `refs/octopage/lease` from `transport` (`octoblock lease show`).
    pub async fn fetch_remote_lease<T: Transport>(
        &mut self,
        transport: &T,
    ) -> Result<Option<LeaseRecord>> {
        let refs = transport
            .list_refs(&[LEASE_REF])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("list_refs({LEASE_REF}): {e}")))?;
        let Some(r) = refs.into_iter().find(|r| r.name == LEASE_REF) else {
            self.known = None;
            return Ok(None);
        };
        let objs = transport
            .fetch(&[r.id])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("fetch lease commit: {e}")))?;
        let Some(obj) = objs.into_iter().find(|o| o.id() == r.id) else {
            return Err(Error::new(Errno::EIO, "missing lease commit object"));
        };
        if obj.kind() != ObjectKind::Commit {
            return Err(Error::new(Errno::EIO, "lease ref does not point to a commit"));
        }
        let commit = Commit::decode(obj.data())
            .map_err(|e| Error::new(Errno::EIO, format!("decode lease commit: {e}")))?;
        let text = String::from_utf8_lossy(&commit.message);
        let json_slice = text
            .find('{')
            .map(|i| text[i..].trim())
            .ok_or_else(|| Error::new(Errno::EIO, "lease commit missing JSON payload"))?;
        let mut rec: LeaseRecord = serde_json::from_str(json_slice)
            .map_err(|e| Error::new(Errno::EIO, format!("parse lease JSON: {e}")))?;
        rec.commit_id = Some(r.id);
        self.known = Some(rec.clone());
        Ok(Some(rec))
    }

    /// Acquire an unheld/expired lease, or renew our own live lease via compare-and-swap on `refs/octopage/lease`.
    pub async fn acquire_or_renew<T: Transport>(&mut self, transport: &T) -> Result<LeaseOutcome> {
        let now = self.now_ms();
        let current = self.fetch_remote_lease(transport).await?;

        if let Some(ref existing) = current
            && !existing.is_held_by(&self.mount_uuid)
            && existing.is_live_at(now)
        {
            return Ok(if self.ever_held {
                LeaseOutcome::Fenced(Some(existing.clone()))
            } else {
                LeaseOutcome::HeldByOther(existing.clone())
            });
        }

        let new_rec = LeaseRecord {
            holder: self.holder.clone(),
            mount_uuid: self.mount_uuid.clone(),
            expires_ms: now + self.expiry_ms,
            commit_id: None,
        };
        let expected_old = current.as_ref().and_then(|c| c.commit_id);
        match self
            .push_lease_record(transport, expected_old, &new_rec, now)
            .await
        {
            Ok(commit_id) => {
                let mut stored = new_rec;
                stored.commit_id = Some(commit_id);
                self.known = Some(stored.clone());
                self.ever_held = true;
                Ok(LeaseOutcome::Acquired(stored))
            }
            Err(octopage_git::Error::Conflict { .. } | octopage_git::Error::Rejected(_)) => {
                // Lost the CAS race on `refs/octopage/lease`: read whoever won.
                let winner = self.fetch_remote_lease(transport).await?;
                Ok(if self.ever_held {
                    LeaseOutcome::Fenced(winner)
                } else if let Some(w) = winner {
                    LeaseOutcome::HeldByOther(w)
                } else {
                    LeaseOutcome::Fenced(None)
                })
            }
            Err(e) => {
                // Network failure during renewal: if our lease has now expired, we are FENCED!
                if self.ever_held && !self.holds_live_lease() {
                    return Ok(LeaseOutcome::Fenced(self.known.clone()));
                }
                Err(Error::new(Errno::EIO, format!("lease push failed: {e}")))
            }
        }
    }

    /// Force-break an existing writer lease held by another mount and take it over (`octoblock lease break`, Section 7.2).
    pub async fn break_lease<T: Transport>(&mut self, transport: &T) -> Result<LeaseRecord> {
        let now = self.now_ms();
        let current = self.fetch_remote_lease(transport).await?;
        let expected_old = current.and_then(|c| c.commit_id);
        let new_rec = LeaseRecord {
            holder: self.holder.clone(),
            mount_uuid: self.mount_uuid.clone(),
            expires_ms: now + self.expiry_ms,
            commit_id: None,
        };
        let commit_id = self
            .push_lease_record(transport, expected_old, &new_rec, now)
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("lease break failed: {e}")))?;
        let mut stored = new_rec;
        stored.commit_id = Some(commit_id);
        self.known = Some(stored.clone());
        self.ever_held = true;
        Ok(stored)
    }

    /// Release the writer lease cleanly on unmount if still held by this mount (Section 7.2).
    pub async fn release<T: Transport>(&mut self, transport: &T) -> Result<()> {
        let Some(current) = self.fetch_remote_lease(transport).await? else {
            self.known = None;
            return Ok(());
        };
        if !current.is_held_by(&self.mount_uuid) {
            return Ok(());
        }
        if let Some(old_id) = current.commit_id {
            let _ = transport
                .push(&[RefUpdate::delete(LEASE_REF, old_id)], &[])
                .await;
        }
        self.known = None;
        self.ever_held = false;
        Ok(())
    }

    async fn push_lease_record<T: Transport>(
        &self,
        transport: &T,
        expected_old: Option<ObjectId>,
        rec: &LeaseRecord,
        now_ms: i64,
    ) -> std::result::Result<ObjectId, octopage_git::Error> {
        let empty_tree = Tree::new().to_object()?;
        let json = serde_json::to_string(rec).expect("serializable LeaseRecord");
        let sig = Signature::new(&self.holder, "lease@octoblock.invalid", now_ms / 1000);
        let commit = Commit {
            tree: empty_tree.id(),
            parents: Vec::new(),
            author: sig.clone(),
            committer: sig,
            message: format!("octoblock lease\n\n{json}\n").into_bytes(),
        }
        .to_object()?;
        let commit_id = commit.id();
        let objects = [empty_tree.into(), commit.into()];

        for _attempt in 0..4 {
            let update = match expected_old {
                Some(old) => RefUpdate::update(LEASE_REF, old, commit_id),
                None => RefUpdate::create(LEASE_REF, commit_id),
            };
            match transport.push(std::slice::from_ref(&update), &objects).await {
                Ok(()) => return Ok(commit_id),
                Err(octopage_git::Error::PushOutcomeUnknown(_)) => {
                    let refs = transport.list_refs(&[LEASE_REF]).await?;
                    if refs.iter().any(|r| r.name == LEASE_REF && r.id == commit_id) {
                        return Ok(commit_id);
                    }
                    // If connection was dropped before apply, fall through to retry loop with fresh list_refs base.
                }
                Err(octopage_git::Error::Conflict { .. } | octopage_git::Error::Rejected(_)) => {
                    // Stale expected_old: refresh expected_old from current remote ref and retry.
                    if let Ok(refs) = transport.list_refs(&[LEASE_REF]).await
                        && let Some(r) = refs.into_iter().find(|r| r.name == LEASE_REF)
                    {
                        let retry_update = RefUpdate::update(LEASE_REF, r.id, commit_id);
                        if transport.push(std::slice::from_ref(&retry_update), &objects).await.is_ok() {
                            return Ok(commit_id);
                        }
                    }
                    return Err(octopage_git::Error::Conflict {
                        refname: LEASE_REF.into(),
                        reason: "lease cas conflict".into(),
                    });
                }
                Err(e) => return Err(e),
            }
        }
        Err(octopage_git::Error::PushOutcomeUnknown(
            "lease push did not land after retries".into(),
        ))
    }
}