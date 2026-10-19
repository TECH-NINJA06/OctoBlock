//! OctoBlock Layer 4 Write-Back Engine & User-Space Daemon Core (`octoblock-wb`).
//!
//! Connects `octoblock-fs::Volume` (`OBF1`) with the local encrypted write-ahead journal
//! (`L1`), path-class routing (`persist`, `local`, `volatile`, `exclude`), op coalescing/elision,
//! writer leases and fencing (`refs/octopage/lease`), `.octoblock/status` observability, and
//! `octopage-git::Transport` remote group commits (`L2`).

pub mod branch;
pub mod coalesce;
pub mod conflict;
pub mod journal;
pub mod lease;
pub mod policy;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use octoblock_fs::oplog::{OpKind, OpRecord, PageRunRef, encode_changelog};
use octoblock_fs::page::{CasePolicy, PageId, PathClass};
use octoblock_fs::tree::InodeRecord;
use octoblock_fs::{DirEntry, Errno, Error, ROOT_INO, Result, S_IFDIR, S_IFLNK, S_IFREG, Volume};
use octopage_git::{
    Commit, EntryMode, NewObject, Object, ObjectId, ObjectKind, RefUpdate, Signature, Transport,
    Tree, TreeEntry,
};
use serde::{Deserialize, Serialize};

use crate::coalesce::{AtomicRegion, coalesce_and_elide};
use crate::journal::{
    DEFAULT_JOURNAL_CAPACITY, JournalEntry, JournalRecordType, LocalJournal, OnJournalFull,
};
use crate::lease::{LeaseManager, LeaseOutcome, LeasePolicy, LeaseRecord, MountRole};
use crate::policy::PolicyEngine;

/// Durability level reached by an operation (Section 1.5, Section 6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DurabilityLevel {
    /// In daemon memory and kernel page cache only.
    L0,
    /// Appended to the local journal and `fdatasync` barrier completed.
    L1,
    /// Committed in a packfile push acknowledged by the remote Git repository.
    L2,
}

/// Mount durability mode (Section 6.6, Appendix B).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MountMode {
    /// `fsync` forces a remote group commit and waits for the `L2` acknowledgement.
    Strict,
    /// `fsync` performs a local journal `fdatasync` barrier (`L1`, default).
    #[default]
    Balanced,
    /// `fsync` is a no-op (`L0`); background flushes run every 60 s.
    Relaxed,
}

/// High-level state of a mount reported in `.octoblock/status` (Section 11.2, REQ-13).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MountState {
    /// Remote reachable, lease held, journal near empty.
    #[default]
    Online,
    /// Journal depth above zero, pushing.
    Syncing,
    /// 8 consecutive lost races.
    Contended,
    /// Lease lost or expired (`Section 7.2`, `EC-C04`). Writes are journaled locally, not pushed.
    Fenced,
    /// Network or GitHub unreachable.
    DegradedOffline,
    /// Token rejected.
    DegradedAuth,
    /// Journal at 90%+ capacity.
    DegradedJournal,
    /// Live budget at soft limit.
    DegradedQuota,
    /// Remote head is not a descendant of last seen head (`REQ-5`).
    Diverged,
    /// `fsck` or read found corruption.
    Damaged,
}

/// Persistent `state.json` stored in the local state directory (Section 3.4, 6.9, 12.4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalStateFile {
    /// Last seen remote commit SHA (hex).
    pub last_seen_head: Option<String>,
    /// Highest volume epoch observed (`REQ-5` anti-rollback).
    pub highest_epoch: u64,
    /// Pinned signer fingerprints.
    pub pinned_signers: Vec<String>,
}

/// JSON payload served by `.octoblock/status` and `octoblock status --json` (Section 16.2, 17, REQ-13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    /// Current mount state.
    pub state: MountState,
    /// Active mount role (`writer`, `follower`, `multi_writer`).
    pub role: MountRole,
    /// Active mount durability mode.
    pub mode: MountMode,
    /// Highest durability level guaranteed for `fsync` in this mode.
    pub fsync_durability: DurabilityLevel,
    /// Uncommitted operations in the local journal.
    pub journal_depth_ops: usize,
    /// Uncommitted bytes in the local journal.
    pub journal_depth_bytes: u64,
    /// Dirty bytes in the current in-memory commit group.
    pub dirty_group_bytes: u64,
    /// Last acknowledged remote head commit SHA.
    pub head_commit: String,
    /// Current volume epoch.
    pub epoch: u64,
    /// Live bytes charged against the 800 MB budget.
    pub live_bytes: u64,
    /// Soft budget in bytes (800 MB default).
    pub budget_soft: u64,
    /// Number of remote commits pushed during this session.
    pub remote_commits: u64,
    /// Current writer lease holder and expiration (`None` if unleased).
    pub lease: Option<LeaseRecord>,
}

/// `statfs` / `df` accounting structure (Section 8, Section 13.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatFs {
    /// Optimal transfer block size (`page_size`).
    pub bsize: u32,
    /// Total blocks in the volume budget (`budget_soft / page_size`).
    pub blocks: u64,
    /// Free blocks remaining in the volume budget.
    pub bfree: u64,
    /// Available blocks for unprivileged users.
    pub bavail: u64,
    /// Total live inodes in the volume.
    pub files: u64,
    /// Maximum filename length (`255`).
    pub namelen: u32,
}

/// Configuration for [`WriteBackEngine`].
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Git branch ref (`refs/heads/main`).
    pub branch: String,
    /// Mount mode (`strict`, `balanced`, `relaxed`).
    pub mode: MountMode,
    /// Writer lease policy (`required`, `advisory`, `off`).
    pub lease_policy: LeasePolicy,
    /// Explicitly mount as a read-only follower (`--follow`).
    pub follow_only: bool,
    /// Human-readable holder name for the writer lease.
    pub holder_name: String,
    /// Group commit dirty-bytes trigger (`8 MiB` default, Appendix B).
    pub flush_bytes: u64,
    /// Backpressure dirty-bytes high-water mark (`64 MiB` default, Section 6.10).
    pub high_water: u64,
    /// Journal capacity (`1 GiB` default).
    pub journal_capacity: u64,
    /// Action when journal is full.
    pub on_journal_full: OnJournalFull,
    /// Optional 32-byte master key for journal encryption (`REQ-8`).
    pub master_key: Option<[u8; 32]>,
    /// Mount identifier for allocation group hashing and lease identity.
    pub mount_id: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            branch: "refs/heads/main".into(),
            mode: MountMode::Balanced,
            lease_policy: LeasePolicy::Required,
            follow_only: false,
            holder_name: "octoblock-node".into(),
            flush_bytes: 8 * 1024 * 1024,
            high_water: 64 * 1024 * 1024,
            journal_capacity: DEFAULT_JOURNAL_CAPACITY,
            on_journal_full: OnJournalFull::Enospc,
            master_key: None,
            mount_id: 1,
        }
    }
}

/// Layer 4 Write-Back Engine and Path-Class Router over `Volume` and `Transport`.
pub struct WriteBackEngine<T: Transport> {
    transport: T,
    config: EngineConfig,
    role: MountRole,
    lease_mgr: LeaseManager,
    state_dir: PathBuf,
    local_sidecar_dir: PathBuf,
    state_file: LocalStateFile,
    mount_state: MountState,
    vol: Volume,
    policy: PolicyEngine,
    journal: LocalJournal,
    atomic: AtomicRegion,
    /// Volatile (`RAM`) class files keyed by normalized path.
    volatile_files: BTreeMap<String, Vec<u8>>,
    /// Uncommitted ops in the current group (for elision/coalescing).
    group_ops: Vec<OpRecord>,
    dirty_bytes: u64,
    head: ObjectId,
    /// Last commit built and sent when a push returned `PushOutcomeUnknown`.
    pending_unknown_commit: Option<(ObjectId, u64)>,
    remote_commits: u64,
    next_seq: u64,
}

impl<T: Transport> WriteBackEngine<T> {
    /// Format a brand-new `OBF1` volume, acquire the writer lease if configured, and push its initial commit.
    pub async fn mkfs(
        transport: T,
        state_dir: impl AsRef<Path>,
        config: EngineConfig,
        page_size: usize,
        case_policy: CasePolicy,
        policy: PolicyEngine,
    ) -> Result<Self> {
        let state_dir = state_dir.as_ref().to_path_buf();
        fs::create_dir_all(&state_dir)
            .map_err(|e| Error::new(Errno::EIO, format!("state_dir: {e}")))?;
        let local_sidecar_dir = state_dir.join("local_sidecar");
        fs::create_dir_all(&local_sidecar_dir)
            .map_err(|e| Error::new(Errno::EIO, format!("local_sidecar: {e}")))?;

        let mut uuid = [0u8; 16];
        for b in &mut uuid {
            *b = fastrand::u8(..);
        }
        let mut vol = Volume::mkfs(page_size, uuid, case_policy, config.mount_id)?;
        let policy_toml = policy.to_toml().into_bytes();
        let policy_blob = Object::blob(policy_toml.clone())
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        vol.set_policy_sha(policy_blob.id().as_bytes().to_vec());

        let (journal, _) = LocalJournal::open(
            state_dir.join("journal"),
            config.master_key.as_ref(),
            config.journal_capacity,
            config.on_journal_full,
        )?;

        let mount_uuid = format!("mount-{:016x}", config.mount_id);
        let mut lease_mgr = LeaseManager::new(&config.holder_name, mount_uuid, config.lease_policy);
        if config.lease_policy == LeasePolicy::Required {
            lease_mgr.acquire_or_renew(&transport).await?;
        }
        let role = match config.lease_policy {
            LeasePolicy::Advisory => MountRole::MultiWriter,
            _ => MountRole::Writer,
        };

        let mut engine = WriteBackEngine {
            transport,
            config,
            role,
            lease_mgr,
            state_dir,
            local_sidecar_dir,
            state_file: LocalStateFile::default(),
            mount_state: MountState::Online,
            vol,
            policy,
            journal,
            atomic: AtomicRegion::default(),
            volatile_files: BTreeMap::new(),
            group_ops: Vec::new(),
            dirty_bytes: 0,
            head: ObjectId::ZERO,
            pending_unknown_commit: None,
            remote_commits: 0,
            next_seq: 1,
        };
        engine
            .push_volume_state(
                b"{\"seq\":0,\"t\":0.0,\"op\":\"barrier\",\"kind\":\"group_end\"}\n",
                true,
            )
            .await?;
        engine.save_state_file()?;
        Ok(engine)
    }

    /// Mount an existing volume from `transport`, negotiating the writer lease (`Section 7.2`, `EC-C03`),
    /// verifying anti-rollback (`REQ-5`), and replaying any uncommitted records from the local journal (`Section 6.9`).
    pub async fn mount(
        transport: T,
        state_dir: impl AsRef<Path>,
        config: EngineConfig,
    ) -> Result<Self> {
        let state_dir = state_dir.as_ref().to_path_buf();
        fs::create_dir_all(&state_dir)
            .map_err(|e| Error::new(Errno::EIO, format!("state_dir: {e}")))?;
        let local_sidecar_dir = state_dir.join("local_sidecar");
        fs::create_dir_all(&local_sidecar_dir)
            .map_err(|e| Error::new(Errno::EIO, format!("local_sidecar: {e}")))?;

        let state_path = state_dir.join("state.json");
        let state_file: LocalStateFile = if state_path.exists() {
            let raw = fs::read(&state_path)
                .map_err(|e| Error::new(Errno::EIO, format!("read state.json: {e}")))?;
            serde_json::from_slice(&raw)
                .map_err(|e| Error::new(Errno::EIO, format!("parse state.json: {e}")))?
        } else {
            LocalStateFile::default()
        };

        let refs = transport
            .list_refs(&[&config.branch])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("list_refs: {e}")))?;
        let head = refs
            .into_iter()
            .find(|r| r.name == config.branch)
            .map(|r| r.id)
            .ok_or_else(|| Error::new(Errno::ENOENT, "volume branch not found on remote"))?;

        // Negotiate writer lease / role (Section 7.1, 7.2, EC-C03).
        let mount_uuid = format!("mount-{:016x}", config.mount_id);
        let mut lease_mgr = LeaseManager::new(&config.holder_name, mount_uuid, config.lease_policy);
        let mut role = if config.follow_only {
            let _ = lease_mgr.fetch_remote_lease(&transport).await?;
            MountRole::Follower
        } else {
            match config.lease_policy {
                LeasePolicy::Required => match lease_mgr.acquire_or_renew(&transport).await? {
                    LeaseOutcome::Acquired(_) => MountRole::Writer,
                    // EC-C03: Another mount holds the live writer lease -> automatically become Follower!
                    LeaseOutcome::HeldByOther(_) | LeaseOutcome::Fenced(_) => MountRole::Follower,
                },
                LeasePolicy::Advisory => MountRole::MultiWriter,
                LeasePolicy::Off => MountRole::Writer,
            }
        };

        let (pages, policy) = Self::fetch_volume_from_remote(&transport, head).await?;
        let mut vol = Volume::mount(pages, role != MountRole::Follower, config.mount_id)?;

        // Section 6.9 step 2 & Section 12.4 (REQ-5): Anti-rollback check.
        let mut mount_state = MountState::Online;
        if vol.superblock().epoch < state_file.highest_epoch {
            mount_state = MountState::Diverged;
            role = MountRole::Follower;
        } else if let Some(last_hex) = &state_file.last_seen_head
            && let Ok(last_id) = ObjectId::from_hex(last_hex)
            && last_id != head
            && !Self::is_descendant(&transport, head, last_id).await?
        {
            mount_state = MountState::Diverged;
            role = MountRole::Follower;
        }

        let (mut journal, recovered) = LocalJournal::open(
            state_dir.join("journal"),
            config.master_key.as_ref(),
            config.journal_capacity,
            config.on_journal_full,
        )?;

        let mut replayed_ops = Vec::new();
        let mut ino_remap: BTreeMap<u64, u64> = BTreeMap::new();
        if mount_state != MountState::Diverged
            && role != MountRole::Follower
            && !recovered.is_empty()
        {
            for entry in &recovered {
                if entry.kind == JournalRecordType::Mutation {
                    Self::apply_recovered_entry(&mut vol, entry, &mut ino_remap)?;
                    replayed_ops.push(entry.op.clone());
                }
            }
        } else if recovered.is_empty() {
            journal.truncate_committed()?;
        }

        let mut engine = WriteBackEngine {
            transport,
            config,
            role,
            lease_mgr,
            state_dir,
            local_sidecar_dir,
            state_file,
            mount_state,
            vol,
            policy,
            journal,
            atomic: AtomicRegion::default(),
            volatile_files: BTreeMap::new(),
            group_ops: replayed_ops,
            dirty_bytes: 0,
            head,
            pending_unknown_commit: None,
            remote_commits: 0,
            next_seq: 1,
        };
        if engine.mount_state != MountState::Diverged {
            engine.save_state_file()?;
        }
        Ok(engine)
    }

    // ------------------------------------------------------------------ Lease & Fencing Operations

    /// Current mount role (`Writer`, `Follower`, `MultiWriter`).
    pub const fn role(&self) -> MountRole {
        self.role
    }

    /// Reference to the [`LeaseManager`].
    pub const fn lease_manager(&self) -> &LeaseManager {
        &self.lease_mgr
    }

    /// Mutable reference to the [`LeaseManager`] (for clock manipulation in tests).
    pub fn lease_manager_mut(&mut self) -> &mut LeaseManager {
        &mut self.lease_mgr
    }

    /// Renew or reacquire the writer lease (`Section 7.2`, `EC-C04`).
    ///
    /// If the lease was lost or expired, transitions the mount to [`MountState::Fenced`].
    /// If the mount was [`MountState::Fenced`] and successfully reacquires the lease, checks
    /// whether the remote head moved while fenced and rebases the local journal onto the new head!
/// Renew or reacquire the writer lease (`Section 7.2`, `EC-C04`).
    pub async fn renew_lease(&mut self) -> Result<MountState> {
        if self.config.lease_policy != LeasePolicy::Required || self.role == MountRole::Follower {
            return Ok(self.mount_state);
        }
        let was_fenced = self.mount_state == MountState::Fenced;
        match self.lease_mgr.acquire_or_renew(&self.transport).await? {
            LeaseOutcome::Acquired(_) => {
                self.vol.set_read_only(false);
                self.role = MountRole::Writer;
                if was_fenced {
                    self.reconcile_after_fencing().await?;
                }
                self.mount_state = if self.journal.depth_ops() > 0 {
                    MountState::Syncing
                } else {
                    MountState::Online
                };
            }
            LeaseOutcome::HeldByOther(_) | LeaseOutcome::Fenced(_) => {
                self.mount_state = MountState::Fenced;
                // Fenced mounts continue to allow local journal writes (L1), so ensure volume is writable:
                self.vol.set_read_only(false);
            }
        }
        Ok(self.mount_state)
    }

    async fn reconcile_after_fencing(&mut self) -> Result<()> {
        let refs = self
            .transport
            .list_refs(&[&self.config.branch])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("list_refs: {e}")))?;
        let Some(remote_head) = refs
            .into_iter()
            .find(|r| r.name == self.config.branch)
            .map(|r| r.id)
        else {
            return Ok(());
        };
        if remote_head == self.head {
            self.vol.set_read_only(false);
            return Ok(());
        }

        // Verify anti-rollback before accepting the new head (REQ-5).
        if !Self::is_descendant(&self.transport, remote_head, self.head).await? {
            self.mount_state = MountState::Diverged;
            self.role = MountRole::Follower;
            return Err(Error::new(
                Errno::EROFS,
                "remote head diverged while mount was fenced (REQ-5)",
            ));
        }

        let (pages, policy) = Self::fetch_volume_from_remote(&self.transport, remote_head).await?;
        let mut new_vol = Volume::mount(pages, false, self.config.mount_id)?;
        new_vol.set_read_only(false);
        self.role = MountRole::Writer;

        // Replay all uncommitted local journal entries onto `new_vol` (Section 6.9 step 5, Section 7.2).
        let (reopened_journal, entries) = LocalJournal::open(
            self.state_dir.join("journal"),
            self.config.master_key.as_ref(),
            self.config.journal_capacity,
            self.config.on_journal_full,
        )?;
        self.journal = reopened_journal;
        let mut ino_remap = BTreeMap::new();
        let mut replayed_ops = Vec::new();
        for entry in &entries {
            if entry.kind == JournalRecordType::Mutation {
                Self::apply_recovered_entry(&mut new_vol, entry, &mut ino_remap)?;
                replayed_ops.push(entry.op.clone());
            }
        }
        self.vol = new_vol;
        self.policy = policy;
        self.head = remote_head;
        self.group_ops = replayed_ops;
        self.save_state_file()?;
        Ok(())
    }
    /// Force-break the writer lease on `refs/octopage/lease` (`octoblock lease break`, Section 7.2).
    ///
    /// Promotes a `Follower` or `Fenced` mount to active `Writer` and fences the previous holder.
    pub async fn break_lease(&mut self) -> Result<LeaseRecord> {
        let rec = self.lease_mgr.break_lease(&self.transport).await?;
        let was_fenced_or_follower =
            self.mount_state == MountState::Fenced || self.role == MountRole::Follower;
        self.role = MountRole::Writer;
        if was_fenced_or_follower {
            self.reconcile_after_fencing().await?;
        }
        self.mount_state = if self.journal.depth_ops() > 0 {
            MountState::Syncing
        } else {
            MountState::Online
        };
        Ok(rec)
    }

    /// Release the writer lease cleanly on unmount (`octoblock umount`).
    pub async fn unmount(&mut self) -> Result<()> {
        if self.role != MountRole::Follower && self.mount_state != MountState::Fenced {
            let _ = self.sync_remote().await;
        }
        self.lease_mgr.release(&self.transport).await
    }

    /// When a fenced mount reacquires the lease, check if the remote head moved while it was
    /// fenced; if so, fetch the new head and replay the local journal on top of it (`Section 7.2`, `EC-C04`).
    async fn is_descendant(transport: &T, tip: ObjectId, ancestor: ObjectId) -> Result<bool> {
        if tip == ancestor {
            return Ok(true);
        }
        let objs = transport
            .history(tip, Some(ancestor), false)
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("history: {e}")))?;
        for obj in objs {
            if obj.kind() == ObjectKind::Commit
                && let Ok(c) = Commit::decode(obj.data())
                && c.parents.contains(&ancestor)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn fetch_volume_from_remote(
        transport: &T,
        commit_id: ObjectId,
    ) -> Result<(BTreeMap<PageId, Bytes>, PolicyEngine)> {
        let commit_objs = transport
            .fetch(&[commit_id])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("fetch commit: {e}")))?;
        let commit = Commit::decode(commit_objs[0].data())
            .map_err(|e| Error::new(Errno::EIO, format!("decode commit: {e}")))?;
        let root_objs = transport
            .fetch(&[commit.tree])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("fetch root tree: {e}")))?;
        let root_tree = Tree::decode(root_objs[0].data())
            .map_err(|e| Error::new(Errno::EIO, format!("decode root tree: {e}")))?;

        let pages_tree_id = root_tree
            .get(b"pages")
            .map(|e| e.id)
            .ok_or_else(|| Error::new(Errno::EIO, "missing pages/ tree in commit"))?;

        let mut policy = PolicyEngine::tier0_default();
        if let Some(p_entry) = root_tree.get(b"policy.toml") {
            let p_objs = transport
                .fetch(&[p_entry.id])
                .await
                .map_err(|e| Error::new(Errno::EIO, format!("fetch policy.toml: {e}")))?;
            if let Ok(text) = std::str::from_utf8(p_objs[0].data()) {
                policy = PolicyEngine::parse_toml(text)?;
            }
        }

        // Walk the 3-level `pages/AA/BB/CC` fan-out tree and batch-fetch all page blobs.
        let mut blob_ids: Vec<(PageId, ObjectId)> = Vec::new();
        let top_objs = transport
            .fetch(&[pages_tree_id])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("fetch pages top: {e}")))?;
        let top_tree = Tree::decode(top_objs[0].data())
            .map_err(|e| Error::new(Errno::EIO, format!("decode pages top: {e}")))?;

        for e_a in top_tree.entries() {
            if e_a.mode != EntryMode::Tree {
                continue;
            }
            let a = u8::from_str_radix(std::str::from_utf8(&e_a.name).unwrap_or(""), 16)
                .map_err(|_| Error::new(Errno::EIO, "bad fanout byte A"))?;
            let mid_objs = transport
                .fetch(&[e_a.id])
                .await
                .map_err(|e| Error::new(Errno::EIO, format!("fetch pages mid: {e}")))?;
            let mid_tree = Tree::decode(mid_objs[0].data())
                .map_err(|e| Error::new(Errno::EIO, format!("decode pages mid: {e}")))?;
            for e_b in mid_tree.entries() {
                if e_b.mode != EntryMode::Tree {
                    continue;
                }
                let b = u8::from_str_radix(std::str::from_utf8(&e_b.name).unwrap_or(""), 16)
                    .map_err(|_| Error::new(Errno::EIO, "bad fanout byte B"))?;
                let leaf_objs = transport
                    .fetch(&[e_b.id])
                    .await
                    .map_err(|e| Error::new(Errno::EIO, format!("fetch pages leaf: {e}")))?;
                let leaf_tree = Tree::decode(leaf_objs[0].data())
                    .map_err(|e| Error::new(Errno::EIO, format!("decode pages leaf: {e}")))?;
                for e_c in leaf_tree.entries() {
                    let c = u8::from_str_radix(std::str::from_utf8(&e_c.name).unwrap_or(""), 16)
                        .map_err(|_| Error::new(Errno::EIO, "bad fanout byte C"))?;
                    blob_ids.push((PageId::from_bytes([a, b, c]), e_c.id));
                }
            }
        }

        let wanted: Vec<ObjectId> = blob_ids.iter().map(|(_, oid)| *oid).collect();
        let fetched = transport
            .fetch(&wanted)
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("fetch page blobs: {e}")))?;
        let by_oid: BTreeMap<ObjectId, Bytes> = fetched
            .into_iter()
            .map(|o| (o.id(), o.data().clone()))
            .collect();

        let mut pages = BTreeMap::new();
        for (pid, oid) in blob_ids {
            let data = by_oid
                .get(&oid)
                .ok_or_else(|| Error::new(Errno::EIO, format!("missing blob {oid}")))?
                .clone();
            pages.insert(pid, data);
        }
        Ok((pages, policy))
    }

    fn apply_recovered_entry(
        vol: &mut Volume,
        entry: &JournalEntry,
        ino_remap: &mut BTreeMap<u64, u64>,
    ) -> Result<()> {
        let map_ino = |m: &BTreeMap<u64, u64>, ino: u64| m.get(&ino).copied().unwrap_or(ino);
        match &entry.op.kind {
            OpKind::Create {
                op_name,
                parent,
                name,
                mode,
                ino: recorded_ino,
                target,
                ..
            } => {
                let p_ino = map_ino(ino_remap, *parent);
                let actual_ino = match vol.lookup(p_ino, name.as_bytes()) {
                    Ok(existing) => existing,
                    Err(_) => match op_name.as_str() {
                        "mkdir" => {
                            vol.mkdir(p_ino, name.as_bytes(), *mode, entry.op.uid, entry.op.gid)?
                        }
                        "symlink" => {
                            let tgt = target.as_deref().unwrap_or("").as_bytes();
                            vol.symlink(p_ino, name.as_bytes(), tgt, entry.op.uid, entry.op.gid)?
                        }
                        _ => vol.create(
                            p_ino,
                            name.as_bytes(),
                            *mode,
                            entry.op.uid,
                            entry.op.gid,
                        )?,
                    },
                };
                ino_remap.insert(*recorded_ino, actual_ino);
            }
            OpKind::Link { ino, parent, name } => {
                let t_ino = map_ino(ino_remap, *ino);
                let p_ino = map_ino(ino_remap, *parent);
                if vol.lookup(p_ino, name.as_bytes()).is_err() {
                    let _ = vol.link(t_ino, p_ino, name.as_bytes());
                }
            }
            OpKind::Unlink {
                op_name,
                parent,
                name,
                ..
            } => {
                let p_ino = map_ino(ino_remap, *parent);
                if vol.lookup(p_ino, name.as_bytes()).is_ok() {
                    if op_name == "rmdir" {
                        let _ = vol.rmdir(p_ino, name.as_bytes());
                    } else {
                        let _ = vol.unlink(p_ino, name.as_bytes());
                    }
                }
            }
            OpKind::Rename { old, new, flags } => {
                let old_p = map_ino(ino_remap, old.0);
                let new_p = map_ino(ino_remap, new.0);
                if vol.lookup(old_p, old.1.as_bytes()).is_ok() {
                    let _ = vol.rename(
                        old_p,
                        old.1.as_bytes(),
                        new_p,
                        new.1.as_bytes(),
                        *flags,
                    );
                }
            }
            OpKind::Write { ino, off, .. } => {
                let t_ino = map_ino(ino_remap, *ino);
                let _ = vol.write(t_ino, *off, &entry.data);
            }
            OpKind::Truncate {
                op_name,
                ino,
                off,
                size,
                ..
            } => {
                let t_ino = map_ino(ino_remap, *ino);
                if op_name == "punch_hole" {
                    let _ = vol.punch_hole(t_ino, *off, *size);
                } else {
                    let _ = vol.truncate(t_ino, *size);
                }
            }
            OpKind::Setattr {
                ino,
                mode,
                uid,
                gid,
                size,
                mtime,
                flags,
            } => {
                let t_ino = map_ino(ino_remap, *ino);
                let _ = vol.setattr(t_ino, *mode, *uid, *gid, *size, *mtime, *flags);
            }
            OpKind::Xattr {
                op_name,
                ino,
                name,
                ..
            } => {
                let t_ino = map_ino(ino_remap, *ino);
                if op_name == "removexattr" {
                    let _ = vol.removexattr(t_ino, name);
                } else {
                    let _ = vol.setxattr(t_ino, name, &entry.data);
                }
            }
            OpKind::Barrier { .. } => {}
        }
        Ok(())
    }

    fn save_state_file(&mut self) -> Result<()> {
        self.state_file.last_seen_head = Some(self.head.to_hex());
        self.state_file.highest_epoch = self
            .state_file
            .highest_epoch
            .max(self.vol.superblock().epoch);
        let json = serde_json::to_vec_pretty(&self.state_file)
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        let tmp = self.state_dir.join("state.json.tmp");
        let dst = self.state_dir.join("state.json");
        fs::write(&tmp, json).map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        fs::rename(&tmp, &dst).map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        Ok(())
    }

    // ------------------------------------------------------------------ Path resolution & Policy routing

    fn check_writable(&self, non_blocking: bool) -> Result<()> {
        // Only strict Follower mounts are read-only. Fenced mounts are permitted to write locally (L1).
        if self.role == MountRole::Follower && self.mount_state != MountState::Fenced {
            return Err(Error::new(
                Errno::EROFS,
                "follower mount is read-only (Section 7.1)",
            ));
        }
        if self.mount_state == MountState::Diverged {
            return Err(Error::new(Errno::EROFS, "volume is in DIVERGED state"));
        }
        if non_blocking && self.dirty_bytes >= self.config.high_water {
            return Err(Error::new(
                Errno::EAGAIN,
                "dirty bytes above high_water (Section 6.10)",
            ));
        }
        Ok(())
    }

    /// Resolve a POSIX path (`/a/b/c`) to `(parent_ino, entry_name, full_normalized_path)`.
    fn resolve_parent_and_name(&self, path: &str) -> Result<(u64, Vec<u8>, String)> {
        if path.len() > 4096 {
            return Err(Error::new(Errno::ENAMETOOLONG, "path exceeds 4096 bytes"));
        }
        let norm = path.replace('\\', "/");
        let parts: Vec<&str> = norm.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Err(Error::new(Errno::EINVAL, "path names root directory"));
        }
        let mut curr = ROOT_INO;
        for &dir_part in &parts[..parts.len() - 1] {
            curr = self.vol.lookup(curr, dir_part.as_bytes())?;
        }
        let last = parts[parts.len() - 1];
        let full = format!("/{}", parts.join("/"));
        Ok((curr, last.as_bytes().to_vec(), full))
    }

    /// Resolve a full path to its inode number in `Volume`.
    pub fn resolve_ino(&self, path: &str) -> Result<u64> {
        let norm = path.replace('\\', "/");
        let parts: Vec<&str> = norm.split('/').filter(|p| !p.is_empty()).collect();
        let mut curr = ROOT_INO;
        for part in parts {
            curr = self.vol.lookup(curr, part.as_bytes())?;
        }
        Ok(curr)
    }

    fn sidecar_file_path(&self, full_path: &str) -> PathBuf {
        let safe: String = full_path
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.local_sidecar_dir.join(safe)
    }

    // ------------------------------------------------------------------ High-Level File-System Operations

    /// Create a regular file at `path`, classifying its persistence policy (Section 5.3) and journaling the op.
    pub fn create(&mut self, path: &str, mode: u32, uid: u32, gid: u32) -> Result<u64> {
        self.check_writable(false)?;
        let (parent_ino, name, full) = self.resolve_parent_and_name(path)?;
        let class = self.policy.classify(&full);
        if class == PathClass::Exclude {
            return Err(Error::new(Errno::EACCES, "path is excluded by policy"));
        }
        let ino = self.vol.create(parent_ino, &name, mode, uid, gid)?;
        self.vol.set_inode_path_class(ino, class)?;

        match class {
            PathClass::Persist => {
                let op = self.record_op(OpKind::Create {
                    op_name: "create".into(),
                    parent: parent_ino,
                    name: String::from_utf8_lossy(&name).into_owned(),
                    mode: S_IFREG | (mode & 0o7777),
                    ino_range: [65_536, 131_071],
                    ino,
                    target: None,
                });
                self.journal
                    .append(JournalRecordType::Mutation, op, Vec::new())?;
                self.dirty_bytes += 128;
            }
            PathClass::Local => {
                let sp = self.sidecar_file_path(&full);
                fs::write(sp, b"").map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
            }
            PathClass::Volatile => {
                self.volatile_files.insert(full, Vec::new());
            }
            PathClass::Exclude => unreachable!(),
        }
        self.update_journal_health();
        Ok(ino)
    }

    /// Create a directory at `path`.
    pub fn mkdir(&mut self, path: &str, mode: u32, uid: u32, gid: u32) -> Result<u64> {
        self.check_writable(false)?;
        let (parent_ino, name, full) = self.resolve_parent_and_name(path)?;
        let class = self.policy.classify(&full);
        if class == PathClass::Exclude {
            return Err(Error::new(Errno::EACCES, "path is excluded by policy"));
        }
        let ino = self.vol.mkdir(parent_ino, &name, mode, uid, gid)?;
        self.vol.set_inode_path_class(ino, class)?;
        if class == PathClass::Persist {
            let op = self.record_op(OpKind::Create {
                op_name: "mkdir".into(),
                parent: parent_ino,
                name: String::from_utf8_lossy(&name).into_owned(),
                mode: S_IFDIR | (mode & 0o7777),
                ino_range: [65_536, 131_071],
                ino,
                target: None,
            });
            self.journal
                .append(JournalRecordType::Mutation, op, Vec::new())?;
            self.dirty_bytes += 128;
        }
        self.update_journal_health();
        Ok(ino)
    }

    /// Create a symbolic link at `path` pointing to `target`.
    pub fn symlink(&mut self, path: &str, target: &[u8], uid: u32, gid: u32) -> Result<u64> {
        self.check_writable(false)?;
        let (parent_ino, name, full) = self.resolve_parent_and_name(path)?;
        let class = self.policy.classify(&full);
        if class == PathClass::Exclude {
            return Err(Error::new(Errno::EACCES, "path is excluded by policy"));
        }
        let ino = self.vol.symlink(parent_ino, &name, target, uid, gid)?;
        self.vol.set_inode_path_class(ino, class)?;
        if class == PathClass::Persist {
            let op = self.record_op(OpKind::Create {
                op_name: "symlink".into(),
                parent: parent_ino,
                name: String::from_utf8_lossy(&name).into_owned(),
                mode: S_IFLNK | 0o777,
                ino_range: [65_536, 131_071],
                ino,
                target: Some(String::from_utf8_lossy(target).into_owned()),
            });
            self.journal
                .append(JournalRecordType::Mutation, op, target.to_vec())?;
            self.dirty_bytes += target.len() as u64;
        }
        Ok(ino)
    }

    /// Create a hard link from `existing_path` to `new_path` (`EXDEV` across classes, REQ-10).
    pub fn link(&mut self, existing_path: &str, new_path: &str) -> Result<()> {
        self.check_writable(false)?;
        let target_ino = self.resolve_ino(existing_path)?;
        let (new_parent, new_name, new_full) = self.resolve_parent_and_name(new_path)?;
        let dst_class = self.policy.classify(&new_full);
        let src_class = self.vol.getattr(target_ino)?.path_class();
        if src_class != dst_class {
            return Err(Error::new(Errno::EXDEV, "cross-class link refused (REQ-10)"));
        }
        self.vol.link(target_ino, new_parent, &new_name)?;
        if src_class == PathClass::Persist {
            let op = self.record_op(OpKind::Link {
                ino: target_ino,
                parent: new_parent,
                name: String::from_utf8_lossy(&new_name).into_owned(),
            });
            self.journal
                .append(JournalRecordType::Mutation, op, Vec::new())?;
        }
        Ok(())
    }

    /// Write `data` to `path` at `offset`.
    pub fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        self.check_writable(false)?;
        self.atomic.record_bytes(data.len() as u64)?;
        let (_, _, full) = self.resolve_parent_and_name(path)?;
        let ino = self.resolve_ino(path)?;
        let rec = self.vol.getattr(ino)?;
        match rec.path_class() {
            PathClass::Persist => {
                let n = self.vol.write(ino, offset, data)?;
                let updated = self.vol.getattr(ino)?;
                let psize = u64::from(self.vol.superblock().page_size);
                let start_p = (offset / psize) as u32;
                let end_p = ((offset + (data.len() as u64).saturating_sub(1)) / psize) as u32;
                let op = self.record_op(OpKind::Write {
                    ino,
                    off: offset,
                    len: data.len() as u64,
                    pages: PageRunRef {
                        file_page: start_p,
                        count: end_p.saturating_sub(start_p) + 1,
                    },
                    size: updated.size,
                });
                self.journal
                    .append(JournalRecordType::Mutation, op, data.to_vec())?;
                self.dirty_bytes += data.len() as u64;
                self.update_journal_health();
                Ok(n)
            }
            PathClass::Local => {
                let sp = self.sidecar_file_path(&full);
                let mut buf = fs::read(&sp).unwrap_or_default();
                let end = (offset as usize) + data.len();
                if buf.len() < end {
                    buf.resize(end, 0);
                }
                buf[offset as usize..end].copy_from_slice(data);
                fs::write(&sp, &buf).map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
                Ok(data.len())
            }
            PathClass::Volatile => {
                let buf = self.volatile_files.entry(full).or_default();
                let end = (offset as usize) + data.len();
                if buf.len() < end {
                    buf.resize(end, 0);
                }
                buf[offset as usize..end].copy_from_slice(data);
                Ok(data.len())
            }
            PathClass::Exclude => Err(Error::new(Errno::EACCES, "excluded path")),
        }
    }

    /// Read up to `len` bytes from `path` at `offset` (including virtual `.octoblock/` files, Section 16.2).
    pub fn read(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let norm = path.replace('\\', "/");
        if norm == "/.octoblock/status" {
            let json = serde_json::to_vec_pretty(&self.status()).unwrap();
            let off = (offset as usize).min(json.len());
            let end = (off + len).min(json.len());
            return Ok(json[off..end].to_vec());
        }
        if norm == "/.octoblock/policy.toml" {
            let text = self.policy.to_toml().into_bytes();
            let off = (offset as usize).min(text.len());
            let end = (off + len).min(text.len());
            return Ok(text[off..end].to_vec());
        }

        let (_, _, full) = self.resolve_parent_and_name(path)?;
        let ino = self.resolve_ino(path)?;
        let rec = self.vol.getattr(ino)?;
        match rec.path_class() {
            PathClass::Persist => self.vol.read(ino, offset, len),
            PathClass::Local => {
                let sp = self.sidecar_file_path(&full);
                let buf = fs::read(&sp).unwrap_or_default();
                let off = (offset as usize).min(buf.len());
                let end = (off + len).min(buf.len());
                Ok(buf[off..end].to_vec())
            }
            PathClass::Volatile => {
                let Some(buf) = self.volatile_files.get(&full) else {
                    return Ok(Vec::new());
                };
                let off = (offset as usize).min(buf.len());
                let end = (off + len).min(buf.len());
                Ok(buf[off..end].to_vec())
            }
            PathClass::Exclude => Err(Error::new(Errno::EACCES, "excluded path")),
        }
    }

    /// Truncate `path` to `new_size`.
    pub fn truncate(&mut self, path: &str, new_size: u64) -> Result<()> {
        self.check_writable(false)?;
        let (_, _, full) = self.resolve_parent_and_name(path)?;
        let ino = self.resolve_ino(path)?;
        let rec = self.vol.getattr(ino)?;
        match rec.path_class() {
            PathClass::Persist => {
                self.vol.truncate(ino, new_size)?;
                let op = self.record_op(OpKind::Truncate {
                    op_name: "truncate".into(),
                    ino,
                    off: 0,
                    size: new_size,
                    mode: 0,
                });
                self.journal
                    .append(JournalRecordType::Mutation, op, Vec::new())?;
                Ok(())
            }
            PathClass::Local => {
                let sp = self.sidecar_file_path(&full);
                let mut buf = fs::read(&sp).unwrap_or_default();
                buf.resize(new_size as usize, 0);
                fs::write(&sp, &buf).map_err(|e| Error::new(Errno::EIO, e.to_string()))
            }
            PathClass::Volatile => {
                let buf = self.volatile_files.entry(full).or_default();
                buf.resize(new_size as usize, 0);
                Ok(())
            }
            PathClass::Exclude => Err(Error::new(Errno::EACCES, "excluded path")),
        }
    }

    /// Unlink a non-directory entry at `path`.
    pub fn unlink(&mut self, path: &str) -> Result<()> {
        self.check_writable(false)?;
        let (parent_ino, name, full) = self.resolve_parent_and_name(path)?;
        let ino = self.vol.lookup(parent_ino, &name)?;
        let class = self.vol.getattr(ino)?.path_class();
        self.vol.unlink(parent_ino, &name)?;
        match class {
            PathClass::Persist => {
                let op = self.record_op(OpKind::Unlink {
                    op_name: "unlink".into(),
                    parent: parent_ino,
                    name: String::from_utf8_lossy(&name).into_owned(),
                    ino,
                });
                self.journal
                    .append(JournalRecordType::Mutation, op, Vec::new())?;
            }
            PathClass::Local => {
                let _ = fs::remove_file(self.sidecar_file_path(&full));
            }
            PathClass::Volatile => {
                self.volatile_files.remove(&full);
            }
            PathClass::Exclude => {}
        }
        Ok(())
    }

    /// Remove an empty directory at `path`.
    pub fn rmdir(&mut self, path: &str) -> Result<()> {
        self.check_writable(false)?;
        let (parent_ino, name, _) = self.resolve_parent_and_name(path)?;
        let ino = self.vol.lookup(parent_ino, &name)?;
        let class = self.vol.getattr(ino)?.path_class();
        self.vol.rmdir(parent_ino, &name)?;
        if class == PathClass::Persist {
            let op = self.record_op(OpKind::Unlink {
                op_name: "rmdir".into(),
                parent: parent_ino,
                name: String::from_utf8_lossy(&name).into_owned(),
                ino,
            });
            self.journal
                .append(JournalRecordType::Mutation, op, Vec::new())?;
        }
        Ok(())
    }

    /// Atomic rename from `old_path` to `new_path` (`EXDEV` across classes, REQ-10).
    pub fn rename(&mut self, old_path: &str, new_path: &str, flags: u32) -> Result<()> {
        self.check_writable(false)?;
        let (old_parent, old_name, old_full) = self.resolve_parent_and_name(old_path)?;
        let (new_parent, new_name, new_full) = self.resolve_parent_and_name(new_path)?;
        let src_ino = self.vol.lookup(old_parent, &old_name)?;
        let src_class = self.vol.getattr(src_ino)?.path_class();
        let dst_class = self.policy.classify(&new_full);
        if src_class != dst_class {
            return Err(Error::new(
                Errno::EXDEV,
                "cross-class rename refused (REQ-10)",
            ));
        }
        self.vol
            .rename(old_parent, &old_name, new_parent, &new_name, flags)?;
        match src_class {
            PathClass::Persist => {
                let op = self.record_op(OpKind::Rename {
                    old: (old_parent, String::from_utf8_lossy(&old_name).into_owned()),
                    new: (new_parent, String::from_utf8_lossy(&new_name).into_owned()),
                    flags,
                });
                self.journal
                    .append(JournalRecordType::Mutation, op, Vec::new())?;
            }
            PathClass::Local => {
                let _ = fs::rename(
                    self.sidecar_file_path(&old_full),
                    self.sidecar_file_path(&new_full),
                );
            }
            PathClass::Volatile => {
                if let Some(bytes) = self.volatile_files.remove(&old_full) {
                    self.volatile_files.insert(new_full, bytes);
                }
            }
            PathClass::Exclude => {}
        }
        Ok(())
    }

    /// List directory entries at `path`.
    pub fn readdir(&self, path: &str, after_cookie: u64) -> Result<Vec<DirEntry>> {
        let ino = self.resolve_ino(path)?;
        self.vol.readdir(ino, after_cookie)
    }

    /// Read inode attributes for `path`.
    pub fn getattr(&self, path: &str) -> Result<InodeRecord> {
        let ino = self.resolve_ino(path)?;
        self.vol.getattr(ino)
    }

    /// Begin an un-splittable atomic region (`OBX_ATOMIC_BEGIN`, Section 6.8, REQ-3).
    pub fn atomic_begin(&mut self) -> Result<()> {
        self.atomic.begin()?;
        let op = self.record_op(OpKind::Barrier {
            kind: "atomic_begin".into(),
        });
        self.journal
            .append(JournalRecordType::Barrier, op, Vec::new())?;
        Ok(())
    }

    /// End an atomic region and flush the group (`OBX_ATOMIC_END`, Section 6.8, REQ-3).
    pub async fn atomic_end(&mut self) -> Result<()> {
        self.atomic.end()?;
        let op = self.record_op(OpKind::Barrier {
            kind: "atomic_end".into(),
        });
        self.journal
            .append(JournalRecordType::Barrier, op, Vec::new())?;
        self.journal.barrier()?;
        self.sync_remote().await
    }

    /// Execute `fsync` on `path` honoring the mount mode (`REQ-2`, `EC-L05`).
    pub async fn fsync(&mut self, path: &str) -> Result<DurabilityLevel> {
        let (_, _, full) = self.resolve_parent_and_name(path)?;
        // Section 5.3 & EC-L05: volatile file fsync is a no-op success even in strict mode.
        if self.policy.classify(&full) == PathClass::Volatile {
            return Ok(DurabilityLevel::L0);
        }
        match self.config.mode {
            MountMode::Relaxed => Ok(DurabilityLevel::L0),
            MountMode::Balanced => {
                self.journal.barrier()?;
                Ok(DurabilityLevel::L1)
            }
            MountMode::Strict => {
                self.journal.barrier()?;
                self.sync_remote().await?;
                Ok(DurabilityLevel::L2)
            }
        }
    }

    /// Force an `L2` group commit to the remote repository (`octoblock sync`, Section 6.7).
    pub async fn sync_remote(&mut self) -> Result<()> {
        if self.role == MountRole::Follower {
            return Err(Error::new(Errno::EROFS, "follower mount cannot push"));
        }
        if self.atomic.active {
            // REQ-3: No commit group may be split inside an atomic region.
            return Ok(());
        }
        // REQ-11: Empty groups MUST NOT be committed.
        if self.group_ops.is_empty() && self.journal.depth_ops() == 0 {
            return Ok(());
        }

        // Section 7.2: Verify or reacquire the writer lease before pushing when `--lease required`.
        if self.config.lease_policy == LeasePolicy::Required {
            self.renew_lease().await?;
            if self.mount_state == MountState::Fenced {
                // Fenced mounts MUST NOT push to the remote; ops stay safely in the local journal.
                self.journal.barrier()?;
                return Ok(());
            }
        }

        let coalesced = coalesce_and_elide(&self.group_ops);
        let changelog = encode_changelog(&coalesced);
        let _ = self.vol.commit_group()?;
        self.push_volume_state(&changelog, false).await?;
        self.group_ops.clear();
        self.dirty_bytes = 0;
        self.journal.truncate_committed()?;
        self.mount_state = MountState::Online;
        self.save_state_file()?;
        Ok(())
    }

    async fn push_volume_state(&mut self, changelog_bytes: &[u8], initial: bool) -> Result<()> {
        if let Some((unknown_commit, _)) = self.pending_unknown_commit {
            let refs = self
                .transport
                .list_refs(&[&self.config.branch])
                .await
                .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
            if refs
                .iter()
                .any(|r| r.name == self.config.branch && r.id == unknown_commit)
            {
                self.head = unknown_commit;
                self.pending_unknown_commit = None;
                self.remote_commits += 1;
                return Ok(());
            }
        }

        let pages = self.vol.clone_storage();
        let mut new_objects: Vec<NewObject> = Vec::new();
        let mut by_a: BTreeMap<u8, BTreeMap<u8, Vec<(u8, ObjectId)>>> = BTreeMap::new();

        for (pid, raw_bytes) in pages {
            let blob =
                Object::blob(raw_bytes).map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
            let [a, b, c] = pid.bytes();
            by_a.entry(a)
                .or_default()
                .entry(b)
                .or_default()
                .push((c, blob.id()));
            new_objects.push(blob.into());
        }

        let mut top_tree = Tree::new();
        for (a, by_b) in by_a {
            let mut mid_tree = Tree::new();
            for (b, leaves) in by_b {
                let mut leaf_tree = Tree::new();
                for (c, blob_id) in leaves {
                    leaf_tree
                        .insert(TreeEntry::blob(format!("{c:02x}"), blob_id))
                        .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
                }
                let leaf_obj = leaf_tree
                    .to_object()
                    .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
                mid_tree
                    .insert(TreeEntry::tree(format!("{b:02x}"), leaf_obj.id()))
                    .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
                new_objects.push(leaf_obj.into());
            }
            let mid_obj = mid_tree
                .to_object()
                .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
            top_tree
                .insert(TreeEntry::tree(format!("{a:02x}"), mid_obj.id()))
                .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
            new_objects.push(mid_obj.into());
        }
        let pages_tree_obj = top_tree
            .to_object()
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        new_objects.push(pages_tree_obj.clone().into());

        let changelog_obj = Object::blob(Bytes::copy_from_slice(changelog_bytes))
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        new_objects.push(changelog_obj.clone().into());

        let policy_obj = Object::blob(Bytes::from(self.policy.to_toml()))
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        new_objects.push(policy_obj.clone().into());

        let mut root_tree = Tree::new();
        root_tree
            .insert(TreeEntry::tree("pages", pages_tree_obj.id()))
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        root_tree
            .insert(TreeEntry::blob("changelog", changelog_obj.id()))
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        root_tree
            .insert(TreeEntry::blob("policy.toml", policy_obj.id()))
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        let root_tree_obj = root_tree
            .to_object()
            .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        new_objects.push(root_tree_obj.clone().into());

        let epoch = self.vol.superblock().epoch;
        let commit_time = 1_791_371_000 + (epoch as i64);
        let sig = Signature::new("octoblock", "octoblock@example.invalid", commit_time);
        let parents = if initial || self.head.is_zero() {
            Vec::new()
        } else {
            vec![self.head]
        };
        let commit_obj = Commit {
            tree: root_tree_obj.id(),
            parents,
            author: sig.clone(),
            committer: sig,
            message: format!("octoblock group epoch {epoch}\n").into_bytes(),
        }
        .to_object()
        .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        let commit_id = commit_obj.id();
        new_objects.push(commit_obj.into());

        let ref_update = if initial || self.head.is_zero() {
            RefUpdate::create(&self.config.branch, commit_id)
        } else {
            RefUpdate::update(&self.config.branch, self.head, commit_id)
        };

        for _attempt in 0..4 {
            match self
                .transport
                .push(std::slice::from_ref(&ref_update), &new_objects)
                .await
            {
                Ok(()) => {
                    self.head = commit_id;
                    self.pending_unknown_commit = None;
                    self.remote_commits += 1;
                    return Ok(());
                }
                Err(octopage_git::Error::PushOutcomeUnknown(_)) => {
                    self.pending_unknown_commit = Some((commit_id, epoch));
                    let refs = self
                        .transport
                        .list_refs(&[&self.config.branch])
                        .await
                        .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
                    if refs
                        .iter()
                        .any(|r| r.name == self.config.branch && r.id == commit_id)
                    {
                        self.head = commit_id;
                        self.pending_unknown_commit = None;
                        self.remote_commits += 1;
                        return Ok(());
                    }
                }
                Err(octopage_git::Error::RateLimited { .. }) => {
                    self.mount_state = MountState::DegradedOffline;
                    continue;
                }
                Err(e) => {
                    self.mount_state = MountState::DegradedOffline;
                    return Err(Error::new(Errno::EIO, format!("remote push failed: {e}")));
                }
            }
        }
        Err(Error::new(
            Errno::EIO,
            "push did not land after retry attempts",
        ))
    }

    fn record_op(&mut self, kind: OpKind) -> OpRecord {
        let seq = self.next_seq;
        self.next_seq += 1;
        let op = OpRecord {
            seq,
            t: 1_791_371_042.0 + (seq as f64) * 0.001,
            uid: 1000,
            gid: 1000,
            kind,
        };
        self.group_ops.push(op.clone());
        op
    }

    fn update_journal_health(&mut self) {
        if self.mount_state == MountState::Fenced {
            return;
        }
        if self.journal.is_above_90_percent() {
            self.mount_state = MountState::DegradedJournal;
        } else if self.journal.depth_ops() > 0 && self.mount_state == MountState::Online {
            self.mount_state = MountState::Syncing;
        }
    }

    /// Return `.octoblock/status` observability report (`REQ-13`).
    pub fn status(&self) -> StatusReport {
        let sb = self.vol.superblock();
        let fsync_durability = match self.config.mode {
            MountMode::Strict => DurabilityLevel::L2,
            MountMode::Balanced => DurabilityLevel::L1,
            MountMode::Relaxed => DurabilityLevel::L0,
        };
        StatusReport {
            state: self.mount_state,
            role: self.role,
            mode: self.config.mode,
            fsync_durability,
            journal_depth_ops: self.journal.depth_ops(),
            journal_depth_bytes: self.journal.depth_bytes(),
            dirty_group_bytes: self.dirty_bytes,
            head_commit: self.head.to_hex(),
            epoch: sb.epoch,
            live_bytes: sb.live_bytes,
            budget_soft: octoblock_fs::DEFAULT_BUDGET_SOFT,
            remote_commits: self.remote_commits,
            lease: self.lease_mgr.known_lease().cloned(),
        }
    }

    /// Return `statfs` / `df` volume space statistics (Section 8, Section 13.1).
    pub fn statfs(&self) -> StatFs {
        let sb = self.vol.superblock();
        let psize = u64::from(sb.page_size);
        let total_blocks = octoblock_fs::DEFAULT_BUDGET_SOFT / psize;
        let free_blocks = total_blocks.saturating_sub(sb.live_pages);
        StatFs {
            bsize: sb.page_size,
            blocks: total_blocks,
            bfree: free_blocks,
            bavail: free_blocks,
            files: sb.inode_count,
            namelen: 255,
        }
    }

    /// Reference to the underlying [`Volume`].
    pub const fn volume(&self) -> &Volume {
        &self.vol
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use octoblock_fs::{RENAME_EXCHANGE, RENAME_NOREPLACE};
    use octopage_git::{Fault, InMemory};

    #[tokio::test]
    async fn phase_c_pjdfstest_supported_set_and_policy_classes() {
        let remote = Arc::new(InMemory::new());
        let dir = tempfile::tempdir().unwrap();
        let cfg = EngineConfig {
            master_key: Some([0x33; 32]),
            ..EngineConfig::default()
        };
        let mut engine = WriteBackEngine::mkfs(
            remote,
            dir.path(),
            cfg,
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier1_default(),
        )
        .await
        .unwrap();

        // 1. Path class routing: /tmp is volatile, /var/log is local, /etc is persist
        engine.mkdir("/tmp", 0o755, 0, 0).unwrap();
        engine.create("/tmp/sock.tmp", 0o644, 1000, 1000).unwrap();
        engine.write("/tmp/sock.tmp", 0, b"ram-only").unwrap();
        assert_eq!(engine.read("/tmp/sock.tmp", 0, 64).unwrap(), b"ram-only");
        // EC-L05: volatile fsync returns L0 no-op success
        assert_eq!(
            engine.fsync("/tmp/sock.tmp").await.unwrap(),
            DurabilityLevel::L0
        );

        engine.mkdir("/etc", 0o755, 0, 0).unwrap();
        engine.create("/etc/hosts", 0o644, 0, 0).unwrap();
        engine
            .write("/etc/hosts", 0, b"127.0.0.1 localhost\n")
            .unwrap();

        // REQ-10: Cross-class rename or link returns EXDEV
        assert_eq!(
            engine
                .rename("/tmp/sock.tmp", "/etc/sock.tmp", 0)
                .unwrap_err()
                .errno,
            Errno::EXDEV
        );
        assert_eq!(
            engine
                .link("/tmp/sock.tmp", "/etc/sock.tmp")
                .unwrap_err()
                .errno,
            Errno::EXDEV
        );

        // 2. pjdfstest renameat2 conformance: RENAME_NOREPLACE, RENAME_EXCHANGE, ENOTEMPTY
        engine.create("/etc/hosts.new", 0o644, 0, 0).unwrap();
        engine
            .write("/etc/hosts.new", 0, b"::1 localhost\n")
            .unwrap();
        assert_eq!(
            engine
                .rename("/etc/hosts.new", "/etc/hosts", RENAME_NOREPLACE)
                .unwrap_err()
                .errno,
            Errno::EEXIST
        );
        engine
            .rename("/etc/hosts.new", "/etc/hosts", RENAME_EXCHANGE)
            .unwrap();
        assert_eq!(
            engine.read("/etc/hosts", 0, 64).unwrap(),
            b"::1 localhost\n"
        );
        assert_eq!(
            engine.read("/etc/hosts.new", 0, 64).unwrap(),
            b"127.0.0.1 localhost\n"
        );
        assert_eq!(engine.rmdir("/etc").unwrap_err().errno, Errno::ENOTEMPTY);

        // 3. Virtual .octoblock/status & .octoblock/policy.toml (REQ-13)
        let status_bytes = engine.read("/.octoblock/status", 0, 4096).unwrap();
        let status: StatusReport = serde_json::from_slice(&status_bytes).unwrap();
        assert_eq!(status.mode, MountMode::Balanced);
        assert_eq!(status.role, MountRole::Writer);
        assert_eq!(status.fsync_durability, DurabilityLevel::L1);
        assert!(status.journal_depth_ops > 0);

        // 4. Atomic region & remote L2 flush
        engine.atomic_begin().unwrap();
        engine.unlink("/etc/hosts.new").unwrap();
        engine.atomic_end().await.unwrap();
        assert_eq!(engine.status().journal_depth_ops, 0);
        assert!(engine.statfs().blocks > 0);
    }

    #[tokio::test]
    async fn phase_c_5000_crash_injection_points() {
        let remote = Arc::new(InMemory::new());
        let dir = tempfile::tempdir().unwrap();
        let cfg = EngineConfig {
            master_key: Some([0x7A; 32]),
            mode: MountMode::Balanced,
            ..EngineConfig::default()
        };
        let mut engine = WriteBackEngine::mkfs(
            remote.clone(),
            dir.path(),
            cfg.clone(),
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();

        let mut rng = fastrand::Rng::with_seed(0x5000_C0DE);
        let mut durable_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

        for point in 0..5_000 {
            let path = format!("/file_{}.bin", point % 64);
            let payload = vec![(point & 0xFF) as u8; 128 + (point % 512)];

            if engine.resolve_ino(&path).is_err() {
                engine.create(&path, 0o644, 1000, 1000).unwrap();
            } else {
                engine.truncate(&path, 0).unwrap();
            }
            engine.write(&path, 0, &payload).unwrap();
            let lvl = engine.fsync(&path).await.unwrap();
            assert_eq!(lvl, DurabilityLevel::L1);
            durable_files.insert(path.clone(), payload);

            match point % 25 {
                5 => {
                    let seg = engine.journal.active_segment_path();
                    if let Ok(mut f) = fs::OpenOptions::new().append(true).open(&seg) {
                        use std::io::Write;
                        let _ = f.write_all(&[0x99, 0x00, 0x00, 0x00, 0xDE, 0xAD]);
                    }
                    drop(engine);
                    engine = WriteBackEngine::mount(remote.clone(), dir.path(), cfg.clone())
                        .await
                        .unwrap();
                }
                10 => {
                    remote.inject(Fault::DropBeforeApply);
                    engine.sync_remote().await.unwrap();
                }
                15 => {
                    remote.inject(Fault::DropAfterApply);
                    engine.sync_remote().await.unwrap();
                }
                20 => {
                    engine.sync_remote().await.unwrap();
                    drop(engine);
                    engine = WriteBackEngine::mount(remote.clone(), dir.path(), cfg.clone())
                        .await
                        .unwrap();
                }
                _ => {
                    let _ = rng.u8(..);
                }
            }
        }

        engine.sync_remote().await.unwrap();
        let remounted = WriteBackEngine::mount(remote, dir.path(), cfg)
            .await
            .unwrap();
        for (path, expected_bytes) in &durable_files {
            let got = remounted
                .read(path, 0, expected_bytes.len() + 64)
                .unwrap();
            assert_eq!(
                &got, expected_bytes,
                "lost or corrupted L1/L2 data at {path}"
            );
        }
    }

    #[tokio::test]
    async fn phase_d_writer_lease_cas_and_follower_demotion() {
        let remote = Arc::new(InMemory::new());
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        let cfg1 = EngineConfig {
            mount_id: 101,
            holder_name: "writer-node-1".into(),
            ..EngineConfig::default()
        };
        let cfg2 = EngineConfig {
            mount_id: 202,
            holder_name: "writer-node-2".into(),
            ..EngineConfig::default()
        };

        // Mount 1 formats and acquires the writer lease on refs/octopage/lease.
        let mut m1 = WriteBackEngine::mkfs(
            remote.clone(),
            dir1.path(),
            cfg1,
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();
        assert_eq!(m1.role(), MountRole::Writer);
        m1.create("/hello.txt", 0o644, 1000, 1000).unwrap();
        m1.write("/hello.txt", 0, b"from-m1").unwrap();
        m1.sync_remote().await.unwrap();

        // EC-C03: Mount 2 mounts the same branch while Mount 1's lease is live -> demoted to Follower (EROFS).
        let mut m2 = WriteBackEngine::mount(remote.clone(), dir2.path(), cfg2.clone())
            .await
            .unwrap();
        assert_eq!(m2.role(), MountRole::Follower);
        assert_eq!(m2.read("/hello.txt", 0, 64).unwrap(), b"from-m1");
        assert_eq!(
            m2.create("/illegal.txt", 0o644, 1000, 1000)
                .unwrap_err()
                .errno,
            Errno::EROFS
        );

        // When Mount 1 cleanly unmounts and releases the lease, a new mount takes the Writer role.
        m1.unmount().await.unwrap();
        let mut m2_writer = WriteBackEngine::mount(remote, dir2.path(), cfg2)
            .await
            .unwrap();
        assert_eq!(m2_writer.role(), MountRole::Writer);
        m2_writer.write("/hello.txt", 0, b"from-m2").unwrap();
        m2_writer.sync_remote().await.unwrap();
    }

    #[tokio::test]
    async fn phase_d_fencing_on_expiry_and_lease_break_rebase() {
        let remote = Arc::new(InMemory::new());
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        let cfg1 = EngineConfig {
            mount_id: 1,
            holder_name: "laptop-1".into(),
            ..EngineConfig::default()
        };
        let cfg2 = EngineConfig {
            mount_id: 2,
            holder_name: "workstation-2".into(),
            ..EngineConfig::default()
        };

        let mut m1 = WriteBackEngine::mkfs(
            remote.clone(),
            dir1.path(),
            cfg1,
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();

        // Mount 2 starts as Follower, then forces a lease takeover (`octoblock lease break`, Section 7.2).
        let mut m2 = WriteBackEngine::mount(remote.clone(), dir2.path(), cfg2)
            .await
            .unwrap();
        assert_eq!(m2.role(), MountRole::Follower);
        m2.break_lease().await.unwrap();
        assert_eq!(m2.role(), MountRole::Writer);

        // Mount 2 writes and commits `/from_m2.txt` to the remote while Mount 1 is unaware.
        m2.create("/from_m2.txt", 0o644, 1000, 1000).unwrap();
        m2.write("/from_m2.txt", 0, b"committed-by-m2").unwrap();
        m2.sync_remote().await.unwrap();

        // EC-C04: Mount 1 tries to renew or sync -> discovers it lost the lease and becomes FENCED!
        // While FENCED, Mount 1 continues journaling writes locally (`L1`) without pushing.
        assert_eq!(m1.renew_lease().await.unwrap(), MountState::Fenced);
        m1.create("/from_m1_fenced.txt", 0o644, 1000, 1000).unwrap();
        m1.write("/from_m1_fenced.txt", 0, b"journaled-while-fenced")
            .unwrap();
        assert_eq!(
            m1.fsync("/from_m1_fenced.txt").await.unwrap(),
            DurabilityLevel::L1
        );
        // sync_remote on a FENCED mount keeps ops in the journal and does not push.
        m1.sync_remote().await.unwrap();
        assert_eq!(m1.status().state, MountState::Fenced);
        assert!(m1.status().journal_depth_ops > 0);

        // Now Mount 2 releases its lease, and Mount 1 reacquires the lease!
        // Mount 1 detects the head moved, fetches `/from_m2.txt`, replays `/from_m1_fenced.txt`
        // on top of the new head, and pushes both to the remote (`Section 7.2`, `EC-C04`).
        m2.unmount().await.unwrap();
        assert_eq!(m1.renew_lease().await.unwrap(), MountState::Syncing);
        m1.sync_remote().await.unwrap();
        assert_eq!(m1.status().state, MountState::Online);
        assert_eq!(
            m1.read("/from_m2.txt", 0, 64).unwrap(),
            b"committed-by-m2"
        );
        assert_eq!(
            m1.read("/from_m1_fenced.txt", 0, 64).unwrap(),
            b"journaled-while-fenced"
        );
    }
}