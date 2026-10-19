pub mod branch;
pub mod cli;
pub mod coalesce;
pub mod compact;
pub mod conflict;
pub mod daemon;
pub mod journal;
pub mod lease;
pub mod policy;
pub mod security;
pub mod vfs;

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

use crate::branch::{
    AsOfSelector, OpenFileTable, RefInfo, create_branch, create_snapshot, encode_snapshot_ino,
    list_branches, list_snapshots, resolve_as_of,
};
use crate::conflict::{
    ConflictLog, ConflictReason, ConflictRecord, MAX_CONSECUTIVE_RACES, RemoteDiffSummary,
};

use crate::coalesce::{AtomicRegion, coalesce_and_elide};
use crate::journal::{
    DEFAULT_JOURNAL_CAPACITY, JournalEntry, JournalRecordType, LocalJournal, OnJournalFull,
};
use crate::lease::{LeaseManager, LeaseOutcome, LeasePolicy, LeaseRecord, MountRole};
use crate::policy::PolicyEngine;
use crate::compact::{CompactionReport, archive_generation_tag, is_compacted_continuation};
use crate::security::{
    decrypt_page_obex, encrypt_page_obex, format_signed_commit_message, signer_fingerprint,
    verify_commit_signature,
};

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
    /// Soft live-bytes budget (`800 MB` default, Section 8.1).
    pub budget_soft: u64,
    /// Encrypt remote page blobs in `OBEX` envelopes using `master_key` (`Section 12.1`, `REQ-8`).
    pub encrypt_remote_pages: bool,
    /// Optional 32-byte commit-signing key (`Section 12.3`).
    pub signer_key: Option<[u8; 32]>,
    /// Required signer fingerprints (`Section 12.4`, `REQ-5`).
    pub pinned_signers: Vec<String>,
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
            budget_soft: octoblock_fs::DEFAULT_BUDGET_SOFT,
            encrypt_remote_pages: false,
            signer_key: None,
            pinned_signers: Vec::new(),
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
    conflicts: ConflictLog,
    consecutive_races: u32,
    open_files: OpenFileTable,
    snapshot_cache: BTreeMap<ObjectId, (u16, Volume)>,
    next_snapshot_slot: u16,
    generation: u64,
}

impl std::fmt::Debug for WriteBackEngine<std::sync::Arc<octopage_git::InMemory>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteBackEngine").finish_non_exhaustive()
    }
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
        vol.set_budget_soft(config.budget_soft);

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
            conflicts: ConflictLog::default(),
            consecutive_races: 0,
            open_files: OpenFileTable::default(),
            snapshot_cache: BTreeMap::new(),
            next_snapshot_slot: 1,
            generation: 1,
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

        let page_key = config
            .encrypt_remote_pages
            .then_some(config.master_key.as_ref())
            .flatten();
        let effective_signers = if !config.pinned_signers.is_empty() {
            &config.pinned_signers
        } else {
            &state_file.pinned_signers
        };
        let (pages, policy) = match Self::fetch_volume_from_remote_with_security(
            &transport,
            head,
            page_key,
            effective_signers,
            config.signer_key.as_ref(),
        )
        .await
        {
            Ok(res) => res,
            Err(e) if e.errno == Errno::EPERM => {
                return Err(Error::new(
                    Errno::EROFS,
                    format!("diverged / untrusted commit signer: {e}"),
                ));
            }
            Err(e) => return Err(e),
        };
        let mut vol = Volume::mount(pages, true, config.mount_id)?;

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
            conflicts: ConflictLog::default(),
            consecutive_races: 0,
            open_files: OpenFileTable::default(),
            snapshot_cache: BTreeMap::new(),
            next_snapshot_slot: 1,
            generation: 1,
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
            return Ok(());
        }

        if !Self::is_descendant(&self.transport, remote_head, self.head).await? {
            self.mount_state = MountState::Diverged;
            self.role = MountRole::Follower;
            return Err(Error::new(
                Errno::EROFS,
                "remote head diverged while mount was fenced (REQ-5)",
            ));
        }

        let remote_diff =
            Self::collect_remote_diff(&self.transport, remote_head, self.head).await?;
        let (pages, policy) = Self::fetch_volume_from_remote(&self.transport, remote_head).await?;
        let mut new_vol = Volume::mount(pages, true, self.config.mount_id)?;
        if self.config.lease_policy == LeasePolicy::Required {
            self.role = MountRole::Writer;
        }

        let (reopened_journal, entries) = LocalJournal::open(
            self.state_dir.join("journal"),
            self.config.master_key.as_ref(),
            self.config.journal_capacity,
            self.config.on_journal_full,
        )?;
        self.journal = reopened_journal;
        let mut ino_remap = BTreeMap::new();
        let mut ino_paths: BTreeMap<u64, String> = BTreeMap::from([(ROOT_INO, String::new())]);
        let mut conflicted_inodes: BTreeMap<u64, (u64, String)> = BTreeMap::new();
        let mut replayed_ops = Vec::new();
        let base_hex = self.head.to_hex();
        let remote_hex = remote_head.to_hex();
        let batch_id = format!(
            "epoch-{}-mount-{}",
            new_vol.superblock().epoch,
            self.config.mount_id
        );

        for entry in &entries {
            if entry.kind == JournalRecordType::Mutation {
                self.replay_entry_with_conflict_detection(
                    &mut new_vol,
                    entry,
                    &remote_diff,
                    &mut ino_remap,
                    &mut ino_paths,
                    &mut conflicted_inodes,
                    &batch_id,
                    &base_hex,
                    &remote_hex,
                )?;
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

    #[allow(clippy::too_many_arguments)]
    fn replay_entry_with_conflict_detection(
        &mut self,
        vol: &mut Volume,
        entry: &JournalEntry,
        remote_diff: &RemoteDiffSummary,
        ino_remap: &mut BTreeMap<u64, u64>,
        ino_paths: &mut BTreeMap<u64, String>,
        conflicted_inodes: &mut BTreeMap<u64, (u64, String)>,
        batch_id: &str,
        base_hex: &str,
        remote_hex: &str,
    ) -> Result<()> {
        let map_ino = |m: &BTreeMap<u64, u64>, ino: u64| m.get(&ino).copied().unwrap_or(ino);
        match &entry.op.kind {
            OpKind::Create {
                op_name,
                parent,
                name,
                mode,
                ino: recorded_ino,
                ..
            } => {
                let p_ino = map_ino(ino_remap, *parent);
                let parent_path = ino_paths.get(&p_ino).cloned().unwrap_or_default();
                let full_path = format!("{parent_path}/{name}");
                ino_paths.insert(*recorded_ino, full_path.clone());

                if remote_diff.created_names.contains(&(p_ino, name.clone()))
                    && op_name == "create"
                {
                    let conflict_name =
                        format!("{name}.conflict-{}-{}", self.config.mount_id, entry.seq);
                    let conflict_full = format!("{parent_path}/{conflict_name}");
                    let c_ino = vol.create(
                        p_ino,
                        conflict_name.as_bytes(),
                        *mode,
                        entry.op.uid,
                        entry.op.gid,
                    )?;
                    ino_remap.insert(*recorded_ino, c_ino);
                    conflicted_inodes.insert(*recorded_ino, (c_ino, conflict_full.clone()));
                    self.conflicts.push(ConflictRecord {
                        batch_id: batch_id.to_string(),
                        seq: entry.seq,
                        base_commit: base_hex.to_string(),
                        remote_commit: remote_hex.to_string(),
                        path: full_path,
                        preserved_copy: Some(conflict_full),
                        reason: ConflictReason::CreateCollision,
                    });
                    return Ok(());
                }

                Self::apply_recovered_entry(vol, entry, ino_remap)?;
                if let Some(&actual) = ino_remap.get(recorded_ino) {
                    ino_paths.insert(actual, full_path);
                }
            }
            OpKind::Write { ino, off, .. } => {
                if let Some(&(c_ino, _)) = conflicted_inodes.get(ino) {
                    let _ = vol.write(c_ino, *off, &entry.data);
                    return Ok(());
                }
                let t_ino = map_ino(ino_remap, *ino);
                let path = ino_paths
                    .get(&t_ino)
                    .cloned()
                    .unwrap_or_else(|| format!("/ino-{t_ino}"));

                let exists_on_remote = vol.getattr(t_ino).is_ok();
                if !exists_on_remote || remote_diff.modified_inodes.contains(&t_ino) {
                    let conflict_name =
                        format!("ino-{t_ino}.conflict-{}-{}", self.config.mount_id, entry.seq);
                    let conflict_path = format!("/{conflict_name}");
                    let c_ino = match vol.lookup(ROOT_INO, conflict_name.as_bytes()) {
                        Ok(existing) => existing,
                        Err(_) => vol.create(
                            ROOT_INO,
                            conflict_name.as_bytes(),
                            0o644,
                            entry.op.uid,
                            entry.op.gid,
                        )?,
                    };
                    let _ = vol.write(c_ino, *off, &entry.data);
                    conflicted_inodes.insert(*ino, (c_ino, conflict_path.clone()));
                    self.conflicts.push(ConflictRecord {
                        batch_id: batch_id.to_string(),
                        seq: entry.seq,
                        base_commit: base_hex.to_string(),
                        remote_commit: remote_hex.to_string(),
                        path,
                        preserved_copy: Some(conflict_path),
                        reason: if exists_on_remote {
                            ConflictReason::ConcurrentModify
                        } else {
                            ConflictReason::ModifyDeleted
                        },
                    });
                    return Ok(());
                }
                Self::apply_recovered_entry(vol, entry, ino_remap)?;
            }
            _ => {
                Self::apply_recovered_entry(vol, entry, ino_remap)?;
            }
        }
        Ok(())
    }

    async fn collect_remote_diff(
        transport: &T,
        remote_head: ObjectId,
        base_head: ObjectId,
    ) -> Result<RemoteDiffSummary> {
        let mut summary = RemoteDiffSummary::default();
        let commits = transport
            .history(remote_head, Some(base_head), false)
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("history: {e}")))?;

        for obj in commits {
            if obj.kind() != ObjectKind::Commit {
                continue;
            }
            let Ok(commit) = Commit::decode(obj.data()) else {
                continue;
            };
            let Ok(root_objs) = transport.fetch(&[commit.tree]).await else {
                continue;
            };
            let Ok(root_tree) = Tree::decode(root_objs[0].data()) else {
                continue;
            };
            if let Some(cl_entry) = root_tree.get(b"changelog")
                && let Ok(cl_objs) = transport.fetch(&[cl_entry.id]).await
            {
                summary.absorb_changelog(cl_objs[0].data());
            }
        }
        Ok(summary)
    }

    pub const fn conflicts(&self) -> &ConflictLog {
        &self.conflicts
    }

    pub const fn head_commit(&self) -> ObjectId {
        self.head
    }

    pub async fn mount_as_of(
        transport: T,
        state_dir: impl AsRef<Path>,
        mut config: EngineConfig,
        selector: AsOfSelector,
    ) -> Result<Self> {
        config.follow_only = true;
        let state_dir = state_dir.as_ref().to_path_buf();
        fs::create_dir_all(&state_dir)
            .map_err(|e| Error::new(Errno::EIO, format!("state_dir: {e}")))?;
        let local_sidecar_dir = state_dir.join("local_sidecar");
        fs::create_dir_all(&local_sidecar_dir)
            .map_err(|e| Error::new(Errno::EIO, format!("local_sidecar: {e}")))?;

        let commit_id = resolve_as_of(&transport, &config.branch, &selector).await?;
        let (pages, policy) = Self::fetch_volume_from_remote(&transport, commit_id).await?;
        let vol = Volume::mount(pages, false, config.mount_id)?;
        let (journal, _) = LocalJournal::open(
            state_dir.join("journal"),
            config.master_key.as_ref(),
            config.journal_capacity,
            config.on_journal_full,
        )?;
        let mount_uuid = format!("mount-{:016x}", config.mount_id);
        let lease_mgr = LeaseManager::new(&config.holder_name, mount_uuid, config.lease_policy);

        Ok(WriteBackEngine {
            transport,
            config,
            role: MountRole::Follower,
            lease_mgr,
            state_dir,
            local_sidecar_dir,
            state_file: LocalStateFile {
                last_seen_head: Some(commit_id.to_hex()),
                highest_epoch: vol.superblock().epoch,
                pinned_signers: Vec::new(),
            },
            mount_state: MountState::Online,
            vol,
            policy,
            journal,
            atomic: AtomicRegion::default(),
            volatile_files: BTreeMap::new(),
            group_ops: Vec::new(),
            dirty_bytes: 0,
            head: commit_id,
            pending_unknown_commit: None,
            remote_commits: 0,
            next_seq: 1,
            conflicts: ConflictLog::default(),
            consecutive_races: 0,
            open_files: OpenFileTable::default(),
            snapshot_cache: BTreeMap::new(),
            next_snapshot_slot: 1,
            generation: 1,
        })
    }

    pub async fn open_handle(&mut self, path: &str) -> Result<u64> {
        let _ = self.resolve_ino(path)?;
        let commit_id = self.head;
        self.ensure_snapshot_cached(commit_id).await?;
        Ok(self.open_files.open_handle(path.replace('\\', "/"), commit_id))
    }

    pub fn read_handle(&self, fh: u64, offset: u64, len: usize) -> Result<Vec<u8>> {
        let (path, pinned_commit) = self
            .open_files
            .get(fh)
            .ok_or_else(|| Error::new(Errno::EINVAL, "invalid file handle"))?;
        if *pinned_commit == self.head {
            return self.read(path, offset, len);
        }
        let (_, snap_vol) = self
            .snapshot_cache
            .get(pinned_commit)
            .ok_or_else(|| Error::new(Errno::EIO, "pinned snapshot missing from cache"))?;
        let ino = Self::resolve_ino_in_vol(snap_vol, path)?;
        snap_vol.read(ino, offset, len)
    }

    pub fn close_handle(&mut self, fh: u64) -> Result<()> {
        self.open_files
            .close_handle(fh)
            .ok_or_else(|| Error::new(Errno::EINVAL, "invalid file handle"))?;
        Ok(())
    }

    pub async fn poll_remote(&mut self) -> Result<bool> {
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
            return Ok(false);
        };
        if remote_head == self.head {
            return Ok(false);
        }
        if !Self::is_descendant(&self.transport, remote_head, self.head).await? {
            self.mount_state = MountState::Diverged;
            self.role = MountRole::Follower;
            return Err(Error::new(
                Errno::EROFS,
                "remote head diverged on poll (REQ-5)",
            ));
        }

        let old_head = self.head;
        if self.open_files.pinned_commits().contains(&old_head) {
            self.ensure_snapshot_cached(old_head).await?;
        }

        let (pages, policy) = Self::fetch_volume_from_remote(&self.transport, remote_head).await?;
        self.vol = Volume::mount(pages, true, self.config.mount_id)?;
        self.policy = policy;
        self.head = remote_head;
        self.save_state_file()?;
        Ok(true)
    }

    pub async fn create_branch(&self, name: &str) -> Result<RefInfo> {
        create_branch(&self.transport, name, self.head).await
    }

    pub async fn list_branches(&self) -> Result<Vec<RefInfo>> {
        list_branches(&self.transport).await
    }

    pub async fn switch_branch(&mut self, branch_name: &str) -> Result<()> {
        if !self.group_ops.is_empty() || self.journal.depth_ops() > 0 {
            self.sync_remote().await?;
        }
        let full_ref = if branch_name.starts_with("refs/heads/") {
            branch_name.to_string()
        } else {
            format!("refs/heads/{branch_name}")
        };
        let refs = self
            .transport
            .list_refs(&[&full_ref])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("list_refs: {e}")))?;
        let target_head = refs
            .into_iter()
            .find(|r| r.name == full_ref)
            .map(|r| r.id)
            .ok_or_else(|| Error::new(Errno::ENOENT, format!("branch {full_ref} not found")))?;

        let (pages, policy) = Self::fetch_volume_from_remote(&self.transport, target_head).await?;
        self.vol = Volume::mount(pages, true, self.config.mount_id)?;
        self.policy = policy;
        self.config.branch = full_ref;
        self.head = target_head;
        self.state_file.highest_epoch = self.vol.superblock().epoch;
        self.save_state_file()?;
        Ok(())
    }

    pub async fn create_snapshot(&self, name: &str) -> Result<RefInfo> {
        create_snapshot(&self.transport, name, self.head).await
    }

    pub async fn list_snapshots(&self) -> Result<Vec<RefInfo>> {
        list_snapshots(&self.transport).await
    }

    pub async fn merge_branch(
        &mut self,
        source_branch: &str,
        base_commit: ObjectId,
    ) -> Result<usize> {
        let full_ref = if source_branch.starts_with("refs/heads/") {
            source_branch.to_string()
        } else {
            format!("refs/heads/{source_branch}")
        };
        let refs = self
            .transport
            .list_refs(&[&full_ref])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("list_refs: {e}")))?;
        let source_tip = refs
            .into_iter()
            .find(|r| r.name == full_ref)
            .map(|r| r.id)
            .ok_or_else(|| Error::new(Errno::ENOENT, "source branch not found"))?;

        let (src_pages, _) = Self::fetch_volume_from_remote(&self.transport, source_tip).await?;
        let src_vol = Volume::mount(src_pages, false, self.config.mount_id)?;
        let (base_pages, _) = Self::fetch_volume_from_remote(&self.transport, base_commit).await?;
        let base_vol = Volume::mount(base_pages, false, self.config.mount_id)?;

        let applied = self.merge_tree_recursive(&base_vol, &src_vol, ROOT_INO, ROOT_INO, "")?;
        if applied > 0 {
            self.sync_remote().await?;
        }
        Ok(applied)
    }

    fn merge_tree_recursive(
        &mut self,
        base_vol: &Volume,
        src_vol: &Volume,
        base_dir_ino: u64,
        src_dir_ino: u64,
        prefix: &str,
    ) -> Result<usize> {
        let mut applied = 0usize;
        let entries = src_vol.readdir(src_dir_ino, 0)?;
        for entry in entries {
            let name_str = String::from_utf8_lossy(&entry.name);
            if name_str == "." || name_str == ".." {
                continue;
            }
            let full_path = format!("{prefix}/{name_str}");
            let src_attr = src_vol.getattr(entry.ino)?;
            let base_ino = if base_dir_ino != 0 {
                base_vol.lookup(base_dir_ino, &entry.name).ok()
            } else {
                None
            };

            if (src_attr.mode & S_IFDIR) == S_IFDIR {
                if self.resolve_ino(&full_path).is_err() {
                    self.mkdir(&full_path, src_attr.mode & 0o7777, src_attr.uid, src_attr.gid)?;
                    applied += 1;
                }
                applied += self.merge_tree_recursive(
                    base_vol,
                    src_vol,
                    base_ino.unwrap_or(0),
                    entry.ino,
                    &full_path,
                )?;
            } else if (src_attr.mode & S_IFREG) == S_IFREG {
                let src_bytes = src_vol.read(entry.ino, 0, src_attr.size as usize)?;
                let base_bytes = base_ino.and_then(|b_ino| {
                    let b_attr = base_vol.getattr(b_ino).ok()?;
                    base_vol.read(b_ino, 0, b_attr.size as usize).ok()
                });
                if base_bytes.as_ref() != Some(&src_bytes) {
                    let local_bytes = self.read(&full_path, 0, 1 << 20).ok();
                    if let Some(ref cur_local) = local_bytes
                        && base_bytes.as_ref() != Some(cur_local)
                        && cur_local != &src_bytes
                    {
                        let conflict_path = format!("{full_path}.conflict-merge");
                        if self.resolve_ino(&conflict_path).is_err() {
                            self.create(&conflict_path, 0o644, src_attr.uid, src_attr.gid)?;
                        }
                        self.write(&conflict_path, 0, &src_bytes)?;
                        self.conflicts.push(ConflictRecord {
                            batch_id: format!("merge-{}", self.vol.superblock().epoch),
                            seq: self.next_seq,
                            base_commit: self.head.to_hex(),
                            remote_commit: "branch-merge".into(),
                            path: full_path,
                            preserved_copy: Some(conflict_path),
                            reason: ConflictReason::ConcurrentModify,
                        });
                        applied += 1;
                    } else {
                        if self.resolve_ino(&full_path).is_err() {
                            self.create(
                                &full_path,
                                src_attr.mode & 0o7777,
                                src_attr.uid,
                                src_attr.gid,
                            )?;
                        } else {
                            self.truncate(&full_path, 0)?;
                        }
                        self.write(&full_path, 0, &src_bytes)?;
                        applied += 1;
                    }
                }
            }
        }
        Ok(applied)
    }

    async fn ensure_snapshot_cached(&mut self, commit_id: ObjectId) -> Result<(u16, &Volume)> {
        if !self.snapshot_cache.contains_key(&commit_id) {
            let (pages, _) = Self::fetch_volume_from_remote(&self.transport, commit_id).await?;
            let vol = Volume::mount(pages, false, self.config.mount_id)?;
            let slot = self.next_snapshot_slot;
            self.next_snapshot_slot = self.next_snapshot_slot.saturating_add(1).max(1);
            self.snapshot_cache.insert(commit_id, (slot, vol));
        }
        let (slot, vol) = self.snapshot_cache.get(&commit_id).unwrap();
        Ok((*slot, vol))
    }

    pub async fn read_snapshot_path(
        &mut self,
        snap_id_or_tag: &str,
        inner_path: &str,
        offset: u64,
        len: usize,
    ) -> Result<(u64, Vec<u8>)> {
        let commit_id = if let Ok(oid) = ObjectId::from_hex(snap_id_or_tag) {
            oid
        } else {
            resolve_as_of(
                &self.transport,
                &self.config.branch,
                &AsOfSelector::SnapshotTag(snap_id_or_tag.to_string()),
            )
            .await?
        };
        let (slot, snap_vol) = self.ensure_snapshot_cached(commit_id).await?;
        let local_ino = Self::resolve_ino_in_vol(snap_vol, inner_path)?;
        let data = snap_vol.read(local_ino, offset, len)?;
        Ok((encode_snapshot_ino(slot, local_ino), data))
    }

    fn resolve_ino_in_vol(vol: &Volume, path: &str) -> Result<u64> {
        let norm = path.replace('\\', "/");
        let parts: Vec<&str> = norm.split('/').filter(|p| !p.is_empty()).collect();
        let mut curr = ROOT_INO;
        for part in parts {
            curr = vol.lookup(curr, part.as_bytes())?;
        }
        Ok(curr)
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
        self.lease_mgr.release(&self.transport).await?;
        Ok(())
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
        is_compacted_continuation(transport, tip, ancestor).await
    }

    async fn fetch_volume_from_remote(
        transport: &T,
        commit_id: ObjectId,
    ) -> Result<(BTreeMap<PageId, Bytes>, PolicyEngine)> {
        Self::fetch_volume_from_remote_with_security(transport, commit_id, None, &[], None).await
    }

    async fn fetch_volume_from_remote_with_security(
        transport: &T,
        commit_id: ObjectId,
        master_key: Option<&[u8; 32]>,
        pinned_signers: &[String],
        signer_key: Option<&[u8; 32]>,
    ) -> Result<(BTreeMap<PageId, Bytes>, PolicyEngine)> {
        let commit_objs = transport
            .fetch(&[commit_id])
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("fetch commit: {e}")))?;
        let commit = Commit::decode(commit_objs[0].data())
            .map_err(|e| Error::new(Errno::EIO, format!("decode commit: {e}")))?;
        verify_commit_signature(
            &commit.message,
            commit.tree,
            &commit.parents,
            pinned_signers,
            signer_key,
        )?;
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
            let raw = by_oid
                .get(&oid)
                .ok_or_else(|| Error::new(Errno::EIO, format!("missing blob {oid}")))?;
            let decrypted = decrypt_page_obex(master_key, pid, raw)?;
            pages.insert(pid, decrypted);
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
                if self
                    .vol
                    .superblock()
                    .live_bytes
                    .saturating_add(data.len() as u64)
                    > self.config.budget_soft
                {
                    self.mount_state = MountState::DegradedQuota;
                    return Err(Error::new(
                        Errno::ENOSPC,
                        "live bytes would exceed volume soft budget (Section 8.1)",
                    ));
                }
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
        if norm == "/.octoblock/conflicts" || norm == "/.octoblock/conflicts/index.json" {
            let json = self.conflicts.to_json_bytes();
            let off = (offset as usize).min(json.len());
            let end = (off + len).min(json.len());
            return Ok(json[off..end].to_vec());
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
            return Ok(());
        }
        if self.group_ops.is_empty() && self.journal.depth_ops() == 0 {
            return Ok(());
        }

        if self.config.lease_policy == LeasePolicy::Required {
            self.renew_lease().await?;
            if self.mount_state == MountState::Fenced {
                self.journal.barrier()?;
                return Ok(());
            }
        }

        self.journal.barrier()?;
        for _race in 0..=MAX_CONSECUTIVE_RACES {
            let coalesced = coalesce_and_elide(&self.group_ops);
            let changelog = encode_changelog(&coalesced);
            let _ = self.vol.commit_group()?;
            match self.push_volume_state(&changelog, false).await {
                Ok(()) => {
                    self.group_ops.clear();
                    self.dirty_bytes = 0;
                    self.journal.truncate_committed()?;
                    self.consecutive_races = 0;
                    self.mount_state = MountState::Online;
                    self.save_state_file()?;
                    return Ok(());
                }
                Err(e) if e.errno == Errno::EAGAIN => {
                    self.consecutive_races += 1;
                    if self.consecutive_races >= MAX_CONSECUTIVE_RACES {
                        self.mount_state = MountState::Contended;
                        return Err(Error::new(
                            Errno::EAGAIN,
                            "8 consecutive CAS races lost; mount is CONTENDED (Section 7.3)",
                        ));
                    }
                    self.reconcile_after_fencing().await?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Squash the remote commit history into a single root commit containing only the live `OBF1`
    /// pages of the volume, optionally archiving the previous chain under `refs/tags/octoblock/gen-<N>`
    /// (`octoblock compact`, Section 8.2, `REQ-6`).
    pub async fn compact_history(&mut self, archive_generation: bool) -> Result<CompactionReport> {
        if self.role == MountRole::Follower {
            return Err(Error::new(Errno::EROFS, "follower mount cannot compact"));
        }
        if !self.group_ops.is_empty() || self.journal.depth_ops() > 0 {
            self.sync_remote().await?;
        }

        let old_head = self.head;
        let generation = self.generation;
        let archived_ref = if archive_generation && !old_head.is_zero() {
            Some(archive_generation_tag(&self.transport, generation, old_head).await?)
        } else {
            None
        };

        // Advance volume epoch so the compacted root commit has strictly higher epoch (REQ-5).
        let _ = self.vol.commit_group()?;
        let epoch = self.vol.superblock().epoch;

        // Build squashed root commit (`parents: Vec::new()`) with `Compacted-From: <old_head>` trailer.
        let pages = self.vol.clone_storage();
        let mut new_objects: Vec<NewObject> = Vec::new();
        let mut by_a: BTreeMap<u8, BTreeMap<u8, Vec<(u8, ObjectId)>>> = BTreeMap::new();
        for (pid, raw_bytes) in pages {
            let payload = if self.config.encrypt_remote_pages {
                let key = self.config.master_key.as_ref().ok_or_else(|| {
                    Error::new(Errno::EINVAL, "encrypt_remote_pages requires master_key")
                })?;
                encrypt_page_obex(key, pid, epoch, &raw_bytes)
            } else {
                raw_bytes
            };
            let blob =
                Object::blob(payload).map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
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

        let changelog_obj = Object::blob(Bytes::from_static(
            b"{\"seq\":0,\"t\":0.0,\"op\":\"barrier\",\"kind\":\"compact_root\"}\n",
        ))
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

        let commit_time = 1_791_371_000 + (epoch as i64);
        let sig = Signature::new("octoblock", "octoblock@example.invalid", commit_time);
        let base_msg = format!(
            "octoblock group epoch {epoch}\nCompacted-From: {}\nGeneration: {generation}",
            old_head.to_hex()
        );
        let message = if let Some(ref sk) = self.config.signer_key {
            format_signed_commit_message(&base_msg, sk, root_tree_obj.id(), &[], epoch)
        } else {
            format!("{base_msg}\n").into_bytes()
        };
        let commit_obj = Commit {
            tree: root_tree_obj.id(),
            parents: Vec::new(),
            author: sig.clone(),
            committer: sig,
            message,
        }
        .to_object()
        .map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        let new_head = commit_obj.id();
        new_objects.push(commit_obj.into());

        let update = RefUpdate::update(&self.config.branch, old_head, new_head);
        self.transport
            .push(&[update], &new_objects)
            .await
            .map_err(|e| Error::new(Errno::EIO, format!("compact push failed: {e}")))?;

        self.head = new_head;
        self.generation += 1;
        self.remote_commits += 1;
        self.save_state_file()?;

        Ok(CompactionReport {
            generation,
            archived_ref,
            old_head: old_head.to_hex(),
            new_head: new_head.to_hex(),
            epoch,
            live_bytes: self.vol.superblock().live_bytes,
        })
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

        let epoch = self.vol.superblock().epoch;
    for (pid, raw_bytes) in pages {
        let payload = if self.config.encrypt_remote_pages {
            let key = self.config.master_key.as_ref().ok_or_else(|| {
                Error::new(Errno::EINVAL, "encrypt_remote_pages requires master_key")
        })?;
        encrypt_page_obex(key, pid, epoch, &raw_bytes)
    } else {
        raw_bytes
    };

    let blob =
        Object::blob(payload).map_err(|e| Error::new(Errno::EIO, e.to_string()))?;

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

        let commit_time = 1_791_371_000 + (epoch as i64);
    let sig = Signature::new("octoblock", "octoblock@example.invalid", commit_time);
    let parents = if initial || self.head.is_zero() {
        Vec::new()
    } else {
        vec![self.head]
    };
    let base_msg = format!("octoblock group epoch {epoch}");
    let message = if let Some(ref sk) = self.config.signer_key {
        let fp = signer_fingerprint(sk);
        if !self.state_file.pinned_signers.contains(&fp) {
           self.state_file.pinned_signers.push(fp);
        }
        format_signed_commit_message(&base_msg, sk, root_tree_obj.id(), &parents, epoch)
    } else {
        format!("{base_msg}\n").into_bytes()
    };
    let commit_obj = Commit {
       tree: root_tree_obj.id(),
       parents,
       author: sig.clone(),
       committer: sig,
       message,
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
                Err(octopage_git::Error::Conflict { .. }) => {
                    return Err(Error::new(Errno::EAGAIN, "remote head CAS conflict"));
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
        if self.vol.superblock().live_bytes >= self.config.budget_soft {
            self.mount_state = MountState::DegradedQuota;
            return;
        }
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

    #[tokio::test]
    async fn phase_d_multi_writer_replay_and_conflict_records() {
        let remote = Arc::new(InMemory::new());
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        let cfg1 = EngineConfig {
            mount_id: 10,
            lease_policy: LeasePolicy::Advisory,
            holder_name: "mw-1".into(),
            ..EngineConfig::default()
        };
        let cfg2 = EngineConfig {
            mount_id: 20,
            lease_policy: LeasePolicy::Advisory,
            holder_name: "mw-2".into(),
            ..EngineConfig::default()
        };

        let mut mw1 = WriteBackEngine::mkfs(
            remote.clone(),
            dir1.path(),
            cfg1,
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();
        let mut mw2 = WriteBackEngine::mount(remote.clone(), dir2.path(), cfg2)
            .await
            .unwrap();
        assert_eq!(mw1.role(), MountRole::MultiWriter);
        assert_eq!(mw2.role(), MountRole::MultiWriter);

        mw1.create("/only_mw1.txt", 0o644, 1000, 1000).unwrap();
        mw1.write("/only_mw1.txt", 0, b"mw1-clean").unwrap();
        mw1.create("/shared.conf", 0o644, 1000, 1000).unwrap();
        mw1.write("/shared.conf", 0, b"winner-version").unwrap();
        mw1.sync_remote().await.unwrap();

        mw2.create("/only_mw2.txt", 0o644, 1000, 1000).unwrap();
        mw2.write("/only_mw2.txt", 0, b"mw2-clean").unwrap();
        mw2.create("/shared.conf", 0o644, 1000, 1000).unwrap();
        mw2.write("/shared.conf", 0, b"loser-preserved-version")
            .unwrap();
        mw2.sync_remote().await.unwrap();

        assert_eq!(mw2.read("/only_mw1.txt", 0, 64).unwrap(), b"mw1-clean");
        assert_eq!(mw2.read("/only_mw2.txt", 0, 64).unwrap(), b"mw2-clean");
        assert_eq!(
            mw2.read("/shared.conf", 0, 64).unwrap(),
            b"winner-version"
        );

        assert_eq!(mw2.conflicts().len(), 1);
        let rec = &mw2.conflicts().records[0];
        assert_eq!(rec.path, "/shared.conf");
        assert_eq!(rec.reason, ConflictReason::CreateCollision);
        let preserved_path = rec.preserved_copy.as_ref().unwrap();
        assert_eq!(
            mw2.read(preserved_path, 0, 64).unwrap(),
            b"loser-preserved-version"
        );
        let conflict_json = mw2.read("/.octoblock/conflicts/index.json", 0, 4096).unwrap();
        assert!(String::from_utf8_lossy(&conflict_json).contains("create_collision"));
    }

    #[tokio::test]
    async fn phase_d_follower_close_to_open_coherence() {
        let remote = Arc::new(InMemory::new());
        let dir_w = tempfile::tempdir().unwrap();
        let dir_f = tempfile::tempdir().unwrap();

        let mut writer = WriteBackEngine::mkfs(
            remote.clone(),
            dir_w.path(),
            EngineConfig {
                mount_id: 1,
                ..EngineConfig::default()
            },
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();
        writer.create("/data.log", 0o644, 1000, 1000).unwrap();
        writer.write("/data.log", 0, b"version-1").unwrap();
        writer.sync_remote().await.unwrap();

        let mut follower = WriteBackEngine::mount(
            remote.clone(),
            dir_f.path(),
            EngineConfig {
                mount_id: 2,
                follow_only: true,
                ..EngineConfig::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(follower.role(), MountRole::Follower);

        let fh_v1 = follower.open_handle("/data.log").await.unwrap();
        assert_eq!(follower.read_handle(fh_v1, 0, 64).unwrap(), b"version-1");

        writer.truncate("/data.log", 0).unwrap();
        writer.write("/data.log", 0, b"version-2").unwrap();
        writer.sync_remote().await.unwrap();

        assert!(follower.poll_remote().await.unwrap());
        assert_eq!(follower.read_handle(fh_v1, 0, 64).unwrap(), b"version-1");
        let fh_v2 = follower.open_handle("/data.log").await.unwrap();
        assert_eq!(follower.read_handle(fh_v2, 0, 64).unwrap(), b"version-2");
        follower.close_handle(fh_v1).unwrap();
        follower.close_handle(fh_v2).unwrap();
    }

    #[tokio::test]
    async fn phase_d_branches_snapshots_time_travel_and_merge() {
        let remote = Arc::new(InMemory::new());
        let dir = tempfile::tempdir().unwrap();
        let dir_as_of = tempfile::tempdir().unwrap();

        let mut engine = WriteBackEngine::mkfs(
            remote.clone(),
            dir.path(),
            EngineConfig {
                mount_id: 1,
                lease_policy: LeasePolicy::Off,
                ..EngineConfig::default()
            },
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();

        engine.create("/readme.md", 0o644, 1000, 1000).unwrap();
        engine.write("/readme.md", 0, b"v1-baseline").unwrap();
        engine.sync_remote().await.unwrap();
        let base_commit = engine.head_commit();

        engine.create_snapshot("v1.0").await.unwrap();
        assert_eq!(engine.list_snapshots().await.unwrap().len(), 1);

        engine.create_branch("feature").await.unwrap();
        assert_eq!(engine.list_branches().await.unwrap().len(), 2);
        engine.switch_branch("feature").await.unwrap();
        engine.create("/feature.txt", 0o644, 1000, 1000).unwrap();
        engine.write("/feature.txt", 0, b"feature-work").unwrap();
        engine.sync_remote().await.unwrap();

        engine.switch_branch("main").await.unwrap();
        assert!(engine.resolve_ino("/feature.txt").is_err());
        engine.truncate("/readme.md", 0).unwrap();
        engine.write("/readme.md", 0, b"v2-updated-on-main").unwrap();
        engine.sync_remote().await.unwrap();

        let (snap_ino, snap_bytes) = engine
            .read_snapshot_path("v1.0", "/readme.md", 0, 64)
            .await
            .unwrap();
        assert_eq!(snap_bytes, b"v1-baseline");
        let (slot, _local_ino) = crate::branch::decode_snapshot_ino(snap_ino);
        assert!(slot >= 1, "snapshot inode must have non-zero high 16-bit slot");

        let time_travel = WriteBackEngine::mount_as_of(
            remote.clone(),
            dir_as_of.path(),
            EngineConfig::default(),
            AsOfSelector::Commit(base_commit),
        )
        .await
        .unwrap();
        assert_eq!(
            time_travel.read("/readme.md", 0, 64).unwrap(),
            b"v1-baseline"
        );

        let merged_ops = engine.merge_branch("feature", base_commit).await.unwrap();
        assert!(merged_ops > 0);
        assert_eq!(
            engine.read("/feature.txt", 0, 64).unwrap(),
            b"feature-work"
        );
    }
    #[tokio::test]
    async fn phase_e_remote_page_encryption_and_tamper_detection() {
        let remote = Arc::new(InMemory::new());
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let key = [0xA5; 32];

        let cfg = EngineConfig {
            master_key: Some(key),
            encrypt_remote_pages: true,
            lease_policy: LeasePolicy::Off,
            ..EngineConfig::default()
        };

        let mut m1 = WriteBackEngine::mkfs(
            remote.clone(),
            dir1.path(),
            cfg.clone(),
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();
        m1.create("/secret.txt", 0o644, 1000, 1000).unwrap();
        m1.write("/secret.txt", 0, b"confidential-obex-payload")
            .unwrap();
        m1.sync_remote().await.unwrap();

        // Mounting without master_key or with wrong key MUST fail (REQ-8).
        let bad_cfg = EngineConfig {
            master_key: Some([0xFF; 32]),
            encrypt_remote_pages: true,
            lease_policy: LeasePolicy::Off,
            ..EngineConfig::default()
        };
        assert!(WriteBackEngine::mount(remote.clone(), dir2.path(), bad_cfg)
            .await
            .is_err());

        // Mounting with the correct key decrypts all OBEX pages cleanly.
        let m2 = WriteBackEngine::mount(remote, dir2.path(), cfg)
            .await
            .unwrap();
        assert_eq!(
            m2.read("/secret.txt", 0, 64).unwrap(),
            b"confidential-obex-payload"
        );
    }

    #[tokio::test]
    async fn phase_e_commit_signing_pinned_signers_and_anti_rollback() {
        let remote = Arc::new(InMemory::new());
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let good_key = [0x11; 32];
        let attacker_key = [0x99; 32];
        let good_fp = crate::security::signer_fingerprint(&good_key);

        let cfg1 = EngineConfig {
            signer_key: Some(good_key),
            pinned_signers: vec![good_fp.clone()],
            lease_policy: LeasePolicy::Off,
            ..EngineConfig::default()
        };

        let mut m1 = WriteBackEngine::mkfs(
            remote.clone(),
            dir1.path(),
            cfg1.clone(),
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();
        let early_commit = m1.head_commit();

        m1.create("/signed.txt", 0o644, 1000, 1000).unwrap();
        m1.write("/signed.txt", 0, b"epoch-advance").unwrap();
        m1.sync_remote().await.unwrap();
        let latest_commit = m1.head_commit();

        // 1. Pinned signer check: mounting with a different pinned signer rejects the commit (REQ-5).
        let wrong_pin_cfg = EngineConfig {
            pinned_signers: vec![crate::security::signer_fingerprint(&attacker_key)],
            lease_policy: LeasePolicy::Off,
            ..EngineConfig::default()
        };
        assert_eq!(
            WriteBackEngine::mount(remote.clone(), dir2.path(), wrong_pin_cfg)
                .await
                .unwrap_err()
                .errno,
            Errno::EROFS
        );

        // 2. Anti-rollback check (REQ-5): force-resetting the remote branch back to `early_commit`
        // causes `m1`'s next mount with its `state.json` to detect epoch regression and enter DIVERGED!
        remote
            .push(
                &[RefUpdate::update("refs/heads/main", latest_commit, early_commit)],
                &[],
            )
            .await
            .unwrap();
        let remounted = WriteBackEngine::mount(remote, dir1.path(), cfg1)
            .await
            .unwrap();
        assert_eq!(remounted.status().state, MountState::Diverged);
        assert_eq!(remounted.role(), MountRole::Follower);
    }

    #[tokio::test]
    async fn phase_e_quota_budget_and_history_compaction() {
        let remote = Arc::new(InMemory::new());
        let dir = tempfile::tempdir().unwrap();

        // Configure a tight 64 KiB soft budget to test quota enforcement and compaction recovery.
        let cfg = EngineConfig {
            budget_soft: 64 * 1024,
            lease_policy: LeasePolicy::Off,
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

        engine.create("/big.bin", 0o644, 1000, 1000).unwrap();
        // Write a payload larger than the 64 KiB budget (e.g. 128 KiB) to trigger ENOSPC directly
        let res = engine.write("/big.bin", 0, &vec![0xAB; 128 * 1024]);
        assert_eq!(res.unwrap_err().errno, Errno::ENOSPC);

        // Create a smaller file that fits within the budget
        engine.create("/kept.txt", 0o644, 1000, 1000).unwrap();
        engine.write("/kept.txt", 0, b"survives-compaction").unwrap();
        engine.sync_remote().await.unwrap();

        // Compact history with generation archive tag (`refs/tags/octoblock/gen-1`, Section 8.2).
        let report = engine.compact_history(true).await.unwrap();
        assert_eq!(report.generation, 1);
        assert_eq!(
            report.archived_ref.as_deref(),
            Some("refs/tags/octoblock/gen-1")
        );

        // Remount after compaction: anti-rollback recognizes `Compacted-From` and reads `/kept.txt`.
        drop(engine);
        let remounted = WriteBackEngine::mount(remote, dir.path(), cfg)
            .await
            .unwrap();
        assert_eq!(remounted.status().state, MountState::Online);
        assert_eq!(
            remounted.read("/kept.txt", 0, 64).unwrap(),
            b"survives-compaction"
        );
    }
    #[tokio::test]
    async fn phase_f_vfs_virtual_namespace_ioctls_and_cli_commands() {
        use crate::cli::{CliCommand, execute_cli};
        use crate::vfs::{
            OBX_IOC_ATOMIC_BEGIN, OBX_IOC_ATOMIC_END, VINO_OCTOBLOCK_DIR, VfsSession,
        };

        let remote = Arc::new(InMemory::new());
        let dir = tempfile::tempdir().unwrap();
        let cfg = EngineConfig {
            lease_policy: LeasePolicy::Off,
            ..EngineConfig::default()
        };
        let engine = WriteBackEngine::mkfs(
            remote,
            dir.path(),
            cfg,
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();

        let mut vfs = VfsSession::new(engine);

        // 1. VFS lookup reference counting & virtual /.octoblock directory
        let vino = vfs.lookup("/.octoblock").await.unwrap();
        assert_eq!(vino, VINO_OCTOBLOCK_DIR);
        assert_eq!(vfs.lookup_count(vino), 1);
        vfs.forget(vino, 1);
        assert_eq!(vfs.lookup_count(vino), 0);

        let entries = vfs.readdir("/.octoblock", 0).await.unwrap();
        assert_eq!(entries.len(), 4);

        // 2. Virtual /.octoblock namespace is strictly read-only (EROFS)
        assert_eq!(
            vfs.create("/.octoblock/hack", 0o644, 0, 0)
                .unwrap_err()
                .errno,
            Errno::EROFS
        );

        // 3. Atomic transaction via VFS ioctl (OBX_IOC_ATOMIC_BEGIN / OBX_IOC_ATOMIC_END)
        vfs.ioctl(OBX_IOC_ATOMIC_BEGIN).await.unwrap();
        vfs.create("/app.toml", 0o644, 1000, 1000).unwrap();
        vfs.write("/app.toml", 0, b"version = 1\n").unwrap();
        vfs.ioctl(OBX_IOC_ATOMIC_END).await.unwrap();

        // 4. Control-plane CLI execution (`snapshot create`, `status --json`, `fsck`)
        let snap_out = execute_cli(
            vfs.engine_mut(),
            CliCommand::parse_args(&["snapshot", "create", "rel-1"]).unwrap(),
        )
        .await
        .unwrap();
        assert!(snap_out.contains("refs/tags/octoblock/rel-1"));

        // Overwrite live `/app.toml` and read historical version through VFS `/.octoblock/snapshots/rel-1/app.toml`
        vfs.write("/app.toml", 0, b"version = 2\n").unwrap();
        let snap_bytes = vfs
            .read("/.octoblock/snapshots/rel-1/app.toml", 0, 64)
            .await
            .unwrap();
        assert_eq!(snap_bytes, b"version = 1\n");

        let fsck_out = execute_cli(vfs.engine_mut(), CliCommand::parse_args(&["fsck"]).unwrap())
            .await
            .unwrap();
        assert!(fsck_out.contains("fsck clean=true"));
    }
    #[tokio::test]
    async fn phase_g_fuse_inode_dispatcher_and_daemon_background_ticks() {
        use crate::daemon::FuseDispatcher;
        use crate::vfs::OBX_IOC_SYNC_L2;

        let remote = Arc::new(InMemory::new());
        let dir_w = tempfile::tempdir().unwrap();
        let dir_f = tempfile::tempdir().unwrap();

        // Writer daemon configured with a 1 KiB auto-flush threshold
        let writer_engine = WriteBackEngine::mkfs(
            remote.clone(),
            dir_w.path(),
            EngineConfig {
                mount_id: 1,
                flush_bytes: 1024,
                ..EngineConfig::default()
            },
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();
        let mut writer_daemon = FuseDispatcher::new(writer_engine, 1024);

        //Follower daemon mounted on the same remote
        let follower_engine = WriteBackEngine::mount(
            remote.clone(),
            dir_f.path(),
            EngineConfig {
                mount_id: 2,
                follow_only: true,
                ..EngineConfig::default()
            },
        )
        .await
        .unwrap();
        let mut follower_daemon = FuseDispatcher::new(follower_engine, 1024);

        // 1. FUSE mkdir, create, write, and lookup by (parent_ino, name)
        let docs_ino = writer_daemon
            .fuse_mkdir(ROOT_INO, "docs", 0o755, 1000, 1000)
            .await
            .unwrap();
        let (file_ino, fh) = writer_daemon
            .fuse_create(docs_ino, "spec.md", 0o644, 1000, 1000)
            .await
            .unwrap();
        let payload = vec![b'X'; 2048];
        writer_daemon.fuse_write(file_ino, 0, &payload).unwrap();
        writer_daemon.fuse_release(fh).unwrap();

        // 2. Writer background_tick detects dirty_group_bytes >= 1024 and auto-flushes to L2!
        let w_tick = writer_daemon.background_tick(false).await.unwrap();
        assert!(w_tick.flushed_l2);
        assert_eq!(writer_daemon.engine().status().journal_depth_ops, 0);

        // 3. Follower background_tick polls the remote and pulls the new commit
        let f_tick = follower_daemon.background_tick(false).await.unwrap();
        assert!(f_tick.pulled_remote);

        let (f_docs_ino, _) = follower_daemon.fuse_lookup(ROOT_INO, "docs").await.unwrap();
        let (f_file_ino, attr) = follower_daemon
            .fuse_lookup(f_docs_ino, "spec.md")
            .await
            .unwrap();
        assert_eq!(attr.size, 2048);

        let f_fh = follower_daemon.fuse_open(f_file_ino).await.unwrap();
        let read_back = follower_daemon
            .fuse_read(f_file_ino, Some(f_fh), 0, 2048)
            .await
            .unwrap();
        assert_eq!(read_back, payload);
        follower_daemon.fuse_release(f_fh).unwrap();

        // 4. Rename & ioctl sync via FuseDispatcher, then clean daemon shutdown
        writer_daemon
            .fuse_rename(docs_ino, "spec.md", docs_ino, "final.md", 0)
            .unwrap();
        writer_daemon.fuse_ioctl(OBX_IOC_SYNC_L2).await.unwrap();
        writer_daemon.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn phase_h_multi_node_chaos_stress_and_end_to_end_verification() {
        let remote = Arc::new(InMemory::new());
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let dir_f = tempfile::tempdir().unwrap();

        let shared_key = [0x5A; 32];
        let signer = [0x3C; 32];
        let pin = crate::security::signer_fingerprint(&signer);

        let cfg_a = EngineConfig {
            mount_id: 100,
            lease_policy: LeasePolicy::Advisory,
            holder_name: "chaos-mw-a".into(),
            master_key: Some(shared_key),
            signer_key: Some(signer),
            pinned_signers: vec![pin.clone()],
            ..EngineConfig::default()
        };
        let cfg_b = EngineConfig {
            mount_id: 200,
            lease_policy: LeasePolicy::Advisory,
            holder_name: "chaos-mw-b".into(),
            master_key: Some(shared_key),
            signer_key: Some(signer),
            pinned_signers: vec![pin.clone()],
            ..EngineConfig::default()
        };
        let cfg_f = EngineConfig {
            mount_id: 300,
            follow_only: true,
            holder_name: "chaos-follower".into(),
            master_key: Some(shared_key),
            signer_key: Some(signer),
            pinned_signers: vec![pin],
            ..EngineConfig::default()
        };

        let mut node_a = WriteBackEngine::mkfs(
            remote.clone(),
            dir_a.path(),
            cfg_a,
            4096,
            CasePolicy::Sensitive,
            PolicyEngine::tier0_default(),
        )
        .await
        .unwrap();
        node_a.create("/anchor.txt", 0o644, 1000, 1000).unwrap();
        node_a.write("/anchor.txt", 0, b"gen-0-anchor").unwrap();
        node_a.sync_remote().await.unwrap();

        let mut node_b = WriteBackEngine::mount(remote.clone(), dir_b.path(), cfg_b)
            .await
            .unwrap();
        let mut follower = WriteBackEngine::mount(remote.clone(), dir_f.path(), cfg_f.clone())
            .await
            .unwrap();

        // Pin an open file handle on the follower before the chaos rounds begin
        let pinned_fh = follower.open_handle("/anchor.txt").await.unwrap();

        for round in 0..40usize {
            let path_a = format!("/node_a_{round}.dat");
            let path_b = format!("/node_b_{round}.dat");
            let payload_a = format!("a-round-{round}").into_bytes();
            let payload_b = format!("b-round-{round}").into_bytes();

            node_a.create(&path_a, 0o644, 1000, 1000).unwrap();
            node_a.write(&path_a, 0, &payload_a).unwrap();

            node_b.create(&path_b, 0o644, 1000, 1000).unwrap();
            node_b.write(&path_b, 0, &payload_b).unwrap();

            // Every 10th round, both nodes contend on the same new path to trigger conflict preservation
            if round % 10 == 0 {
                let contested = format!("/contested_{round}.conf");
                node_a.create(&contested, 0o644, 1000, 1000).unwrap();
                node_a.write(&contested, 0, b"winner-a").unwrap();

                node_b.create(&contested, 0o644, 1000, 1000).unwrap();
                node_b.write(&contested, 0, b"preserved-b").unwrap();
            }

            // Inject transport faults during remote sync
            if round % 5 == 1 {
                remote.inject(Fault::DropBeforeApply);
            } else if round % 5 == 3 {
                remote.inject(Fault::DropAfterApply);
            }
            node_a.sync_remote().await.unwrap();

            if round % 7 == 2 {
                remote.inject(Fault::DropAfterApply);
            }
            node_b.sync_remote().await.unwrap();

            if round % 8 == 0 {
                let _ = follower.poll_remote().await.unwrap();
                // Pinned handle still reads the original snapshot content
                assert_eq!(
                    follower.read_handle(pinned_fh, 0, 64).unwrap(),
                    b"gen-0-anchor"
                );
            }
        }

        // Sync Node A with Node B's latest commits and compact history into Generation 1
        node_a.create("/final_a.txt", 0o644, 1000, 1000).unwrap();
        node_a.write("/final_a.txt", 0, b"done").unwrap();
        node_a.sync_remote().await.unwrap();

        let report = node_a.compact_history(true).await.unwrap();
        assert_eq!(report.generation, 1);
        assert_eq!(
            report.archived_ref.as_deref(),
            Some("refs/tags/octoblock/gen-1")
        );

        // Follower polls across the compacted root commit and verifies all 80 per-node files + conflicts
        follower.close_handle(pinned_fh).unwrap();
        assert!(follower.poll_remote().await.unwrap());
        assert_eq!(node_b.conflicts().len(), 4);

        for round in 0..40usize {
            let path_a = format!("/node_a_{round}.dat");
            let path_b = format!("/node_b_{round}.dat");
            assert_eq!(
                follower.read(&path_a, 0, 64).unwrap(),
                format!("a-round-{round}").as_bytes()
            );
            assert_eq!(
                follower.read(&path_b, 0, 64).unwrap(),
                format!("b-round-{round}").as_bytes()
            );
        }
    }
}