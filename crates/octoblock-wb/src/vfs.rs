use std::collections::BTreeMap;

use octoblock_fs::tree::InodeRecord;
use octoblock_fs::{Errno, Error, ROOT_INO, Result, S_IFDIR, S_IFREG};
use octopage_git::Transport;

use crate::{DurabilityLevel, StatFs, WriteBackEngine};

pub const VINO_OCTOBLOCK_DIR: u64 = 0xFFFF_0000_0000_0001;
pub const VINO_STATUS_FILE: u64 = 0xFFFF_0000_0000_0002;
pub const VINO_POLICY_FILE: u64 = 0xFFFF_0000_0000_0003;
pub const VINO_CONFLICTS_DIR: u64 = 0xFFFF_0000_0000_0004;
pub const VINO_CONFLICTS_INDEX: u64 = 0xFFFF_0000_0000_0005;
pub const VINO_SNAPSHOTS_DIR: u64 = 0xFFFF_0000_0000_0006;

pub const OBX_IOC_ATOMIC_BEGIN: u32 = 0x4F42_5801;
pub const OBX_IOC_ATOMIC_END: u32 = 0x4F42_5802;
pub const OBX_IOC_SYNC_L2: u32 = 0x4F42_5803;

/// VFS directory entry returned by [`VfsSession::readdir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VfsDirEntry {
    /// Inode number (live or virtual).
    pub ino: u64,
    /// Entry filename bytes.
    pub name: Vec<u8>,
}

/// User-space VFS / FUSE dispatcher wrapping [`WriteBackEngine`].
pub struct VfsSession<T: Transport> {
    engine: WriteBackEngine<T>,
    /// Tracks kernel FUSE lookup reference counts per inode (`lookup` increments, `forget` decrements).
    lookup_counts: BTreeMap<u64, u64>,
}

impl<T: Transport> VfsSession<T> {
    /// Wrap an initialized [`WriteBackEngine`] in a Layer 5 [`VfsSession`].
    pub fn new(engine: WriteBackEngine<T>) -> Self {
        let mut lookup_counts = BTreeMap::new();
        lookup_counts.insert(ROOT_INO, 1);
        VfsSession {
            engine,
            lookup_counts,
        }
    }

    /// Borrow the underlying [`WriteBackEngine`].
    pub const fn engine(&self) -> &WriteBackEngine<T> {
        &self.engine
    }

    /// Mutably borrow the underlying [`WriteBackEngine`].
    pub fn engine_mut(&mut self) -> &mut WriteBackEngine<T> {
        &mut self.engine
    }

    /// Consume the session and return the inner [`WriteBackEngine`].
    pub fn into_engine(self) -> WriteBackEngine<T> {
        self.engine
    }

    /// Return the current FUSE lookup reference count for `ino`.
    pub fn lookup_count(&self, ino: u64) -> u64 {
        self.lookup_counts.get(&ino).copied().unwrap_or(0)
    }

    /// Resolve a path, incrementing its kernel lookup reference count (`FUSE_LOOKUP`).
    pub async fn lookup(&mut self, path: &str) -> Result<u64> {
        let norm = Self::normalize(path);
        if let Some(vino) = Self::virtual_ino(&norm) {
            *self.lookup_counts.entry(vino).or_insert(0) += 1;
            return Ok(vino);
        }
        if let Some((tag, inner)) = Self::split_snapshot_path(&norm) {
            let (snap_ino, _) = self.engine.read_snapshot_path(tag, inner, 0, 0).await?;
            *self.lookup_counts.entry(snap_ino).or_insert(0) += 1;
            return Ok(snap_ino);
        }
        let ino = self.engine.resolve_ino(&norm)?;
        *self.lookup_counts.entry(ino).or_insert(0) += 1;
        Ok(ino)
    }

    /// Decrement the kernel lookup reference count for `ino` by `nlookup` (`FUSE_FORGET`).
    pub fn forget(&mut self, ino: u64, nlookup: u64) {
        if let Some(cnt) = self.lookup_counts.get_mut(&ino) {
            *cnt = cnt.saturating_sub(nlookup);
            if *cnt == 0 && ino != ROOT_INO {
                self.lookup_counts.remove(&ino);
            }
        }
    }

    /// Retrieve attributes for a live or virtual `.octoblock` path (`FUSE_GETATTR`).
    pub fn getattr(&self, path: &str) -> Result<InodeRecord> {
        let norm = Self::normalize(path);
        if let Some(vino) = Self::virtual_ino(&norm) {
            let is_dir = matches!(
                vino,
                VINO_OCTOBLOCK_DIR | VINO_CONFLICTS_DIR | VINO_SNAPSHOTS_DIR
            );
            let size = if is_dir {
                0
            } else {
                self.engine
                    .read(&norm, 0, 1 << 20)
                    .map(|b| b.len() as u64)
                    .unwrap_or(0)
            };
            let mut rec = self.engine.getattr("/")?;
            rec.mode = if is_dir {
                S_IFDIR | 0o555
            } else {
                S_IFREG | 0o444
            };
            rec.size = size;
            return Ok(rec);
        }
        self.engine.getattr(&norm)
    }

    /// List directory entries, including virtual `/.octoblock` entries (`FUSE_READDIR`).
    pub async fn readdir(&self, path: &str, after_cookie: u64) -> Result<Vec<VfsDirEntry>> {
        let norm = Self::normalize(path);
        if norm == "/.octoblock" {
            return Ok(vec![
                VfsDirEntry {
                    ino: VINO_STATUS_FILE,
                    name: b"status".to_vec(),
                },
                VfsDirEntry {
                    ino: VINO_POLICY_FILE,
                    name: b"policy.toml".to_vec(),
                },
                VfsDirEntry {
                    ino: VINO_CONFLICTS_DIR,
                    name: b"conflicts".to_vec(),
                },
                VfsDirEntry {
                    ino: VINO_SNAPSHOTS_DIR,
                    name: b"snapshots".to_vec(),
                },
            ]);
        }
        if norm == "/.octoblock/conflicts" {
            return Ok(vec![VfsDirEntry {
                ino: VINO_CONFLICTS_INDEX,
                name: b"index.json".to_vec(),
            }]);
        }
        if norm == "/.octoblock/snapshots" {
            let snaps = self.engine.list_snapshots().await?;
            return Ok(snaps
                .into_iter()
                .enumerate()
                .map(|(idx, s)| VfsDirEntry {
                    ino: VINO_SNAPSHOTS_DIR + (idx as u64) + 1,
                    name: s.name.into_bytes(),
                })
                .collect());
        }
        let entries = self.engine.readdir(&norm, after_cookie)?;
        Ok(entries
            .into_iter()
            .map(|e| VfsDirEntry {
                ino: e.ino,
                name: e.name,
            })
            .collect())
    }

    /// Read bytes from any path, transparently routing `/.octoblock/snapshots/<tag>/<path>`
    pub async fn read(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let norm = Self::normalize(path);
        if let Some((tag, inner)) = Self::split_snapshot_path(&norm) {
            let (_, bytes) = self
                .engine
                .read_snapshot_path(tag, inner, offset, len)
                .await?;
            return Ok(bytes);
        }
        self.engine.read(&norm, offset, len)
    }

    /// Create a regular file, refusing mutations inside `/.octoblock/` (`EROFS`).
    pub fn create(&mut self, path: &str, mode: u32, uid: u32, gid: u32) -> Result<u64> {
        let norm = Self::normalize(path);
        Self::reject_virtual_mutation(&norm)?;
        self.engine.create(&norm, mode, uid, gid)
    }

    /// Write data to `path`, refusing mutations inside `/.octoblock/` (`EROFS`).
    pub fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        let norm = Self::normalize(path);
        Self::reject_virtual_mutation(&norm)?;
        self.engine.write(&norm, offset, data)
    }

    /// Unlink a path, refusing mutations inside `/.octoblock/` (`EROFS`).
    pub fn unlink(&mut self, path: &str) -> Result<()> {
        let norm = Self::normalize(path);
        Self::reject_virtual_mutation(&norm)?;
        self.engine.unlink(&norm)
    }

    /// Execute an `ioctl` command on the mount (`OBX_IOC_ATOMIC_BEGIN`, `OBX_IOC_ATOMIC_END`, `OBX_IOC_SYNC_L2`).
    pub async fn ioctl(&mut self, cmd: u32) -> Result<()> {
        match cmd {
            OBX_IOC_ATOMIC_BEGIN => self.engine.atomic_begin(),
            OBX_IOC_ATOMIC_END => self.engine.atomic_end().await,
            OBX_IOC_SYNC_L2 => self.engine.sync_remote().await,
            _ => Err(Error::new(
                Errno::EINVAL,
                format!("unsupported octoblock ioctl {cmd:#x}"),
            )),
        }
    }

    /// Flush file changes via `fsync`.
    pub async fn fsync(&mut self, path: &str) -> Result<DurabilityLevel> {
        self.engine.fsync(path).await
    }

    /// Query file-system block statistics (`FUSE_STATFS`).
    pub fn statfs(&self) -> StatFs {
        self.engine.statfs()
    }

    fn normalize(path: &str) -> String {
        let s = path.replace('\\', "/");
        if s.starts_with('/') {
            s
        } else {
            format!("/{s}")
        }
    }

    fn virtual_ino(norm: &str) -> Option<u64> {
        match norm {
            "/.octoblock" => Some(VINO_OCTOBLOCK_DIR),
            "/.octoblock/status" => Some(VINO_STATUS_FILE),
            "/.octoblock/policy.toml" => Some(VINO_POLICY_FILE),
            "/.octoblock/conflicts" => Some(VINO_CONFLICTS_DIR),
            "/.octoblock/conflicts/index.json" => Some(VINO_CONFLICTS_INDEX),
            "/.octoblock/snapshots" => Some(VINO_SNAPSHOTS_DIR),
            _ => None,
        }
    }

    fn split_snapshot_path(norm: &str) -> Option<(&str, &str)> {
        let rest = norm.strip_prefix("/.octoblock/snapshots/")?;
        let (tag, inner) = rest.split_once('/')?;
        if tag.is_empty() || inner.is_empty() {
            return None;
        }
        Some((tag, inner))
    }

    fn reject_virtual_mutation(norm: &str) -> Result<()> {
        if norm == "/.octoblock" || norm.starts_with("/.octoblock/") {
            return Err(Error::new(
                Errno::EROFS,
                "virtual /.octoblock control namespace is read-only",
            ));
        }
        Ok(())
    }
}