use std::collections::BTreeMap;

use octoblock_fs::tree::InodeRecord;
use octoblock_fs::{Errno, Error, ROOT_INO, Result};
use octopage_git::Transport;

use crate::lease::MountRole;
use crate::vfs::{
    VINO_CONFLICTS_DIR, VINO_CONFLICTS_INDEX, VINO_OCTOBLOCK_DIR, VINO_POLICY_FILE,
    VINO_SNAPSHOTS_DIR, VINO_STATUS_FILE, VfsDirEntry, VfsSession,
};
use crate::{DurabilityLevel, MountState, StatFs, WriteBackEngine};

/// Summary of actions taken during a single background daemon tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickReport {
    /// Current mount state after the tick.
    pub state: MountState,
    /// True if a writer/multi-writer mount flushed dirty bytes to the remote (`L2`).
    pub flushed_l2: bool,
    /// True if a follower mount detected and pulled a new remote head commit.
    pub pulled_remote: bool,
}

/// Layer 5 inode-addressed FUSE protocol dispatcher and background daemon runtime.
pub struct FuseDispatcher<T: Transport> {
    vfs: VfsSession<T>,
    /// Maps live and virtual inode numbers to their current normalized path.
    ino_paths: BTreeMap<u64, String>,
    /// Dirty-bytes threshold that triggers an automatic background `L2` flush.
    flush_bytes: u64,
}

impl<T: Transport> FuseDispatcher<T> {
    /// Create a new [`FuseDispatcher`] wrapping `engine`.
    pub fn new(engine: WriteBackEngine<T>, flush_bytes: u64) -> Self {
        let mut ino_paths = BTreeMap::new();
        ino_paths.insert(ROOT_INO, "/".to_string());
        ino_paths.insert(VINO_OCTOBLOCK_DIR, "/.octoblock".to_string());
        ino_paths.insert(VINO_STATUS_FILE, "/.octoblock/status".to_string());
        ino_paths.insert(VINO_POLICY_FILE, "/.octoblock/policy.toml".to_string());
        ino_paths.insert(VINO_CONFLICTS_DIR, "/.octoblock/conflicts".to_string());
        ino_paths.insert(
            VINO_CONFLICTS_INDEX,
            "/.octoblock/conflicts/index.json".to_string(),
        );
        ino_paths.insert(VINO_SNAPSHOTS_DIR, "/.octoblock/snapshots".to_string());

        FuseDispatcher {
            vfs: VfsSession::new(engine),
            ino_paths,
            flush_bytes,
        }
    }

    /// Borrow the underlying [`VfsSession`].
    pub const fn vfs(&self) -> &VfsSession<T> {
        &self.vfs
    }

    /// Mutably borrow the underlying [`VfsSession`].
    pub fn vfs_mut(&mut self) -> &mut VfsSession<T> {
        &mut self.vfs
    }

    /// Borrow the underlying [`WriteBackEngine`].
    pub const fn engine(&self) -> &WriteBackEngine<T> {
        self.vfs.engine()
    }

    /// Mutably borrow the underlying [`WriteBackEngine`].
    pub fn engine_mut(&mut self) -> &mut WriteBackEngine<T> {
        self.vfs.engine_mut()
    }

    /// Resolve a child `(parent_ino, name)` pair to its inode number and attributes (`FUSE_LOOKUP`).
    pub async fn fuse_lookup(&mut self, parent_ino: u64, name: &str) -> Result<(u64, InodeRecord)> {
        let child_path = self.join_child_path(parent_ino, name)?;
        let ino = self.vfs.lookup(&child_path).await?;
        self.ino_paths.insert(ino, child_path.clone());
        let attr = self.vfs.getattr(&child_path)?;
        Ok((ino, attr))
    }

    /// Decrement kernel lookup reference count (`FUSE_FORGET`).
    pub fn fuse_forget(&mut self, ino: u64, nlookup: u64) {
        self.vfs.forget(ino, nlookup);
        if self.vfs.lookup_count(ino) == 0 && ino != ROOT_INO {
            self.ino_paths.remove(&ino);
        }
    }

    /// Get inode attributes by `ino` (`FUSE_GETATTR`).
    pub fn fuse_getattr(&self, ino: u64) -> Result<InodeRecord> {
        let path = self.path_for_ino(ino)?;
        self.vfs.getattr(path)
    }

    /// Read directory entries by `dir_ino` (`FUSE_READDIR`).
    pub async fn fuse_readdir(&mut self, dir_ino: u64, after_cookie: u64) -> Result<Vec<VfsDirEntry>> {
        let dir_path = self.path_for_ino(dir_ino)?.to_string();
        let entries = self.vfs.readdir(&dir_path, after_cookie).await?;
        for e in &entries {
            let name_str = String::from_utf8_lossy(&e.name);
            if name_str != "." && name_str != ".." {
                let child = if dir_path == "/" {
                    format!("/{name_str}")
                } else {
                    format!("{dir_path}/{name_str}")
                };
                self.ino_paths.insert(e.ino, child);
            }
        }
        Ok(entries)
    }

    /// Create and open a regular file under `parent_ino` (`FUSE_CREATE`).
    pub async fn fuse_create(
        &mut self,
        parent_ino: u64,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(u64, u64)> {
        let child_path = self.join_child_path(parent_ino, name)?;
        let ino = self.vfs.create(&child_path, mode, uid, gid)?;
        let _ = self.vfs.lookup(&child_path).await?;
        self.ino_paths.insert(ino, child_path.clone());
        let fh = self.vfs.engine_mut().open_handle(&child_path).await?;
        Ok((ino, fh))
    }

    /// Create a directory under `parent_ino` (`FUSE_MKDIR`).
    pub async fn fuse_mkdir(
        &mut self,
        parent_ino: u64,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        let child_path = self.join_child_path(parent_ino, name)?;
        if child_path == "/.octoblock" || child_path.starts_with("/.octoblock/") {
            return Err(Error::new(Errno::EROFS, "virtual /.octoblock is read-only"));
        }
        let ino = self.vfs.engine_mut().mkdir(&child_path, mode, uid, gid)?;
        let _ = self.vfs.lookup(&child_path).await?;
        self.ino_paths.insert(ino, child_path);
        Ok(ino)
    }

    /// Open an existing inode and return a file handle (`FUSE_OPEN`) with close-to-open coherence.
    pub async fn fuse_open(&mut self, ino: u64) -> Result<u64> {
        let path = self.path_for_ino(ino)?.to_string();
        self.vfs.engine_mut().open_handle(&path).await
    }

    /// Read bytes via an open file handle `fh` (`FUSE_READ`) or directly by `ino`.
    pub async fn fuse_read(&mut self, ino: u64, fh: Option<u64>, offset: u64, len: usize) -> Result<Vec<u8>> {
        if let Some(handle) = fh {
            return self.vfs.engine().read_handle(handle, offset, len);
        }
        let path = self.path_for_ino(ino)?.to_string();
        self.vfs.read(&path, offset, len).await
    }

    /// Write bytes to `ino` at `offset` (`FUSE_WRITE`).
    pub fn fuse_write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        let path = self.path_for_ino(ino)?.to_string();
        self.vfs.write(&path, offset, data)
    }

    /// Release an open file handle (`FUSE_RELEASE`).
    pub fn fuse_release(&mut self, fh: u64) -> Result<()> {
        self.vfs.engine_mut().close_handle(fh)
    }

    /// Unlink a child entry from `parent_ino` (`FUSE_UNLINK`).
    pub fn fuse_unlink(&mut self, parent_ino: u64, name: &str) -> Result<()> {
        let child_path = self.join_child_path(parent_ino, name)?;
        self.vfs.unlink(&child_path)
    }

    /// Remove an empty directory under `parent_ino` (`FUSE_RMDIR`).
    pub fn fuse_rmdir(&mut self, parent_ino: u64, name: &str) -> Result<()> {
        let child_path = self.join_child_path(parent_ino, name)?;
        self.vfs.engine_mut().rmdir(&child_path)
    }

    /// Rename a child entry across parent directories (`FUSE_RENAME`).
    pub fn fuse_rename(
        &mut self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        flags: u32,
    ) -> Result<()> {
        let old_path = self.join_child_path(old_parent, old_name)?;
        let new_path = self.join_child_path(new_parent, new_name)?;
        let ino = self.vfs.engine().resolve_ino(&old_path).ok();
        self.vfs.engine_mut().rename(&old_path, &new_path, flags)?;
        if let Some(i) = ino {
            self.ino_paths.insert(i, new_path);
        }
        Ok(())
    }

    /// Flush file state via `FUSE_FSYNC`.
    pub async fn fuse_fsync(&mut self, ino: u64) -> Result<DurabilityLevel> {
        let path = self.path_for_ino(ino)?.to_string();
        self.vfs.fsync(&path).await
    }

    /// Execute a volume `ioctl` (`OBX_IOC_ATOMIC_BEGIN`, `OBX_IOC_ATOMIC_END`, `OBX_IOC_SYNC_L2`).
    pub async fn fuse_ioctl(&mut self, cmd: u32) -> Result<()> {
        self.vfs.ioctl(cmd).await
    }

    /// Query volume block statistics (`FUSE_STATFS`).
    pub fn fuse_statfs(&self) -> StatFs {
        self.vfs.statfs()
    }

    /// Run one background daemon maintenance tick (Section 6.6, Section 7.2, Section 7.4):
    /// - Followers poll the remote branch for new commits while preserving open file handles.
    /// - Writers renew their lease and flush dirty commit groups if `force_flush` or `dirty_group_bytes >= flush_bytes`.
    pub async fn background_tick(&mut self, force_flush: bool) -> Result<TickReport> {
        let engine = self.vfs.engine_mut();
        if engine.role() == MountRole::Follower {
            let pulled = engine.poll_remote().await?;
            return Ok(TickReport {
                state: engine.status().state,
                flushed_l2: false,
                pulled_remote: pulled,
            });
        }

        let _ = engine.renew_lease().await?;
        let st = engine.status();
        let should_flush = st.state != MountState::Fenced
            && (force_flush || st.dirty_group_bytes >= self.flush_bytes)
            && (st.journal_depth_ops > 0 || st.dirty_group_bytes > 0);

        if should_flush {
            engine.sync_remote().await?;
            return Ok(TickReport {
                state: engine.status().state,
                flushed_l2: true,
                pulled_remote: false,
            });
        }

        Ok(TickReport {
            state: st.state,
            flushed_l2: false,
            pulled_remote: false,
        })
    }

    /// Cleanly flush and release the writer lease on daemon shutdown (`FUSE_DESTROY`).
    pub async fn shutdown(&mut self) -> Result<()> {
        self.vfs.engine_mut().unmount().await
    }

    fn path_for_ino(&self, ino: u64) -> Result<&str> {
        self.ino_paths
            .get(&ino)
            .map(String::as_str)
            .ok_or_else(|| Error::new(Errno::ENOENT, format!("untracked inode {ino}")))
    }

    fn join_child_path(&self, parent_ino: u64, name: &str) -> Result<String> {
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(Error::new(Errno::EINVAL, "invalid entry name"));
        }
        let parent = self.path_for_ino(parent_ino)?;
        if parent == "/" {
            Ok(format!("/{name}"))
        } else {
            Ok(format!("{parent}/{name}"))
        }
    }
}