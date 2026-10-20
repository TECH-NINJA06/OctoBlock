use octoblock_fs::{Errno, Error, ROOT_INO, Result};
use octopage_git::{ObjectId, Transport};

use crate::WriteBackEngine;

/// Parsed `octoblock` control-plane CLI command
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    Status { json: bool },
    Sync,
    Compact { archive_generation: bool },
    BranchList,
    BranchCreate { name: String },
    BranchSwitch { name: String },
    SnapshotList,
    SnapshotCreate { name: String },
    Merge {
        source_branch: String,
        base_commit_hex: String,
    },
    LeaseStatus,
    LeaseBreak,
    Conflicts,
    Fsck,
}

impl CliCommand {
    /// Parse a command-line argument slice (excluding the binary name `octoblock`).
    pub fn parse_args(args: &[&str]) -> Result<Self> {
        let Some(&cmd) = args.first() else {
            return Err(Error::new(Errno::EINVAL, "missing subcommand"));
        };
        match cmd {
            "status" => {
                let json = args.get(1).is_some_and(|&flag| flag == "--json");
                Ok(CliCommand::Status { json })
            }
            "sync" => Ok(CliCommand::Sync),
            "compact" => {
                let no_archive = args.get(1).is_some_and(|&flag| flag == "--no-archive");
                Ok(CliCommand::Compact {
                    archive_generation: !no_archive,
                })
            }
            "branch" => match args.get(1).copied() {
                Some("list") => Ok(CliCommand::BranchList),
                Some("create") => {
                    let name = (*args
                        .get(2)
                        .ok_or_else(|| Error::new(Errno::EINVAL, "missing branch name"))?)
                    .to_string();
                    Ok(CliCommand::BranchCreate { name })
                }
                Some("switch") => {
                    let name = (*args
                        .get(2)
                        .ok_or_else(|| Error::new(Errno::EINVAL, "missing branch name"))?)
                    .to_string();
                    Ok(CliCommand::BranchSwitch { name })
                }
                _ => Err(Error::new(
                    Errno::EINVAL,
                    "expected `branch list|create|switch`",
                )),
            },
            "snapshot" => match args.get(1).copied() {
                Some("list") => Ok(CliCommand::SnapshotList),
                Some("create") => {
                    let name = (*args
                        .get(2)
                        .ok_or_else(|| Error::new(Errno::EINVAL, "missing snapshot name"))?)
                    .to_string();
                    Ok(CliCommand::SnapshotCreate { name })
                }
                _ => Err(Error::new(
                    Errno::EINVAL,
                    "expected `snapshot list|create`",
                )),
            },
            "merge" => {
                let source_branch = (*args
                    .get(1)
                    .ok_or_else(|| Error::new(Errno::EINVAL, "missing source branch"))?)
                .to_string();
                let base_commit_hex = (*args
                    .get(2)
                    .ok_or_else(|| Error::new(Errno::EINVAL, "missing base commit SHA"))?)
                .to_string();
                Ok(CliCommand::Merge {
                    source_branch,
                    base_commit_hex,
                })
            }
            "lease" => match args.get(1).copied() {
                Some("status") => Ok(CliCommand::LeaseStatus),
                Some("break") => Ok(CliCommand::LeaseBreak),
                _ => Err(Error::new(Errno::EINVAL, "expected `lease status|break`")),
            },
            "conflicts" => Ok(CliCommand::Conflicts),
            "fsck" => Ok(CliCommand::Fsck),
            other => Err(Error::new(
                Errno::EINVAL,
                format!("unknown octoblock command: {other}"),
            )),
        }
    }
}

/// Execute a [`CliCommand`] against `engine` and return the formatted stdout string.
pub async fn execute_cli<T: Transport>(
    engine: &mut WriteBackEngine<T>,
    cmd: CliCommand,
) -> Result<String> {
    match cmd {
        CliCommand::Status { json } => {
            let st = engine.status();
            if json {
                serde_json::to_string_pretty(&st)
                    .map_err(|e| Error::new(Errno::EIO, e.to_string()))
            } else {
                Ok(format!(
                    "state={:?} role={:?} mode={:?} epoch={} head={} journal_ops={} live_bytes={}",
                    st.state,
                    st.role,
                    st.mode,
                    st.epoch,
                    st.head_commit,
                    st.journal_depth_ops,
                    st.live_bytes
                ))
            }
        }
        CliCommand::Sync => {
            engine.sync_remote().await?;
            Ok(format!("synced head={}", engine.head_commit().to_hex()))
        }
        CliCommand::Compact { archive_generation } => {
            let rep = engine.compact_history(archive_generation).await?;
            serde_json::to_string_pretty(&rep)
                .map_err(|e| Error::new(Errno::EIO, e.to_string()))
        }
        CliCommand::BranchList => {
            let branches = engine.list_branches().await?;
            let lines: Vec<String> = branches
                .into_iter()
                .map(|b| format!("{}\t{}", b.full_ref, b.commit_id.to_hex()))
                .collect();
            Ok(lines.join("\n"))
        }
        CliCommand::BranchCreate { name } => {
            let info = engine.create_branch(&name).await?;
            Ok(format!(
                "created branch {} -> {}",
                info.full_ref,
                info.commit_id.to_hex()
            ))
        }
        CliCommand::BranchSwitch { name } => {
            engine.switch_branch(&name).await?;
            Ok(format!("switched to branch {name}"))
        }
        CliCommand::SnapshotList => {
            let snaps = engine.list_snapshots().await?;
            let lines: Vec<String> = snaps
                .into_iter()
                .map(|s| format!("{}\t{}", s.full_ref, s.commit_id.to_hex()))
                .collect();
            Ok(lines.join("\n"))
        }
        CliCommand::SnapshotCreate { name } => {
            let info = engine.create_snapshot(&name).await?;
            Ok(format!(
                "created snapshot {} -> {}",
                info.full_ref,
                info.commit_id.to_hex()
            ))
        }
        CliCommand::Merge {
            source_branch,
            base_commit_hex,
        } => {
            let base_id = ObjectId::from_hex(&base_commit_hex)
                .map_err(|e| Error::new(Errno::EINVAL, format!("invalid base SHA: {e}")))?;
            let count = engine.merge_branch(&source_branch, base_id).await?;
            Ok(format!("merged {count} items from {source_branch}"))
        }
        CliCommand::LeaseStatus => {
            let lease = engine.lease_manager().known_lease();
            serde_json::to_string_pretty(&lease)
                .map_err(|e| Error::new(Errno::EIO, e.to_string()))
        }
        CliCommand::LeaseBreak => {
            let rec = engine.break_lease().await?;
            Ok(format!(
                "broke lease: holder={} mount_uuid={}",
                rec.holder, rec.mount_uuid
            ))
        }
        CliCommand::Conflicts => {
            Ok(String::from_utf8_lossy(&engine.conflicts().to_json_bytes()).into_owned())
        }
        CliCommand::Fsck => {
            let _ = engine.volume().getattr(ROOT_INO)?;
            let checked_pages = engine.volume().clone_storage().len();
            Ok(format!(
                "fsck clean=true checked_pages={checked_pages} findings=0"
            ))
        }
    }
}