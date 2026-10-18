//! Appendix C Operation record and canonical JSON Lines (`jsonl`) changelog encoding.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{Errno, Error, Result};

/// Data page run reference inside a `write` op (`{"file_page": 0, "count": 2}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRunRef {
    /// Starting logical page index inside the file.
    pub file_page: u32,
    /// Number of pages written by the operation.
    pub count: u32,
}

/// Specific file-system operation payload (Section 6.1 & Appendix C).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpKind {
    /// Create a regular file, directory, symlink, or device node.
    Create {
        /// Kind of create (`create`, `mkdir`, `symlink`, `mknod`).
        op_name: String,
        /// Parent directory inode number.
        parent: u64,
        /// Entry name in parent.
        name: String,
        /// File mode (`S_IFMT | perm`).
        mode: u32,
        /// Reserved inode range `[start, end_inclusive]`.
        ino_range: [u64; 2],
        /// Allocated inode number.
        ino: u64,
        /// Optional symlink target or device `rdev`.
        target: Option<String>,
    },
    /// Create a hard link.
    Link {
        /// Existing target inode number.
        ino: u64,
        /// New parent directory inode.
        parent: u64,
        /// New entry name.
        name: String,
    },
    /// Unlink a file or remove an empty directory (`unlink` or `rmdir`).
    Unlink {
        /// `"unlink"` or `"rmdir"`.
        op_name: String,
        /// Parent directory inode.
        parent: u64,
        /// Entry name removed.
        name: String,
        /// Expected child inode number.
        ino: u64,
    },
    /// Atomic rename (`rename`).
    Rename {
        /// Old `(parent_ino, name)`.
        old: (u64, String),
        /// New `(parent_ino, name)`.
        new: (u64, String),
        /// Rename flags (`RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `RENAME_WHITEOUT`).
        flags: u32,
    },
    /// Write bytes into a file (`write`).
    Write {
        /// Target file inode.
        ino: u64,
        /// Byte offset.
        off: u64,
        /// Byte length written.
        len: u64,
        /// Referenced data page run in the commit.
        pages: PageRunRef,
        /// Resulting file size after the write.
        size: u64,
    },
    /// Truncate, `fallocate`, or `punch_hole`.
    Truncate {
        /// `"truncate"`, `"fallocate"`, or `"punch_hole"`.
        op_name: String,
        /// Target file inode.
        ino: u64,
        /// Offset (0 for `truncate`).
        off: u64,
        /// New size or range length.
        size: u64,
        /// Mode flags for `fallocate`.
        mode: u32,
    },
    /// Update inode attributes (`setattr`).
    Setattr {
        /// Target inode.
        ino: u64,
        /// Optional new mode.
        mode: Option<u32>,
        /// Optional new uid.
        uid: Option<u32>,
        /// Optional new gid.
        gid: Option<u32>,
        /// Optional new size.
        size: Option<u64>,
        /// Optional new mtime (ns).
        mtime: Option<i64>,
        /// Optional new flags (`IMMUTABLE`, `APPEND`).
        flags: Option<u32>,
    },
    /// Set or remove an extended attribute (`setxattr` / `removexattr`).
    Xattr {
        /// `"setxattr"` or `"removexattr"`.
        op_name: String,
        /// Target inode.
        ino: u64,
        /// Attribute name.
        name: String,
        /// Attribute value length (or `None` on remove).
        value_len: Option<usize>,
    },
    /// Group boundary or atomic-region barrier (`barrier`).
    Barrier {
        /// `"group_end"`, `"atomic_begin"`, or `"atomic_end"`.
        kind: String,
    },
}

/// One logged mutation in the volume changelog (Appendix C).
#[derive(Clone, Debug, PartialEq)]
pub struct OpRecord {
    /// Monotonic sequence number within the volume.
    pub seq: u64,
    /// Client timestamp in seconds (recorded for deterministic replay).
    pub t: f64,
    /// Caller user ID.
    pub uid: u32,
    /// Caller group ID.
    pub gid: u32,
    /// Specific operation details.
    pub kind: OpKind,
}

impl OpRecord {
    /// Encode as a single canonical JSON line with keys in Appendix C's deterministic order.
    pub fn to_json_line(&self) -> String {
        let mut m = Map::new();
        m.insert("seq".into(), Value::from(self.seq));
        m.insert("t".into(), Value::from((self.t * 1000.0).round() / 1000.0));
        match &self.kind {
            OpKind::Create {
                op_name,
                parent,
                name,
                mode,
                ino_range,
                ino,
                target,
            } => {
                m.insert("op".into(), Value::from(op_name.as_str()));
                m.insert("uid".into(), Value::from(self.uid));
                m.insert("gid".into(), Value::from(self.gid));
                m.insert("parent".into(), Value::from(*parent));
                m.insert("name".into(), Value::from(name.as_str()));
                m.insert("mode".into(), Value::from(*mode));
                if let Some(t) = target {
                    m.insert("target".into(), Value::from(t.as_str()));
                }
                m.insert(
                    "ino_range".into(),
                    Value::Array(vec![Value::from(ino_range[0]), Value::from(ino_range[1])]),
                );
                m.insert("ino".into(), Value::from(*ino));
            }
            OpKind::Link { ino, parent, name } => {
                m.insert("op".into(), Value::from("link"));
                m.insert("uid".into(), Value::from(self.uid));
                m.insert("gid".into(), Value::from(self.gid));
                m.insert("ino".into(), Value::from(*ino));
                m.insert("parent".into(), Value::from(*parent));
                m.insert("name".into(), Value::from(name.as_str()));
            }
            OpKind::Unlink {
                op_name,
                parent,
                name,
                ino,
            } => {
                m.insert("op".into(), Value::from(op_name.as_str()));
                m.insert("uid".into(), Value::from(self.uid));
                m.insert("gid".into(), Value::from(self.gid));
                m.insert("parent".into(), Value::from(*parent));
                m.insert("name".into(), Value::from(name.as_str()));
                m.insert("ino".into(), Value::from(*ino));
            }
            OpKind::Rename { old, new, flags } => {
                m.insert("op".into(), Value::from("rename"));
                m.insert("uid".into(), Value::from(self.uid));
                m.insert("gid".into(), Value::from(self.gid));
                m.insert(
                    "old".into(),
                    Value::Array(vec![Value::from(old.0), Value::from(old.1.as_str())]),
                );
                m.insert(
                    "new".into(),
                    Value::Array(vec![Value::from(new.0), Value::from(new.1.as_str())]),
                );
                m.insert("flags".into(), Value::from(*flags));
            }
            OpKind::Write {
                ino,
                off,
                len,
                pages,
                size,
            } => {
                m.insert("op".into(), Value::from("write"));
                m.insert("ino".into(), Value::from(*ino));
                m.insert("off".into(), Value::from(*off));
                m.insert("len".into(), Value::from(*len));
                let mut pm = Map::new();
                pm.insert("file_page".into(), Value::from(pages.file_page));
                pm.insert("count".into(), Value::from(pages.count));
                m.insert("pages".into(), Value::Object(pm));
                m.insert("size".into(), Value::from(*size));
            }
            OpKind::Truncate {
                op_name,
                ino,
                off,
                size,
                mode,
            } => {
                m.insert("op".into(), Value::from(op_name.as_str()));
                m.insert("ino".into(), Value::from(*ino));
                m.insert("off".into(), Value::from(*off));
                m.insert("size".into(), Value::from(*size));
                m.insert("mode".into(), Value::from(*mode));
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
                m.insert("op".into(), Value::from("setattr"));
                m.insert("ino".into(), Value::from(*ino));
                if let Some(v) = mode {
                    m.insert("mode".into(), Value::from(*v));
                }
                if let Some(v) = uid {
                    m.insert("set_uid".into(), Value::from(*v));
                }
                if let Some(v) = gid {
                    m.insert("set_gid".into(), Value::from(*v));
                }
                if let Some(v) = size {
                    m.insert("size".into(), Value::from(*v));
                }
                if let Some(v) = mtime {
                    m.insert("mtime".into(), Value::from(*v));
                }
                if let Some(v) = flags {
                    m.insert("flags".into(), Value::from(*v));
                }
            }
            OpKind::Xattr {
                op_name,
                ino,
                name,
                value_len,
            } => {
                m.insert("op".into(), Value::from(op_name.as_str()));
                m.insert("ino".into(), Value::from(*ino));
                m.insert("name".into(), Value::from(name.as_str()));
                if let Some(len) = value_len {
                    m.insert("value_len".into(), Value::from(*len));
                }
            }
            OpKind::Barrier { kind } => {
                m.insert("op".into(), Value::from("barrier"));
                m.insert("kind".into(), Value::from(kind.as_str()));
            }
        }
        serde_json::to_string(&Value::Object(m)).expect("valid JSON")
    }

    /// Parse a single JSONL changelog line, ignoring unknown keys for forward compatibility.
    pub fn parse_json_line(line: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(line)
            .map_err(|e| Error::new(Errno::EINVAL, format!("bad changelog JSON: {e}")))?;
        let obj = v
            .as_object()
            .ok_or_else(|| Error::new(Errno::EINVAL, "changelog line is not a JSON object"))?;
        let get_u64 = |k: &str| {
            obj.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::new(Errno::EINVAL, format!("missing u64 field {k}")))
        };
        let get_str = |k: &str| {
            obj.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| Error::new(Errno::EINVAL, format!("missing string field {k}")))
        };

        let seq = get_u64("seq")?;
        let t = obj
            .get("t")
            .and_then(Value::as_f64)
            .ok_or_else(|| Error::new(Errno::EINVAL, "missing timestamp t"))?;
        let uid = obj.get("uid").and_then(Value::as_u64).unwrap_or(0) as u32;
        let gid = obj.get("gid").and_then(Value::as_u64).unwrap_or(0) as u32;
        let op = get_str("op")?;

        let kind = match op.as_str() {
            "create" | "mkdir" | "symlink" | "mknod" => {
                let range_arr = obj
                    .get("ino_range")
                    .and_then(Value::as_array)
                    .ok_or_else(|| Error::new(Errno::EINVAL, "missing ino_range"))?;
                let r0 = range_arr.first().and_then(Value::as_u64).unwrap_or(65_536);
                let r1 = range_arr.get(1).and_then(Value::as_u64).unwrap_or(131_071);
                OpKind::Create {
                    op_name: op,
                    parent: get_u64("parent")?,
                    name: get_str("name")?,
                    mode: get_u64("mode")? as u32,
                    ino_range: [r0, r1],
                    ino: get_u64("ino")?,
                    target: obj.get("target").and_then(Value::as_str).map(String::from),
                }
            }
            "link" => OpKind::Link {
                ino: get_u64("ino")?,
                parent: get_u64("parent")?,
                name: get_str("name")?,
            },
            "unlink" | "rmdir" => OpKind::Unlink {
                op_name: op,
                parent: get_u64("parent")?,
                name: get_str("name")?,
                ino: get_u64("ino")?,
            },
            "rename" => {
                let parse_pair = |k: &str| -> Result<(u64, String)> {
                    let arr = obj
                        .get(k)
                        .and_then(Value::as_array)
                        .ok_or_else(|| Error::new(Errno::EINVAL, format!("missing pair {k}")))?;
                    let p = arr
                        .first()
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Error::new(Errno::EINVAL, "bad parent in rename"))?;
                    let n = arr
                        .get(1)
                        .and_then(Value::as_str)
                        .ok_or_else(|| Error::new(Errno::EINVAL, "bad name in rename"))?;
                    Ok((p, n.to_string()))
                };
                OpKind::Rename {
                    old: parse_pair("old")?,
                    new: parse_pair("new")?,
                    flags: obj.get("flags").and_then(Value::as_u64).unwrap_or(0) as u32,
                }
            }
            "write" => {
                let pages_obj = obj
                    .get("pages")
                    .and_then(Value::as_object)
                    .ok_or_else(|| Error::new(Errno::EINVAL, "missing pages in write op"))?;
                let file_page = pages_obj
                    .get("file_page")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32;
                let count = pages_obj.get("count").and_then(Value::as_u64).unwrap_or(0) as u32;
                OpKind::Write {
                    ino: get_u64("ino")?,
                    off: get_u64("off")?,
                    len: get_u64("len")?,
                    pages: PageRunRef { file_page, count },
                    size: get_u64("size")?,
                }
            }
            "truncate" | "fallocate" | "punch_hole" => OpKind::Truncate {
                op_name: op,
                ino: get_u64("ino")?,
                off: obj.get("off").and_then(Value::as_u64).unwrap_or(0),
                size: get_u64("size")?,
                mode: obj.get("mode").and_then(Value::as_u64).unwrap_or(0) as u32,
            },
            "setattr" => OpKind::Setattr {
                ino: get_u64("ino")?,
                mode: obj.get("mode").and_then(Value::as_u64).map(|x| x as u32),
                uid: obj.get("set_uid").and_then(Value::as_u64).map(|x| x as u32),
                gid: obj.get("set_gid").and_then(Value::as_u64).map(|x| x as u32),
                size: obj.get("size").and_then(Value::as_u64),
                mtime: obj.get("mtime").and_then(Value::as_i64),
                flags: obj.get("flags").and_then(Value::as_u64).map(|x| x as u32),
            },
            "setxattr" | "removexattr" => OpKind::Xattr {
                op_name: op,
                ino: get_u64("ino")?,
                name: get_str("name")?,
                value_len: obj
                    .get("value_len")
                    .and_then(Value::as_u64)
                    .map(|x| x as usize),
            },
            "barrier" => OpKind::Barrier {
                kind: get_str("kind")?,
            },
            other => {
                return Err(Error::new(
                    Errno::EINVAL,
                    format!("unknown changelog op {other:?}"),
                ));
            }
        };
        Ok(OpRecord {
            seq,
            t,
            uid,
            gid,
            kind,
        })
    }
}

/// Encode a slice of `OpRecord`s into a newline-terminated canonical JSONL blob.
pub fn encode_changelog(ops: &[OpRecord]) -> Vec<u8> {
    let mut out = String::new();
    for op in ops {
        out.push_str(&op.to_json_line());
        out.push('\n');
    }
    out.into_bytes()
}

/// Decode a JSONL changelog blob into `OpRecord`s.
pub fn decode_changelog(bytes: &[u8]) -> Result<Vec<OpRecord>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::new(Errno::EINVAL, format!("changelog is not UTF-8: {e}")))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(OpRecord::parse_json_line)
        .collect()
}