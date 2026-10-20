use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use octoblock_fs::oplog::OpRecord;
use octoblock_fs::{Errno, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Default segment file size: 64 MiB 
pub const SEGMENT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Default total journal capacity: 1 GiB 
pub const DEFAULT_JOURNAL_CAPACITY: u64 = 1024 * 1024 * 1024;
const RECORD_HEADER_LEN: usize = 4 + 4 + 8 + 1; // len(u32) + crc32c(u32) + seq(u64) + type(u8)
const NONCE_LEN: usize = 24;

/// Behavior when the local journal reaches `journal_capacity` 
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnJournalFull {
    /// Return `ENOSPC` to writers (default).
    #[default]
    Enospc,
    /// Block/throttle writers (`EAGAIN` for non-blocking).
    Block,
    /// Transition the mount to read-only (`EROFS`).
    ReadOnly,
}

/// Type tag for a journal record (`type u8`, Section 6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum JournalRecordType {
    /// A file-system mutation op record plus any associated full data bytes.
    Mutation = 1,
    /// Explicit journal barrier / sync point.
    Barrier = 2,
}

impl JournalRecordType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Mutation),
            2 => Some(Self::Barrier),
            _ => None,
        }
    }
}

/// Decoded payload of a journal record (Section 6.4).
#[derive(Clone, Debug, PartialEq)]
pub struct JournalEntry {
    /// Monotonic journal sequence number.
    pub seq: u64,
    /// Record type.
    pub kind: JournalRecordType,
    /// Logged file-system mutation.
    pub op: OpRecord,
    /// Full data bytes for `write`/`symlink` ops 
    pub data: Vec<u8>,
}

/// Internal wire representation encoding `op` via its canonical Appendix C JSON line.
#[derive(Serialize, Deserialize)]
struct WireJournalEntry {
    seq: u64,
    kind: JournalRecordType,
    op_line: String,
    data: Vec<u8>,
}

/// Software Castagnoli CRC32C implementation (`0x82F63B78` polynomial).
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

/// Derive a 32-byte journal subkey from the volume's master data key
pub fn derive_journal_subkey(master_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"octoblock-journal-subkey-v1:");
    hasher.update(master_key);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Zeroizing::new(out)
}

/// Local append-only write-ahead journal managing 64 MiB segment files (Section 6.4).
pub struct LocalJournal {
    dir: PathBuf,
    cipher: Option<XChaCha20Poly1305>,
    capacity: u64,
    policy: OnJournalFull,
    active_segment_id: u64,
    active_file: File,
    active_size: u64,
    total_bytes: u64,
    next_seq: u64,
    synced_seq: u64,
    unsynced_ops: usize,
}

impl LocalJournal {
    /// Open or initialize the journal directory, replaying valid records and truncating any torn tail (`EC-D08`).
    pub fn open(
        dir: impl AsRef<Path>,
        master_key: Option<&[u8; 32]>,
        capacity: u64,
        policy: OnJournalFull,
    ) -> Result<(Self, Vec<JournalEntry>)> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|e| Error::new(Errno::EIO, format!("journal dir: {e}")))?;

        let cipher = master_key.map(|k| {
            let subkey = derive_journal_subkey(k);
            XChaCha20Poly1305::new((&*subkey).into())
        });

        let mut segments = Self::list_segments(&dir)?;
        if segments.is_empty() {
            segments.push(1);
        }

        let mut recovered = Vec::new();
        let mut total_bytes = 0u64;
        let mut max_seq = 0u64;

        for &seg_id in &segments {
            let path = Self::segment_path(&dir, seg_id);
            if !path.exists() {
                continue;
            }
            let (entries, valid_len) = Self::read_and_truncate_segment(&path, cipher.as_ref())?;
            total_bytes += valid_len;
            for e in entries {
                max_seq = max_seq.max(e.seq);
                recovered.push(e);
            }
        }

        let active_segment_id = *segments.last().unwrap_or(&1);
        let active_path = Self::segment_path(&dir, active_segment_id);
        // Use `.write(true)` + `SeekFrom::End(0)` rather than `.append(true)` so Windows grants
        // `FILE_WRITE_DATA`, which is required by `File::set_len(0)` during `truncate_committed`.
        let mut active_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&active_path)
            .map_err(|e| Error::new(Errno::EIO, format!("open journal segment: {e}")))?;
        let active_size = active_file
            .seek(SeekFrom::End(0))
            .map_err(|e| Error::new(Errno::EIO, format!("seek journal segment: {e}")))?;

        let journal = LocalJournal {
            dir,
            cipher,
            capacity,
            policy,
            active_segment_id,
            active_file,
            active_size,
            total_bytes,
            next_seq: max_seq + 1,
            synced_seq: max_seq,
            unsynced_ops: recovered.len(),
        };
        Ok((journal, recovered))
    }

    fn segment_path(dir: &Path, seg_id: u64) -> PathBuf {
        dir.join(format!("seg-{seg_id:08}.log"))
    }

    fn list_segments(dir: &Path) -> Result<Vec<u64>> {
        let mut ids = Vec::new();
        let entries =
            fs::read_dir(dir).map_err(|e| Error::new(Errno::EIO, format!("read_dir: {e}")))?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if let Some(num) = s.strip_prefix("seg-").and_then(|r| r.strip_suffix(".log"))
                && let Ok(id) = num.parse::<u64>()
            {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    fn read_and_truncate_segment(
        path: &Path,
        cipher: Option<&XChaCha20Poly1305>,
    ) -> Result<(Vec<JournalEntry>, u64)> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| Error::new(Errno::EIO, format!("open segment: {e}")))?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)
            .map_err(|e| Error::new(Errno::EIO, format!("read segment: {e}")))?;

        let mut pos = 0usize;
        let mut entries = Vec::new();

        while pos < raw.len() {
            // Torn header at tail -> truncate (Section 6.4, EC-D08).
            if pos + RECORD_HEADER_LEN > raw.len() {
                file.set_len(pos as u64).ok();
                file.sync_data().ok();
                break;
            }
            let payload_len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
            let expected_crc = u32::from_le_bytes(raw[pos + 4..pos + 8].try_into().unwrap());
            let seq = u64::from_le_bytes(raw[pos + 8..pos + 16].try_into().unwrap());
            let rtype_byte = raw[pos + 16];

            if payload_len > (SEGMENT_MAX_BYTES as usize)
                || pos + RECORD_HEADER_LEN + payload_len > raw.len()
            {
                // Torn record payload at tail -> truncate here (EC-D08).
                file.set_len(pos as u64).ok();
                file.sync_data().ok();
                break;
            }

            let mut crc_input = Vec::with_capacity(9 + payload_len);
            crc_input.extend_from_slice(&raw[pos + 8..pos + RECORD_HEADER_LEN + payload_len]);
            if crc32c(&crc_input) != expected_crc {
                // Bad CRC at tail -> truncate torn tail (Section 6.4, EC-D08).
                file.set_len(pos as u64).ok();
                file.sync_data().ok();
                break;
            }

            // Valid CRC! If content inside a CRC-valid record is impossible, EC-D07 requires
            // stopping replay and reporting corruption (`EIO` / `DAMAGED`).
            let Some(kind) = JournalRecordType::from_u8(rtype_byte) else {
                return Err(Error::new(
                    Errno::EIO,
                    format!(
                        "journal record {seq} has valid CRC but impossible type {rtype_byte} (EC-D07)"
                    ),
                ));
            };
            let wire_payload =
                &raw[pos + RECORD_HEADER_LEN..pos + RECORD_HEADER_LEN + payload_len];
            let plain = match cipher {
                None => wire_payload.to_vec(),
                Some(aead) => {
                    if wire_payload.len() < NONCE_LEN + 16 {
                        return Err(Error::new(
                            Errno::EIO,
                            "encrypted journal record too short (EC-D07)",
                        ));
                    }
                    let (n, ct) = wire_payload.split_at(NONCE_LEN);
                    let nonce = XNonce::try_from(n)
                        .map_err(|_| Error::new(Errno::EIO, "invalid journal nonce length"))?;
                    let aad = [seq.to_le_bytes().as_slice(), &[rtype_byte]].concat();
                    aead.decrypt(
                        &nonce,
                        Payload {
                            msg: ct,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        Error::new(
                            Errno::EIO,
                            format!("journal record {seq} failed AEAD authentication (REQ-8)"),
                        )
                    })?
                }
            };

            let wire: WireJournalEntry = serde_json::from_slice(&plain).map_err(|e| {
                Error::new(
                    Errno::EIO,
                    format!(
                        "journal record {seq} has valid CRC but impossible JSON content: {e} (EC-D07)"
                    ),
                )
            })?;
            if wire.seq != seq || wire.kind != kind {
                return Err(Error::new(
                    Errno::EIO,
                    format!("journal record {seq} header/body mismatch (EC-D07)"),
                ));
            }
            let op = OpRecord::parse_json_line(&wire.op_line).map_err(|e| {
                Error::new(
                    Errno::EIO,
                    format!("journal record {seq} invalid op_line: {e} (EC-D07)"),
                )
            })?;
            entries.push(JournalEntry {
                seq,
                kind,
                op,
                data: wire.data,
            });
            pos += RECORD_HEADER_LEN + payload_len;
        }

        Ok((entries, pos as u64))
    }

    /// Append a record to the active journal segment (`L0` in OS buffer until [`Self::barrier`]).
    pub fn append(&mut self, kind: JournalRecordType, op: OpRecord, data: Vec<u8>) -> Result<u64> {
        let seq = self.next_seq;
        let wire = WireJournalEntry {
            seq,
            kind,
            op_line: op.to_json_line(),
            data,
        };
        let plain =
            serde_json::to_vec(&wire).map_err(|e| Error::new(Errno::EIO, e.to_string()))?;
        let rtype_byte = kind as u8;

        let wire_payload = match &self.cipher {
            None => plain,
            Some(aead) => {
                let mut nonce = [0u8; NONCE_LEN];
                getrandom::fill(&mut nonce)
                    .map_err(|e| Error::new(Errno::EIO, format!("rng: {e}")))?;
                let aad = [seq.to_le_bytes().as_slice(), &[rtype_byte]].concat();
                let ct = aead
                    .encrypt(
                        &XNonce::from(nonce),
                        Payload {
                            msg: &plain,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| Error::new(Errno::EIO, "journal encryption failed"))?;
                [nonce.as_slice(), &ct].concat()
            }
        };

        let record_len = (RECORD_HEADER_LEN + wire_payload.len()) as u64;
        if self.total_bytes + record_len > self.capacity {
            return Err(match self.policy {
                OnJournalFull::Enospc => Error::new(Errno::ENOSPC, "local journal is full"),
                OnJournalFull::Block => {
                    Error::new(Errno::EAGAIN, "local journal is full (throttled)")
                }
                OnJournalFull::ReadOnly => {
                    Error::new(Errno::EROFS, "local journal is full (mounted read-only)")
                }
            });
        }

        if self.active_size + record_len > SEGMENT_MAX_BYTES {
            self.roll_segment()?;
        }

        let mut crc_input = Vec::with_capacity(9 + wire_payload.len());
        crc_input.extend_from_slice(&seq.to_le_bytes());
        crc_input.push(rtype_byte);
        crc_input.extend_from_slice(&wire_payload);
        let crc = crc32c(&crc_input);

        let mut frame = Vec::with_capacity(record_len as usize);
        frame.extend_from_slice(&(wire_payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&crc.to_le_bytes());
        frame.extend_from_slice(&crc_input);

        self.active_file
            .write_all(&frame)
            .map_err(|e| Error::new(Errno::EIO, format!("journal write: {e}")))?;
        self.active_size += record_len;
        self.total_bytes += record_len;
        self.next_seq += 1;
        self.unsynced_ops += 1;
        Ok(seq)
    }

    fn roll_segment(&mut self) -> Result<()> {
        self.active_file
            .sync_data()
            .map_err(|e| Error::new(Errno::EIO, format!("fdatasync: {e}")))?;
        self.active_segment_id += 1;
        let path = Self::segment_path(&self.dir, self.active_segment_id);
        self.active_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| Error::new(Errno::EIO, format!("create next segment: {e}")))?;
        self.active_size = 0;
        Ok(())
    }

    /// Issue an `fdatasync` barrier on the active journal segment, reaching `L1` durability for all prior records (Section 6.4, 6.5, REQ-2).
    pub fn barrier(&mut self) -> Result<u64> {
        self.active_file
            .sync_data()
            .map_err(|e| Error::new(Errno::EIO, format!("journal fdatasync barrier: {e}")))?;
        self.synced_seq = self.next_seq.saturating_sub(1);
        Ok(self.synced_seq)
    }

    /// Truncate all journal segments after a remote commit (`L2`) has been acknowledged and recorded in `state.json` (Section 6.4).
    pub fn truncate_committed(&mut self) -> Result<()> {
        let segments = Self::list_segments(&self.dir)?;
        for seg_id in segments {
            if seg_id != self.active_segment_id {
                let _ = fs::remove_file(Self::segment_path(&self.dir, seg_id));
            }
        }
        self.active_file
            .set_len(0)
            .map_err(|e| Error::new(Errno::EIO, format!("journal truncate: {e}")))?;
        self.active_file
            .seek(SeekFrom::Start(0))
            .map_err(|e| Error::new(Errno::EIO, format!("journal seek: {e}")))?;
        self.active_file
            .sync_data()
            .map_err(|e| Error::new(Errno::EIO, format!("journal fdatasync: {e}")))?;
        self.active_size = 0;
        self.total_bytes = 0;
        self.unsynced_ops = 0;
        self.synced_seq = self.next_seq.saturating_sub(1);
        Ok(())
    }

    /// Current journal bytes on disk (`journal_depth` in bytes).
    pub const fn depth_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Number of uncommitted operations currently in the journal (`journal_depth` in ops).
    pub const fn depth_ops(&self) -> usize {
        self.unsynced_ops
    }

    /// Highest journal sequence number that has completed an `L1` `fdatasync` barrier.
    pub const fn synced_seq(&self) -> u64 {
        self.synced_seq
    }

    /// Whether the journal is above 90% of its configured capacity (`DEGRADED_JOURNAL`, Section 6.10).
    pub const fn is_above_90_percent(&self) -> bool {
        self.total_bytes * 10 >= self.capacity * 9
    }

    /// Path to the active segment file (for fault-injection tests).
    pub fn active_segment_path(&self) -> PathBuf {
        Self::segment_path(&self.dir, self.active_segment_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octoblock_fs::oplog::OpKind;

    fn sample_op(seq: u64) -> OpRecord {
        OpRecord {
            seq,
            t: 1_791_371_042.0,
            uid: 1000,
            gid: 1000,
            kind: OpKind::Barrier {
                kind: "group_end".into(),
            },
        }
    }

    #[test]
    fn encrypted_journal_round_trip_and_torn_tail_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x42u8; 32];
        let seg_path = {
            let (mut j, recovered) = LocalJournal::open(
                dir.path(),
                Some(&key),
                DEFAULT_JOURNAL_CAPACITY,
                OnJournalFull::Enospc,
            )
            .unwrap();
            assert!(recovered.is_empty());
            j.append(
                JournalRecordType::Mutation,
                sample_op(1),
                b"SECRET_PAYLOAD".to_vec(),
            )
            .unwrap();
            j.append(
                JournalRecordType::Mutation,
                sample_op(2),
                b"SECOND_PAYLOAD".to_vec(),
            )
            .unwrap();
            j.barrier().unwrap();
            j.active_segment_path()
        };

        // REQ-8: Verify disk segment contains no plaintext
        let raw_on_disk = fs::read(&seg_path).unwrap();
        assert!(!raw_on_disk.windows(14).any(|w| w == b"SECRET_PAYLOAD"));

        // EC-D08: Append a torn tail (half a header + garbage) and verify clean truncation on reopen
        let mut f = OpenOptions::new().append(true).open(&seg_path).unwrap();
        f.write_all(&[0x99, 0x00, 0x00, 0x00, 0x12, 0x34]).unwrap();
        drop(f);

        let (mut j2, recovered) = LocalJournal::open(
            dir.path(),
            Some(&key),
            DEFAULT_JOURNAL_CAPACITY,
            OnJournalFull::Enospc,
        )
        .unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].data, b"SECRET_PAYLOAD");
        assert_eq!(recovered[1].data, b"SECOND_PAYLOAD");
        j2.truncate_committed().unwrap();
        assert_eq!(j2.depth_bytes(), 0);
    }
}