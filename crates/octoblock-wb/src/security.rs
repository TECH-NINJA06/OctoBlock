//! Section 12 Client-side page encryption (`OBEX`), commit signing, and pinned-signer
//! verification (`REQ-5`, `REQ-8`).

use bytes::Bytes;
use octoblock_fs::page::PageId;
use octoblock_fs::{Errno, Error, Result};
use octopage_git::ObjectId;

/// 4-byte magic header for encrypted remote page blobs (`OBEX`, Section 12.1).
pub const OBEX_MAGIC: &[u8; 4] = b"OBEX";
/// Current `OBEX` envelope format version.
pub const OBEX_VERSION: u8 = 1;
/// Fixed header + tag overhead of an `OBEX` blob (`4 + 1 + 3 + 8 + 16 + 32 = 64` bytes).
pub const OBEX_OVERHEAD: usize = 64;

/// Derive a deterministic human-readable signer fingerprint (`obk-signer-<hex>`) from a 32-byte signer secret key.
pub fn signer_fingerprint(secret_key: &[u8; 32]) -> String {
    let pub_tag = keyed_prf(secret_key, b"octoblock-signer-pubkey-v1", &[]);
    let mut hex = String::with_capacity(32);
    for &b in &pub_tag[..16] {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("obk-signer-{hex}")
}

/// Sign a commit's `(tree_id, parents, epoch)` tuple using `secret_key`, returning `(fingerprint, sig_hex)`.
pub fn sign_commit_metadata(
    secret_key: &[u8; 32],
    tree_id: ObjectId,
    parents: &[ObjectId],
    epoch: u64,
) -> (String, String) {
    let fp = signer_fingerprint(secret_key);
    let payload = canonical_commit_payload(&fp, tree_id, parents, epoch);
    // Derive verification key from the fingerprint's secret and MAC the canonical payload.
    let verify_key = keyed_prf(secret_key, b"octoblock-signer- pubkey-secret-bridge", fp.as_bytes());
    let mac = keyed_prf(&verify_key, b"octoblock-commit-sig-v1", &payload);
    let mut sig_hex = String::with_capacity(64);
    for &b in &mac {
        sig_hex.push_str(&format!("{b:02x}"));
    }
    (fp, sig_hex)
}

/// Format commit message trailers carrying the signer fingerprint and signature (Section 12.3).
pub fn format_signed_commit_message(
    base_message: &str,
    secret_key: &[u8; 32],
    tree_id: ObjectId,
    parents: &[ObjectId],
    epoch: u64,
) -> Vec<u8> {
    let (fp, sig_hex) = sign_commit_metadata(secret_key, tree_id, parents, epoch);
    format!(
        "{}\nOctoBlock-Signer: {fp}\nOctoBlock-Sig: {sig_hex}\n",
        base_message.trim_end()
    )
    .into_bytes()
}

/// Verify a commit's signature trailers against `pinned_signers` and optional `secret_key` (Section 12.3, 12.4).
pub fn verify_commit_signature(
    message: &[u8],
    tree_id: ObjectId,
    parents: &[ObjectId],
    pinned_signers: &[String],
    known_secret_key: Option<&[u8; 32]>,
) -> Result<Option<String>> {
    let text = String::from_utf8_lossy(message);
    let mut signer: Option<String> = None;
    let mut sig_hex: Option<String> = None;
    let mut epoch: u64 = 0;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("octoblock group epoch ") {
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            epoch = num_str.parse::<u64>().unwrap_or(0);
        } else if let Some(fp) = trimmed.strip_prefix("OctoBlock-Signer:") {
            signer = Some(fp.trim().to_string());
        } else if let Some(sig) = trimmed.strip_prefix("OctoBlock-Sig:") {
            sig_hex = Some(sig.trim().to_string());
        }
    }

    if pinned_signers.is_empty() && signer.is_none() {
        return Ok(None);
    }

    let fp = signer.ok_or_else(|| {
        Error::new(
            Errno::EINVAL,
            "commit is unsigned but pinned_signers are required (REQ-5)",
        )
    })?;
    let sig = sig_hex.ok_or_else(|| Error::new(Errno::EPERM, "missing OctoBlock-Sig trailer"))?;

    if !pinned_signers.is_empty() && !pinned_signers.iter().any(|p| p == &fp) {
        return Err(Error::new(
            Errno::EPERM,
            format!("commit signer {fp} is not in pinned_signers (REQ-5)"),
        ));
    }

    if let Some(sk) = known_secret_key
        && signer_fingerprint(sk) == fp
    {
        let (_, expected_sig) = sign_commit_metadata(sk, tree_id, parents, epoch);
        if sig != expected_sig {
            return Err(Error::new(
                Errno::EPERM,
                "invalid OctoBlock-Sig commit signature (REQ-5)",
            ));
        }
    } else if sig.len() != 64 || !sig.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::new(Errno::EPERM, "malformed OctoBlock-Sig trailer"));
    }

    Ok(Some(fp))
}

/// Encrypt a raw `OBF1` page into an authenticated `OBEX` blob (`Section 12.1`, `REQ-8`).
pub fn encrypt_page_obex(
    master_key: &[u8; 32],
    page_id: PageId,
    epoch: u64,
    plaintext: &[u8],
) -> Bytes {
    let mut nonce = [0u8; 16];
    for b in &mut nonce {
        *b = fastrand::u8(..);
    }
    let mut header = Vec::with_capacity(32);
    header.extend_from_slice(OBEX_MAGIC);
    header.push(OBEX_VERSION);
    header.extend_from_slice(&page_id.bytes());
    header.extend_from_slice(&epoch.to_le_bytes());
    header.extend_from_slice(&nonce);

    let enc_key = keyed_prf(master_key, b"octoblock-obex-enc-v1", &header);
    let mac_key = keyed_prf(master_key, b"octoblock-obex-mac-v1", &header);

    let mut ciphertext = plaintext.to_vec();
    xor_keystream(&enc_key, &nonce, &mut ciphertext);
    let tag = keyed_prf(&mac_key, &header, &ciphertext);

    let mut out = Vec::with_capacity(OBEX_OVERHEAD + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Bytes::from(out)
}

/// Decrypt an `OBEX` page blob (or pass through an unencrypted `OBF1` page when `master_key` is `None`).
pub fn decrypt_page_obex(
    master_key: Option<&[u8; 32]>,
    expected_page_id: PageId,
    blob: &[u8],
) -> Result<Bytes> {
    if blob.len() < 4 || &blob[..4] != OBEX_MAGIC {
        if master_key.is_some() {
            return Err(Error::new(
                Errno::EIO,
                "expected encrypted OBEX page blob, found plaintext",
            ));
        }
        return Ok(Bytes::copy_from_slice(blob));
    }
    let key = master_key.ok_or_else(|| {
        Error::new(
            Errno::EINVAL,
            "volume pages are OBEX-encrypted; master_key required (REQ-8)",
        )
    })?;
    if blob.len() < OBEX_OVERHEAD {
        return Err(Error::new(Errno::EIO, "truncated OBEX page envelope"));
    }
    if blob[4] != OBEX_VERSION {
        return Err(Error::new(
            Errno::EIO,
            format!("unsupported OBEX version {}", blob[4]),
        ));
    }
    if blob[5..8] != expected_page_id.bytes() {
        return Err(Error::new(
            Errno::EIO,
            "OBEX page_id mismatch (page swap attack detected)",
        ));
    }

    let header = &blob[..32];
    let nonce = &blob[16..32];
    let tag = &blob[32..64];
    let ciphertext = &blob[64..];

    let enc_key = keyed_prf(key, b"octoblock-obex-enc-v1", header);
    let mac_key = keyed_prf(key, b"octoblock-obex-mac-v1", header);
    let expected_tag = keyed_prf(&mac_key, header, ciphertext);

    let mut diff = 0u8;
    for (&a, &b) in tag.iter().zip(expected_tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(Error::new(
            Errno::EIO,
            "OBEX authentication tag mismatch (remote page tampered or wrong key)",
        ));
    }

    let mut plaintext = ciphertext.to_vec();
    let mut nonce_arr = [0u8; 16];
    nonce_arr.copy_from_slice(nonce);
    xor_keystream(&enc_key, &nonce_arr, &mut plaintext);
    Ok(Bytes::from(plaintext))
}

fn canonical_commit_payload(
    fingerprint: &str,
    tree_id: ObjectId,
    parents: &[ObjectId],
    epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(fingerprint.as_bytes());
    out.extend_from_slice(tree_id.as_bytes());
    out.extend_from_slice(&epoch.to_le_bytes());
    for p in parents {
        out.extend_from_slice(p.as_bytes());
    }
    out
}

fn keyed_prf(key: &[u8; 32], domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut s = [0u64; 4];
    for (i, chunk) in key.chunks_exact(8).enumerate() {
        s[i] = u64::from_le_bytes(chunk.try_into().unwrap())
            ^ (0x9E37_79B9_7F4A_7C15u64.wrapping_mul((i as u64) + 1));
    }
    absorb_bytes(&mut s, domain);
    s[0] ^= 0xFF;
    chacha_rounds(&mut s);
    absorb_bytes(&mut s, data);
    s[3] ^= (domain.len() as u64) << 32 | (data.len() as u64);
    chacha_rounds(&mut s);
    chacha_rounds(&mut s);

    let mut out = [0u8; 32];
    for (i, word) in s.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn absorb_bytes(s: &mut [u64; 4], bytes: &[u8]) {
    let mut idx = 0;
    while idx + 8 <= bytes.len() {
        let w = u64::from_le_bytes(bytes[idx..idx + 8].try_into().unwrap());
        s[(idx / 8) & 3] ^= w;
        if (idx / 8) & 3 == 3 {
            chacha_rounds(s);
        }
        idx += 8;
    }
    if idx < bytes.len() {
        let mut tail = [0u8; 8];
        tail[..bytes.len() - idx].copy_from_slice(&bytes[idx..]);
        tail[bytes.len() - idx] = 0x80;
        s[0] ^= u64::from_le_bytes(tail);
        chacha_rounds(s);
    }
}

fn xor_keystream(key: &[u8; 32], nonce: &[u8; 16], buf: &mut [u8]) {
    for (counter, chunk) in buf.chunks_mut(32).enumerate() {
        let mut block_in = [0u8; 24];
        block_in[..16].copy_from_slice(nonce);
        block_in[16..24].copy_from_slice(&(counter as u64).to_le_bytes());
        let stream = keyed_prf(key, b"octoblock-stream-block", &block_in);
        for (b, &k) in chunk.iter_mut().zip(stream.iter()) {
            *b ^= k;
        }
    }
}

fn chacha_rounds(s: &mut [u64; 4]) {
    for _ in 0..8 {
        s[0] = s[0].wrapping_add(s[1]);
        s[3] = (s[3] ^ s[0]).rotate_left(16);
        s[2] = s[2].wrapping_add(s[3]);
        s[1] = (s[1] ^ s[2]).rotate_left(12);
        s[0] = s[0].wrapping_add(s[1]);
        s[3] = (s[3] ^ s[0]).rotate_left(8);
        s[2] = s[2].wrapping_add(s[3]);
        s[1] = (s[1] ^ s[2]).rotate_left(7);
        s.swap(1, 3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obex_page_encryption_and_tamper_rejection() {
        let key = [0x42; 32];
        let pid = PageId::from_bytes([0x01, 0x02, 0x03]);
        let plain = b"OBF1-superblock-or-extent-page-payload";
        let encrypted = encrypt_page_obex(&key, pid, 9, plain);
        assert_eq!(&encrypted[..4], OBEX_MAGIC);
        let recovered = decrypt_page_obex(Some(&key), pid, &encrypted).unwrap();
        assert_eq!(&recovered[..], plain);

        let mut tampered = encrypted.to_vec();
        tampered[65] ^= 0x01;
        assert!(decrypt_page_obex(Some(&key), pid, &tampered).is_err());
    }
}