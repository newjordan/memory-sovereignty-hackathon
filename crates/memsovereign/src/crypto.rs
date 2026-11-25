//! Cryptographic primitives for the memory log.
//!
//! # What this module guarantees
//!
//! * **Encryption** is XChaCha20-Poly1305. The ciphertext includes the Poly1305
//!   tag, so a flipped bit or a wrong associated-data string fails closed.
//! * **Nonces** are 192 bits from the operating system's CSPRNG, generated
//!   inside [`encrypt_xchacha20poly1305`]. Callers cannot pass a nonce or a
//!   non-cryptographic RNG. A repeated nonce under one key would reveal the
//!   XOR of two plaintexts; a 192-bit random nonce makes that collision
//!   negligible, and keeping generation internal removes the usual misuse.
//! * **Keys** for content are 32 uniform bytes. They are not derived from the
//!   Ed25519 seed (the signing key and the content key stay independent) and
//!   not stretched from a password — there is no password. See the README
//!   threat model for what that means on a copied disk.
//! * **Hashes** are BLAKE3 in derive-key mode with a hardcoded context string,
//!   so an entry hash cannot be substituted for an attachments hash.
//! * **Signatures** are produced by the caller over the byte strings from
//!   [`entry_signing_message`], [`head_signing_message`],
//!   [`receipt_signing_message`], and [`checkpoint_signing_message`]. Those
//!   strings are domain-separated. The hash chain by itself is not a MAC.

use crate::types::{Attachment, CheckpointUnsigned, EntryUnsigned, Provenance, ReceiptUnsigned};
use anyhow::Context;
use base64::Engine;
use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::SysRng;
use rand_core::UnwrapErr;

pub type Hash32 = [u8; 32];

/// OS CSPRNG wrapped so [`CryptoRng::fill_bytes`] is infallible.
///
/// A failure of the operating system generator panics. That is intentional:
/// continuing with a short read would be worse than stopping.
pub type OsRng = UnwrapErr<SysRng>;

pub fn os_rng() -> OsRng {
    UnwrapErr(SysRng)
}

const ENTRY_HASH_CTX: &str = "memsovereign 2026-11-25 entry-hash";
const ATTACHMENTS_HASH_CTX: &str = "memsovereign 2026-11-25 attachments-hash";
const PROVENANCE_HASH_CTX: &str = "memsovereign 2026-11-25 provenance-hash";
const RECEIPT_STATEMENT_CTX: &str = "memsovereign 2026-11-25 receipt-statement";
const CHECKPOINT_STATEMENT_CTX: &str = "memsovereign 2026-11-25 checkpoint-statement";

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn b64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode")
}

pub fn decode_b64_32(s: &str) -> anyhow::Result<Hash32> {
    let bytes = b64_decode(s)?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_b64_24(s: &str) -> anyhow::Result<[u8; 24]> {
    let bytes = b64_decode(s)?;
    if bytes.len() != 24 {
        anyhow::bail!("expected 24 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 24];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// BLAKE3 derive-key hash. `context` must be a hardcoded application string.
pub fn domain_hash(context: &'static str, data: &[u8]) -> Hash32 {
    debug_assert!(!context.is_empty());
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(data);
    hasher.finalize().into()
}

fn canonical_hash<T: serde::Serialize + ?Sized>(
    context: &'static str,
    value: &T,
) -> anyhow::Result<Hash32> {
    let bytes = serde_json::to_vec(value).context("canonical json")?;
    Ok(domain_hash(context, &bytes))
}

pub fn entry_hash(unsigned: &EntryUnsigned) -> anyhow::Result<Hash32> {
    canonical_hash(ENTRY_HASH_CTX, unsigned)
}

pub fn attachments_hash(attachments: &[Attachment]) -> anyhow::Result<Hash32> {
    canonical_hash(ATTACHMENTS_HASH_CTX, attachments)
}

pub fn receipt_statement_hash(unsigned: &ReceiptUnsigned) -> anyhow::Result<Hash32> {
    canonical_hash(RECEIPT_STATEMENT_CTX, unsigned)
}

pub fn checkpoint_statement_hash(unsigned: &CheckpointUnsigned) -> anyhow::Result<Hash32> {
    canonical_hash(CHECKPOINT_STATEMENT_CTX, unsigned)
}

fn provenance_hash(provenance: &Provenance) -> anyhow::Result<Hash32> {
    canonical_hash(PROVENANCE_HASH_CTX, provenance)
}

/// Associated data bound to a ciphertext.
///
/// Covers the index, previous hash, timestamp, provenance, and attachments.
/// [`crate::open_entry`] rebuilds this itself; do not decrypt an entry by
/// calling [`decrypt_xchacha20poly1305`] with empty associated data.
pub fn seal_aad(
    index: u64,
    prev_hash: &Hash32,
    created_at: &str,
    provenance: &Provenance,
    attachments: &[Attachment],
) -> anyhow::Result<Vec<u8>> {
    let created_at_bytes = created_at.as_bytes();
    if created_at_bytes.len() > u16::MAX as usize {
        anyhow::bail!("created_at too long");
    }
    let prov_hash = provenance_hash(provenance)?;
    let att_hash = attachments_hash(attachments)?;
    let mut aad = Vec::with_capacity(8 + 32 + 2 + created_at_bytes.len() + 32 + 32 + 24);
    aad.extend_from_slice(b"memsovereign seal-aad v1\0");
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(prev_hash);
    aad.extend_from_slice(&(created_at_bytes.len() as u16).to_le_bytes());
    aad.extend_from_slice(created_at_bytes);
    aad.extend_from_slice(&prov_hash);
    aad.extend_from_slice(&att_hash);
    Ok(aad)
}

fn statement(label: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(16 + label.len() + 8 + payload.len());
    message.extend_from_slice(b"memsovereign\0");
    message.extend_from_slice(label);
    message.push(0);
    message.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    message.extend_from_slice(payload);
    message
}

pub fn entry_signing_message(entry_hash: &Hash32) -> Vec<u8> {
    statement(b"entry-signature v1", entry_hash)
}

pub fn head_signing_message(index: Option<u64>, entry_hash: &Hash32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 8 + 32);
    match index {
        None => payload.push(0),
        Some(i) => {
            payload.push(1);
            payload.extend_from_slice(&i.to_le_bytes());
        }
    }
    payload.extend_from_slice(entry_hash);
    statement(b"head-signature v1", &payload)
}

pub fn receipt_signing_message(statement_hash: &Hash32) -> Vec<u8> {
    statement(b"receipt-signature v1", statement_hash)
}

pub fn checkpoint_signing_message(statement_hash: &Hash32) -> Vec<u8> {
    statement(b"checkpoint-signature v1", statement_hash)
}

pub fn now_rfc3339() -> anyhow::Result<String> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .context("format current time as RFC3339")
}

/// Seal `plaintext` under `key32`.
///
/// The nonce is a fresh 192-bit value from the OS CSPRNG. This function does
/// not accept a caller-supplied nonce.
pub fn encrypt_xchacha20poly1305(
    key32: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> anyhow::Result<([u8; 24], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new_from_slice(key32).context("content key length")?;
    let nonce = XNonce::try_generate().context("OS CSPRNG failed while generating a nonce")?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .context("encrypt")?;
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(nonce.as_ref());
    Ok((nonce_bytes, ciphertext))
}

pub fn decrypt_xchacha20poly1305(
    key32: &[u8; 32],
    nonce24: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key32).context("content key length")?;
    let nonce = XNonce::try_from(nonce24.as_slice()).context("nonce length")?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .context("decrypt")
}
