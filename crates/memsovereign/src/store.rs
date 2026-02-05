use crate::crypto::{b64, blake3_hash, now_rfc3339};
use crate::keys::{fingerprint_pubkey, read_exact_32, write_file_atomic, StoredKeys};
use crate::paths;
use crate::types::{Attachment, Entry, EntryUnsigned, Provenance, Receipt, ReceiptUnsigned};
use anyhow::Context;
use ed25519_dalek::Signer;
use rand_core::CryptoRngCore;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct InitResult {
    pub home: PathBuf,
    pub pubkey_fingerprint: String,
}

pub fn init_keys(
    home: &Path,
    force: bool,
    mut rng: impl CryptoRngCore,
) -> anyhow::Result<InitResult> {
    let keys_dir = paths::keys_dir(home);
    std::fs::create_dir_all(&keys_dir).with_context(|| format!("create {keys_dir:?}"))?;

    let secret_path = keys_dir.join("identity_ed25519");
    let pub_path = keys_dir.join("identity_ed25519.pub");
    let content_path = keys_dir.join("content_key");

    if !force && (secret_path.exists() || pub_path.exists() || content_path.exists()) {
        anyhow::bail!("keys already exist (use --force to overwrite)");
    }

    let keys = StoredKeys::generate(&mut rng);
    write_file_atomic(&secret_path, &keys.ed25519_secret)?;
    write_file_atomic(&pub_path, &keys.ed25519_public)?;
    write_file_atomic(&content_path, &keys.content_key)?;

    Ok(InitResult {
        home: home.to_path_buf(),
        pubkey_fingerprint: fingerprint_pubkey(&keys.ed25519_public),
    })
}

pub fn load_keys(home: &Path) -> anyhow::Result<StoredKeys> {
    let keys_dir = paths::keys_dir(home);
    let secret_path = keys_dir.join("identity_ed25519");
    let pub_path = keys_dir.join("identity_ed25519.pub");
    let content_path = keys_dir.join("content_key");

    Ok(StoredKeys {
        ed25519_secret: read_exact_32(&secret_path)?,
        ed25519_public: read_exact_32(&pub_path)?,
        content_key: read_exact_32(&content_path)?,
    })
}

fn last_entry_state(entries_path: &Path) -> anyhow::Result<(u64, [u8; 32])> {
    if !entries_path.exists() {
        return Ok((0, [0u8; 32]));
    }
    let f = std::fs::File::open(entries_path).with_context(|| format!("open {entries_path:?}"))?;
    let reader = std::io::BufReader::new(f);
    let mut last: Option<Entry> = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        last = Some(serde_json::from_str(&line).context("parse entry json")?);
    }
    let last = last.ok_or_else(|| anyhow::anyhow!("entries file exists but is empty"))?;
    let prev = crate::crypto::b64_decode(&last.entry_hash_b64)?;
    if prev.len() != 32 {
        anyhow::bail!("invalid entry_hash len");
    }
    let mut prev32 = [0u8; 32];
    prev32.copy_from_slice(&prev);
    Ok((last.index + 1, prev32))
}

pub fn append_entry(
    home: &Path,
    content: &str,
    provenance: Provenance,
    attachments: Vec<Attachment>,
    mut rng: impl CryptoRngCore,
) -> anyhow::Result<(Entry, Receipt)> {
    let keys = load_keys(home)?;
    let id = keys.identity()?;

    let entries_path = paths::entries_path(home);
    if let Some(parent) = entries_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {parent:?}"))?;
    }

    let (index, prev_hash) = last_entry_state(&entries_path)?;

    // Deterministic fields.
    let created_at = now_rfc3339();

    // Encrypt.
    // Bind ciphertext to context so tampering provenance/timestamp/attachments can be detected at decrypt-time.
    // AAD = index || prev_hash || len(created_at) || created_at || blake3(provenance_json) || blake3(attachments_json)
    let prov_json = serde_json::to_vec(&provenance).context("serialize provenance")?;
    let prov_hash = blake3_hash(&prov_json);
    let att_json = serde_json::to_vec(&attachments).context("serialize attachments")?;
    let att_hash = blake3_hash(&att_json);
    let created_at_bytes = created_at.as_bytes();
    if created_at_bytes.len() > u16::MAX as usize {
        anyhow::bail!("created_at too long");
    }
    let aad = {
        let mut aad = Vec::with_capacity(8 + 32 + 2 + created_at_bytes.len() + 32 + 32);
        aad.extend_from_slice(&index.to_le_bytes());
        aad.extend_from_slice(&prev_hash);
        aad.extend_from_slice(&(created_at_bytes.len() as u16).to_le_bytes());
        aad.extend_from_slice(created_at_bytes);
        aad.extend_from_slice(&prov_hash);
        aad.extend_from_slice(&att_hash);
        aad
    };
    let (nonce, ciphertext) = crate::crypto::encrypt_xchacha20poly1305(
        &keys.content_key,
        content.as_bytes(),
        &aad,
        &mut rng,
    )?;

    // Canonical data for hash: unsigned struct serialized as JSON.
    let unsigned = EntryUnsigned {
        index,
        created_at: created_at.clone(),
        provenance: provenance.clone(),
        attachments: attachments.clone(),
        nonce_b64: b64(&nonce),
        ciphertext_b64: b64(&ciphertext),
        prev_entry_hash_b64: b64(&prev_hash),
    };
    let canon = serde_json::to_vec(&unsigned).context("serialize unsigned")?;
    let entry_hash = blake3_hash(&canon);

    let entry = Entry {
        index,
        created_at: created_at.clone(),
        provenance,
        attachments,
        nonce_b64: unsigned.nonce_b64,
        ciphertext_b64: unsigned.ciphertext_b64,
        prev_entry_hash_b64: unsigned.prev_entry_hash_b64,
        entry_hash_b64: b64(&entry_hash),
    };

    // Append to JSONL
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&entries_path)
        .with_context(|| format!("open {entries_path:?} for append"))?;
    let line = serde_json::to_string(&entry).context("serialize entry")?;
    writeln!(f, "{}", line).context("write jsonl")?;

    // Receipt
    // Bind attachments explicitly into the signed receipt statement.
    let receipt_unsigned = ReceiptUnsigned {
        agent_pubkey_b64: b64(&keys.ed25519_public),
        entry_hash_b64: b64(&entry_hash),
        attachments_hash_b64: b64(&att_hash),
        index,
        created_at: created_at.clone(),
    };
    let receipt_canon =
        serde_json::to_vec(&receipt_unsigned).context("serialize receipt unsigned")?;
    let statement_hash = blake3_hash(&receipt_canon);
    let sig = id.signing.sign(&statement_hash);
    let receipt = Receipt {
        agent_pubkey_b64: receipt_unsigned.agent_pubkey_b64,
        entry_hash_b64: receipt_unsigned.entry_hash_b64,
        attachments_hash_b64: receipt_unsigned.attachments_hash_b64,
        index,
        created_at,
        statement_hash_b64: b64(&statement_hash),
        signature_b64: b64(sig.to_bytes().as_slice()),
    };

    // Persist receipt locally to enable later export.
    save_receipt(home, &receipt)?;

    Ok((entry, receipt))
}

pub fn save_receipt(home: &Path, receipt: &Receipt) -> anyhow::Result<PathBuf> {
    let path = paths::receipt_path(home, receipt.index);
    let json = serde_json::to_vec_pretty(receipt).context("serialize receipt")?;
    // Receipts are not secret; default perms are fine.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {parent:?}"))?;
    }
    std::fs::write(&path, json).with_context(|| format!("write {path:?}"))?;
    Ok(path)
}

pub fn load_receipt(home: &Path, index: u64) -> anyhow::Result<Receipt> {
    let path = paths::receipt_path(home, index);
    let bytes = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
    let receipt: Receipt = serde_json::from_str(&bytes).context("parse receipt")?;
    Ok(receipt)
}

/// Returns (head_index, head_hash). When the log is empty, head_index=None and head_hash=32 zero bytes.
pub fn head_state(home: &Path) -> anyhow::Result<(Option<u64>, [u8; 32])> {
    let entries_path = paths::entries_path(home);
    let (next_index, head_hash) = last_entry_state(&entries_path)?;
    let head_index = if next_index == 0 {
        None
    } else {
        Some(next_index - 1)
    };
    Ok((head_index, head_hash))
}

fn validate_checkpoint_label(label: &str) -> anyhow::Result<()> {
    if label.is_empty() {
        anyhow::bail!("label must not be empty");
    }
    // Keep labels filename-safe.
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        anyhow::bail!("label contains invalid characters (allowed: A-Z a-z 0-9 - _ .)");
    }
    Ok(())
}

pub fn checkpoint_path(home: &Path, label: &str) -> anyhow::Result<PathBuf> {
    validate_checkpoint_label(label)?;
    Ok(paths::checkpoints_dir(home).join(format!("checkpoint_{label}.json")))
}

pub fn create_checkpoint(
    home: &Path,
    label: Option<&str>,
) -> anyhow::Result<(crate::types::Checkpoint, PathBuf)> {
    let keys = load_keys(home)?;
    let id = keys.identity()?;

    let (head_index, head_hash) = head_state(home)?;
    let created_at = now_rfc3339();
    let default_label = created_at
        .get(0..10)
        .ok_or_else(|| anyhow::anyhow!("invalid created_at"))?;
    let label = label.unwrap_or(default_label).to_string();
    validate_checkpoint_label(&label)?;

    let unsigned = crate::types::CheckpointUnsigned {
        agent_pubkey_b64: b64(&keys.ed25519_public),
        label: label.clone(),
        created_at: created_at.clone(),
        head_index,
        head_hash_b64: b64(&head_hash),
    };
    let canon = serde_json::to_vec(&unsigned).context("serialize checkpoint unsigned")?;
    let statement_hash = blake3_hash(&canon);

    let sig = id.signing.sign(&statement_hash);
    let checkpoint = crate::types::Checkpoint {
        agent_pubkey_b64: unsigned.agent_pubkey_b64,
        label,
        created_at,
        head_index,
        head_hash_b64: unsigned.head_hash_b64,
        statement_hash_b64: b64(&statement_hash),
        signature_b64: b64(sig.to_bytes().as_slice()),
    };

    let path = checkpoint_path(home, &checkpoint.label)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {parent:?}"))?;
    }
    let json = serde_json::to_vec_pretty(&checkpoint).context("serialize checkpoint")?;
    std::fs::write(&path, json).with_context(|| format!("write {path:?}"))?;

    Ok((checkpoint, path))
}
