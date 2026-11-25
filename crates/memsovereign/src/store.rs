use crate::crypto::{
    attachments_hash, b64, checkpoint_signing_message, checkpoint_statement_hash, entry_hash,
    entry_signing_message, head_signing_message, now_rfc3339, receipt_signing_message,
    receipt_statement_hash, seal_aad,
};
use crate::keys::{fingerprint_pubkey, read_exact_32, write_file_atomic, StoredKeys};
use crate::paths;
use crate::types::{
    Attachment, Checkpoint, Entry, EntryUnsigned, LogHead, Provenance, Receipt, ReceiptUnsigned,
};
use crate::verify::{self, ChainState};
use anyhow::Context;
use ed25519_dalek::Signer;
use rand_core::CryptoRng;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct InitResult {
    pub home: PathBuf,
    pub pubkey_fingerprint: String,
}

pub(crate) struct LogLock {
    file: std::fs::File,
}

impl LogLock {
    pub(crate) fn acquire(home: &Path) -> anyhow::Result<Self> {
        let dir = paths::log_dir(home);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {dir:?}"))?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(paths::lock_path(home))
            .context("open log lock")?;
        file.lock().context("lock log")?;
        Ok(Self { file })
    }
}

impl Drop for LogLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub fn init_keys(home: &Path, force: bool, rng: &mut impl CryptoRng) -> anyhow::Result<InitResult> {
    let keys_dir = paths::keys_dir(home);
    std::fs::create_dir_all(&keys_dir).with_context(|| format!("create {keys_dir:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700))
            .context("set keys directory permissions")?;
    }

    let secret_path = keys_dir.join("identity_ed25519");
    let pub_path = keys_dir.join("identity_ed25519.pub");
    let content_path = keys_dir.join("content_key");

    if !force && (secret_path.exists() || pub_path.exists() || content_path.exists()) {
        anyhow::bail!("keys already exist (use --force to overwrite)");
    }

    let _lock = LogLock::acquire(home)?;
    if log_has_entries(home)? {
        anyhow::bail!("refusing to write keys while log/entries.jsonl is non-empty");
    }

    let keys = StoredKeys::generate(rng)?;
    write_file_atomic(&secret_path, &keys.ed25519_secret)?;
    write_file_atomic(&pub_path, &keys.ed25519_public)?;
    write_file_atomic(&content_path, &keys.content_key)?;
    write_empty_head(home, &keys)?;

    Ok(InitResult {
        home: home.to_path_buf(),
        pubkey_fingerprint: fingerprint_pubkey(&keys.ed25519_public),
    })
}

fn log_has_entries(home: &Path) -> anyhow::Result<bool> {
    let path = paths::entries_path(home);
    if !path.exists() {
        return Ok(false);
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
    Ok(text.lines().any(|line| !line.trim().is_empty()))
}

pub fn load_keys(home: &Path) -> anyhow::Result<StoredKeys> {
    let keys_dir = paths::keys_dir(home);
    Ok(StoredKeys {
        ed25519_secret: read_exact_32(&keys_dir.join("identity_ed25519"))?,
        ed25519_public: read_exact_32(&keys_dir.join("identity_ed25519.pub"))?,
        content_key: read_exact_32(&keys_dir.join("content_key"))?,
    })
}

pub(crate) fn read_entries_unlocked(home: &Path) -> anyhow::Result<Vec<Entry>> {
    let path = paths::entries_path(home);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
    let mut entries = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: Entry = serde_json::from_str(line)
            .with_context(|| format!("parse entry json on line {}", line_no + 1))?;
        entries.push(entry);
    }
    Ok(entries)
}

pub fn read_entries(home: &Path) -> anyhow::Result<Vec<Entry>> {
    let _lock = LogLock::acquire(home)?;
    read_entries_unlocked(home)
}

pub(crate) fn read_head(home: &Path) -> anyhow::Result<Option<LogHead>> {
    let path = paths::head_path(home);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
    let head = serde_json::from_str(&text).context("parse log head")?;
    Ok(Some(head))
}

fn write_head_file(home: &Path, head: &LogHead) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(head).context("serialize log head")?;
    write_file_atomic(&paths::head_path(home), &json)
}

fn write_empty_head(home: &Path, keys: &StoredKeys) -> anyhow::Result<()> {
    let id = keys.identity()?;
    let hash = [0u8; 32];
    let signature = id
        .signing
        .try_sign(&head_signing_message(None, &hash))
        .context("sign empty log head")?;
    write_head_file(
        home,
        &LogHead {
            index: None,
            entry_hash_b64: b64(&hash),
            signature_b64: b64(&signature.to_bytes()),
        },
    )
}

fn write_head_for_tip(
    home: &Path,
    keys: &StoredKeys,
    index: u64,
    entry_hash: &[u8; 32],
) -> anyhow::Result<()> {
    let id = keys.identity()?;
    let signature = id
        .signing
        .try_sign(&head_signing_message(Some(index), entry_hash))
        .context("sign log head")?;
    write_head_file(
        home,
        &LogHead {
            index: Some(index),
            entry_hash_b64: b64(entry_hash),
            signature_b64: b64(&signature.to_bytes()),
        },
    )
}

pub fn append_entry(
    home: &Path,
    content: &str,
    provenance: Provenance,
    attachments: Vec<Attachment>,
) -> anyhow::Result<(Entry, Receipt)> {
    let _lock = LogLock::acquire(home)?;
    let keys = load_keys(home)?;
    let id = keys.identity()?;
    let state = verify::inspect_chain(home)?;
    let index = u64::try_from(state.entries.len()).context("entry index")?;
    let prev_hash = state.tip_hash;
    let created_at = now_rfc3339()?;

    let aad = seal_aad(index, &prev_hash, &created_at, &provenance, &attachments)?;
    let (nonce, ciphertext) =
        crate::crypto::encrypt_xchacha20poly1305(&keys.content_key, content.as_bytes(), &aad)?;

    let unsigned = EntryUnsigned {
        index,
        created_at: created_at.clone(),
        provenance: provenance.clone(),
        attachments: attachments.clone(),
        nonce_b64: b64(&nonce),
        ciphertext_b64: b64(&ciphertext),
        prev_entry_hash_b64: b64(&prev_hash),
    };
    let digest = entry_hash(&unsigned)?;
    let signature = id
        .signing
        .try_sign(&entry_signing_message(&digest))
        .context("sign entry")?;

    let entry = Entry {
        index,
        created_at: created_at.clone(),
        provenance,
        attachments: attachments.clone(),
        nonce_b64: unsigned.nonce_b64,
        ciphertext_b64: unsigned.ciphertext_b64,
        prev_entry_hash_b64: unsigned.prev_entry_hash_b64,
        entry_hash_b64: b64(&digest),
        signature_b64: b64(&signature.to_bytes()),
    };

    let entries_path = paths::entries_path(home);
    if let Some(parent) = entries_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {parent:?}"))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&entries_path)
        .with_context(|| format!("open {entries_path:?} for append"))?;
    let line = serde_json::to_string(&entry).context("serialize entry")?;
    writeln!(file, "{line}").context("write jsonl")?;
    file.sync_all().context("sync log")?;

    let att_hash = attachments_hash(&attachments)?;
    let receipt_unsigned = ReceiptUnsigned {
        agent_pubkey_b64: b64(&keys.ed25519_public),
        entry_hash_b64: b64(&digest),
        attachments_hash_b64: b64(&att_hash),
        index,
        created_at: created_at.clone(),
    };
    let statement_hash = receipt_statement_hash(&receipt_unsigned)?;
    let receipt_signature = id
        .signing
        .try_sign(&receipt_signing_message(&statement_hash))
        .context("sign receipt")?;
    let receipt = Receipt {
        agent_pubkey_b64: receipt_unsigned.agent_pubkey_b64,
        entry_hash_b64: receipt_unsigned.entry_hash_b64,
        attachments_hash_b64: receipt_unsigned.attachments_hash_b64,
        index,
        created_at,
        statement_hash_b64: b64(&statement_hash),
        signature_b64: b64(&receipt_signature.to_bytes()),
    };
    save_receipt(home, &receipt)?;
    write_head_for_tip(home, &keys, index, &digest)?;

    Ok((entry, receipt))
}

/// Decrypt one entry.
///
/// Rebuilds the AEAD associated data from the entry fields. A wrong content
/// key, a modified ciphertext, or a modified bound field (timestamp,
/// provenance, attachments, index, previous hash) fails closed.
pub fn open_entry(content_key: &[u8; 32], entry: &Entry) -> anyhow::Result<Vec<u8>> {
    let prev_hash = crate::crypto::decode_b64_32(&entry.prev_entry_hash_b64)?;
    let nonce = crate::crypto::decode_b64_24(&entry.nonce_b64)?;
    let ciphertext = crate::crypto::b64_decode(&entry.ciphertext_b64)?;
    let aad = seal_aad(
        entry.index,
        &prev_hash,
        &entry.created_at,
        &entry.provenance,
        &entry.attachments,
    )?;
    crate::crypto::decrypt_xchacha20poly1305(content_key, &nonce, &ciphertext, &aad)
}

pub fn save_receipt(home: &Path, receipt: &Receipt) -> anyhow::Result<PathBuf> {
    let path = paths::receipt_path(home, receipt.index);
    let json = serde_json::to_vec_pretty(receipt).context("serialize receipt")?;
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

/// Returns `(head_index, head_hash)` after a successful chain verification.
///
/// An empty log yields `(None, [0u8; 32])`.
pub fn head_state(home: &Path) -> anyhow::Result<(Option<u64>, [u8; 32])> {
    let _lock = LogLock::acquire(home)?;
    let state = verify::inspect_chain(home)?;
    Ok((state.tip_index, state.tip_hash))
}

pub(crate) fn chain_tip(state: &ChainState) -> (Option<u64>, [u8; 32]) {
    (state.tip_index, state.tip_hash)
}

fn validate_checkpoint_label(label: &str) -> anyhow::Result<()> {
    if label.is_empty() {
        anyhow::bail!("label must not be empty");
    }
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
) -> anyhow::Result<(Checkpoint, PathBuf)> {
    let _lock = LogLock::acquire(home)?;
    let keys = load_keys(home)?;
    let id = keys.identity()?;
    let state = verify::inspect_chain(home)?;
    let (head_index, head_hash) = chain_tip(&state);

    let created_at = now_rfc3339()?;
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
    let statement_hash = checkpoint_statement_hash(&unsigned)?;
    let signature = id
        .signing
        .try_sign(&checkpoint_signing_message(&statement_hash))
        .context("sign checkpoint")?;
    let checkpoint = Checkpoint {
        agent_pubkey_b64: unsigned.agent_pubkey_b64,
        label,
        created_at,
        head_index,
        head_hash_b64: unsigned.head_hash_b64,
        statement_hash_b64: b64(&statement_hash),
        signature_b64: b64(&signature.to_bytes()),
    };

    let path = checkpoint_path(home, &checkpoint.label)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {parent:?}"))?;
    }
    let json = serde_json::to_vec_pretty(&checkpoint).context("serialize checkpoint")?;
    std::fs::write(&path, json).with_context(|| format!("write {path:?}"))?;

    Ok((checkpoint, path))
}
