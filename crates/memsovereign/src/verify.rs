use crate::crypto::{b64_decode, blake3_hash};
use crate::paths;
use crate::types::{
    Checkpoint, CheckpointUnsigned, Entry, EntryUnsigned, Receipt, ReceiptUnsigned,
};
use anyhow::Context;
use ed25519_dalek::{Signature, VerifyingKey};
use std::io::BufRead;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("entry {index}: entry_hash mismatch")]
    EntryHashMismatch { index: u64 },
    #[error("entry {index}: prev_entry_hash mismatch")]
    PrevHashMismatch { index: u64 },
    #[error("receipt signature invalid")]
    InvalidReceiptSignature,

    #[error("checkpoint statement_hash mismatch")]
    CheckpointStatementHashMismatch,
    #[error("checkpoint signature invalid")]
    InvalidCheckpointSignature,
    #[error("checkpoint does not match current chain head")]
    CheckpointHeadMismatch,
}

pub fn verify_chain(home: &Path) -> anyhow::Result<()> {
    verify_chain_up_to(home, None)
}

/// Verify the hash chain, optionally stopping after verifying `max_index`.
pub fn verify_chain_up_to(home: &Path, max_index: Option<u64>) -> anyhow::Result<()> {
    let path = paths::entries_path(home);
    if !path.exists() {
        return Ok(());
    }
    let f = std::fs::File::open(&path).with_context(|| format!("open {path:?}"))?;
    let reader = std::io::BufReader::new(f);

    let mut prev_hash = [0u8; 32];
    let mut last_index: Option<u64> = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: Entry = serde_json::from_str(&line).context("parse entry")?;
        last_index = Some(entry.index);

        let prev = b64_decode(&entry.prev_entry_hash_b64)?;
        if prev.len() != 32 {
            anyhow::bail!("entry {}: prev hash not 32 bytes", entry.index);
        }
        if prev.as_slice() != prev_hash {
            return Err(VerifyError::PrevHashMismatch { index: entry.index }.into());
        }

        let unsigned = EntryUnsigned {
            index: entry.index,
            created_at: entry.created_at.clone(),
            provenance: entry.provenance.clone(),
            attachments: entry.attachments.clone(),
            nonce_b64: entry.nonce_b64.clone(),
            ciphertext_b64: entry.ciphertext_b64.clone(),
            prev_entry_hash_b64: entry.prev_entry_hash_b64.clone(),
        };
        let canon = serde_json::to_vec(&unsigned).context("serialize unsigned")?;
        let calc = blake3_hash(&canon);
        let stored = b64_decode(&entry.entry_hash_b64)?;
        if stored.len() != 32 {
            anyhow::bail!("entry {}: entry hash not 32 bytes", entry.index);
        }
        if stored.as_slice() != calc {
            return Err(VerifyError::EntryHashMismatch { index: entry.index }.into());
        }
        prev_hash.copy_from_slice(&calc);

        if let Some(max) = max_index {
            if entry.index == max {
                return Ok(());
            }
        }
    }

    if let Some(max) = max_index {
        anyhow::bail!(
            "log ended at {:?} before reaching requested index {max}",
            last_index
        );
    }

    Ok(())
}

pub fn verify_receipt(receipt: &Receipt) -> anyhow::Result<()> {
    // Recompute statement hash.
    let unsigned = ReceiptUnsigned {
        agent_pubkey_b64: receipt.agent_pubkey_b64.clone(),
        entry_hash_b64: receipt.entry_hash_b64.clone(),
        attachments_hash_b64: receipt.attachments_hash_b64.clone(),
        index: receipt.index,
        created_at: receipt.created_at.clone(),
    };
    let canon = serde_json::to_vec(&unsigned).context("serialize receipt unsigned")?;
    let calc = blake3_hash(&canon);
    let stored = b64_decode(&receipt.statement_hash_b64)?;
    if stored.len() != 32 {
        anyhow::bail!("statement_hash not 32 bytes");
    }
    if stored.as_slice() != calc {
        anyhow::bail!("receipt statement_hash mismatch");
    }

    // Verify signature over statement_hash.
    let pubkey = b64_decode(&receipt.agent_pubkey_b64)?;
    if pubkey.len() != 32 {
        anyhow::bail!("pubkey not 32 bytes");
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pubkey);
    let vk = VerifyingKey::from_bytes(&pk32).context("verifying key")?;

    let sig_bytes = b64_decode(&receipt.signature_b64)?;
    let sig = Signature::from_slice(&sig_bytes).context("signature")?;

    vk.verify_strict(&calc, &sig)
        .map_err(|_| VerifyError::InvalidReceiptSignature.into())
}

pub fn verify_checkpoint(checkpoint: &Checkpoint) -> anyhow::Result<()> {
    // Verify statement hash.
    let unsigned = CheckpointUnsigned {
        agent_pubkey_b64: checkpoint.agent_pubkey_b64.clone(),
        label: checkpoint.label.clone(),
        created_at: checkpoint.created_at.clone(),
        head_index: checkpoint.head_index,
        head_hash_b64: checkpoint.head_hash_b64.clone(),
    };
    let canon = serde_json::to_vec(&unsigned).context("serialize checkpoint unsigned")?;
    let calc = blake3_hash(&canon);
    let stored = b64_decode(&checkpoint.statement_hash_b64)?;
    if stored.len() != 32 {
        anyhow::bail!("statement_hash not 32 bytes");
    }
    if stored.as_slice() != calc {
        return Err(VerifyError::CheckpointStatementHashMismatch.into());
    }

    // Verify signature over statement_hash.
    let pubkey = b64_decode(&checkpoint.agent_pubkey_b64)?;
    if pubkey.len() != 32 {
        anyhow::bail!("pubkey not 32 bytes");
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pubkey);
    let vk = VerifyingKey::from_bytes(&pk32).context("verifying key")?;

    let sig_bytes = b64_decode(&checkpoint.signature_b64)?;
    let sig = Signature::from_slice(&sig_bytes).context("signature")?;

    vk.verify_strict(&calc, &sig)
        .map_err(|_| VerifyError::InvalidCheckpointSignature.into())
}

pub fn verify_checkpoint_matches_chain(home: &Path, checkpoint: &Checkpoint) -> anyhow::Result<()> {
    verify_checkpoint(checkpoint)?;

    // Compare to current head.
    let (cur_head_index, cur_head_hash) = crate::store::head_state(home)?;
    let cur_b64 = crate::crypto::b64(&cur_head_hash);

    if checkpoint.head_hash_b64 != cur_b64 || checkpoint.head_index != cur_head_index {
        return Err(VerifyError::CheckpointHeadMismatch.into());
    }

    Ok(())
}
