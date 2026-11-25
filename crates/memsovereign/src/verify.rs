use crate::crypto::{
    attachments_hash, b64, b64_decode, checkpoint_signing_message, checkpoint_statement_hash,
    decode_b64_32, entry_hash, entry_signing_message, head_signing_message,
    receipt_signing_message, receipt_statement_hash,
};
use crate::store::{self, load_keys};
use crate::types::{
    Checkpoint, CheckpointUnsigned, Entry, EntryUnsigned, LogHead, Receipt, ReceiptUnsigned,
};
use anyhow::Context;
use ed25519_dalek::{Signature, VerifyingKey};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("entry {index}: entry_hash mismatch")]
    EntryHashMismatch { index: u64 },
    #[error("entry {index}: prev_entry_hash mismatch")]
    PrevHashMismatch { index: u64 },
    #[error("entry {index}: expected index {expected}")]
    IndexMismatch { index: u64, expected: u64 },
    #[error("entry {index}: signature invalid")]
    InvalidEntrySignature { index: u64 },
    #[error("receipt signature invalid")]
    InvalidReceiptSignature,
    #[error("receipt does not match log entry {index}")]
    ReceiptEntryMismatch { index: u64 },
    #[error("log head is missing")]
    MissingLogHead,
    #[error("log head signature invalid")]
    InvalidHeadSignature,
    #[error("log head does not match the chain tip")]
    LogHeadMismatch,
    #[error("checkpoint statement_hash mismatch")]
    CheckpointStatementHashMismatch,
    #[error("checkpoint signature invalid")]
    InvalidCheckpointSignature,
    #[error("checkpoint does not match current chain head")]
    CheckpointHeadMismatch,
}

pub(crate) struct ChainState {
    pub entries: Vec<Entry>,
    pub tip_index: Option<u64>,
    pub tip_hash: [u8; 32],
}

pub fn verify_chain(home: &Path) -> anyhow::Result<()> {
    verify_chain_up_to(home, None)
}

/// Verify every entry signature and the signed log head.
///
/// When `max_index` is set, the full chain is still checked, and this also
/// requires an entry with that index.
pub fn verify_chain_up_to(home: &Path, max_index: Option<u64>) -> anyhow::Result<()> {
    let _lock = store::LogLock::acquire(home)?;
    let state = inspect_chain(home)?;
    if let Some(max) = max_index {
        if !state.entries.iter().any(|entry| entry.index == max) {
            anyhow::bail!(
                "log ended at {:?} before reaching requested index {max}",
                state.tip_index
            );
        }
    }
    Ok(())
}

pub(crate) fn inspect_chain(home: &Path) -> anyhow::Result<ChainState> {
    let keys = load_keys(home)?;
    let identity = keys.identity()?;
    let entries = store::read_entries_unlocked(home)?;
    let mut prev_hash = [0u8; 32];

    for (position, entry) in entries.iter().enumerate() {
        let expected = u64::try_from(position).context("entry index")?;
        if entry.index != expected {
            return Err(VerifyError::IndexMismatch {
                index: entry.index,
                expected,
            }
            .into());
        }

        let stored_prev = decode_b64_32(&entry.prev_entry_hash_b64)
            .with_context(|| format!("entry {}: prev hash", entry.index))?;
        if stored_prev != prev_hash {
            return Err(VerifyError::PrevHashMismatch { index: entry.index }.into());
        }

        let unsigned = EntryUnsigned::from_entry(entry);
        let calculated = entry_hash(&unsigned)?;
        let stored_hash = decode_b64_32(&entry.entry_hash_b64)
            .with_context(|| format!("entry {}: entry hash", entry.index))?;
        if stored_hash != calculated {
            return Err(VerifyError::EntryHashMismatch { index: entry.index }.into());
        }

        let signature = parse_signature(&entry.signature_b64)?;
        identity
            .verifying
            .verify_strict(&entry_signing_message(&calculated), &signature)
            .map_err(|_| VerifyError::InvalidEntrySignature { index: entry.index })?;
        prev_hash = calculated;
    }

    let tip_index = entries.last().map(|entry| entry.index);
    check_head(home, &entries, tip_index, &prev_hash, &identity.verifying)?;
    Ok(ChainState {
        entries,
        tip_index,
        tip_hash: prev_hash,
    })
}

fn check_head(
    home: &Path,
    entries: &[Entry],
    tip_index: Option<u64>,
    tip_hash: &[u8; 32],
    verifying: &VerifyingKey,
) -> anyhow::Result<()> {
    let Some(head) = store::read_head(home)? else {
        return Err(VerifyError::MissingLogHead.into());
    };
    verify_head_signature(&head, verifying)?;
    let head_hash = decode_b64_32(&head.entry_hash_b64).context("log head hash")?;

    if head.index == tip_index && head_hash == *tip_hash {
        return Ok(());
    }

    // One signed entry may sit ahead of HEAD if the process crashed after
    // appending the line and before replacing HEAD.json. The entry is already
    // signed, so this does not let an attacker extend the log.
    if let Some(tip) = entries.last() {
        let one_ahead = match head.index {
            None => tip.index == 0 && entries.len() == 1,
            Some(index) => tip.index == index + 1,
        };
        if one_ahead {
            let committed = match head.index {
                None => true,
                Some(index) => entries.iter().any(|entry| {
                    entry.index == index
                        && decode_b64_32(&entry.entry_hash_b64).ok() == Some(head_hash)
                }),
            };
            let tip_prev = decode_b64_32(&tip.prev_entry_hash_b64)?;
            if committed && tip_prev == head_hash {
                return Ok(());
            }
        }
    }

    Err(VerifyError::LogHeadMismatch.into())
}

fn verify_head_signature(head: &LogHead, verifying: &VerifyingKey) -> anyhow::Result<()> {
    let hash = decode_b64_32(&head.entry_hash_b64).context("log head hash")?;
    let signature = parse_signature(&head.signature_b64)?;
    verifying
        .verify_strict(&head_signing_message(head.index, &hash), &signature)
        .map_err(|_| VerifyError::InvalidHeadSignature)?;
    Ok(())
}

pub fn verify_receipt(receipt: &Receipt) -> anyhow::Result<()> {
    let unsigned = ReceiptUnsigned {
        agent_pubkey_b64: receipt.agent_pubkey_b64.clone(),
        entry_hash_b64: receipt.entry_hash_b64.clone(),
        attachments_hash_b64: receipt.attachments_hash_b64.clone(),
        index: receipt.index,
        created_at: receipt.created_at.clone(),
    };
    let calculated = receipt_statement_hash(&unsigned)?;
    let stored = decode_b64_32(&receipt.statement_hash_b64).context("statement_hash")?;
    if stored != calculated {
        anyhow::bail!("receipt statement_hash mismatch");
    }

    let pubkey = b64_decode(&receipt.agent_pubkey_b64)?;
    if pubkey.len() != 32 {
        anyhow::bail!("pubkey not 32 bytes");
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pubkey);
    let verifying = VerifyingKey::from_bytes(&pk32).context("verifying key")?;
    let signature = parse_signature(&receipt.signature_b64)?;
    verifying
        .verify_strict(&receipt_signing_message(&calculated), &signature)
        .map_err(|_| VerifyError::InvalidReceiptSignature)?;
    Ok(())
}

/// Check the receipt signature and that it names the entry stored at its index.
pub fn verify_receipt_against_log(home: &Path, receipt: &Receipt) -> anyhow::Result<()> {
    verify_receipt(receipt)?;
    let _lock = store::LogLock::acquire(home)?;
    let keys = load_keys(home)?;
    if receipt.agent_pubkey_b64 != b64(&keys.ed25519_public) {
        anyhow::bail!("receipt public key does not match the local identity");
    }
    let state = inspect_chain(home)?;
    let Some(entry) = state
        .entries
        .iter()
        .find(|entry| entry.index == receipt.index)
    else {
        anyhow::bail!("log has no entry at index {}", receipt.index);
    };
    let att_hash = attachments_hash(&entry.attachments)?;
    if entry.entry_hash_b64 != receipt.entry_hash_b64
        || entry.created_at != receipt.created_at
        || receipt.attachments_hash_b64 != b64(&att_hash)
    {
        return Err(VerifyError::ReceiptEntryMismatch {
            index: receipt.index,
        }
        .into());
    }
    Ok(())
}

pub fn verify_checkpoint(checkpoint: &Checkpoint) -> anyhow::Result<()> {
    let unsigned = CheckpointUnsigned {
        agent_pubkey_b64: checkpoint.agent_pubkey_b64.clone(),
        label: checkpoint.label.clone(),
        created_at: checkpoint.created_at.clone(),
        head_index: checkpoint.head_index,
        head_hash_b64: checkpoint.head_hash_b64.clone(),
    };
    let calculated = checkpoint_statement_hash(&unsigned)?;
    let stored = decode_b64_32(&checkpoint.statement_hash_b64).context("statement_hash")?;
    if stored != calculated {
        return Err(VerifyError::CheckpointStatementHashMismatch.into());
    }

    let pubkey = b64_decode(&checkpoint.agent_pubkey_b64)?;
    if pubkey.len() != 32 {
        anyhow::bail!("pubkey not 32 bytes");
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pubkey);
    let verifying = VerifyingKey::from_bytes(&pk32).context("verifying key")?;
    let signature = parse_signature(&checkpoint.signature_b64)?;
    verifying
        .verify_strict(&checkpoint_signing_message(&calculated), &signature)
        .map_err(|_| VerifyError::InvalidCheckpointSignature)?;
    Ok(())
}

pub fn verify_checkpoint_matches_chain(home: &Path, checkpoint: &Checkpoint) -> anyhow::Result<()> {
    verify_checkpoint(checkpoint)?;
    let _lock = store::LogLock::acquire(home)?;
    let state = inspect_chain(home)?;
    let current = b64(&state.tip_hash);
    if checkpoint.head_hash_b64 != current || checkpoint.head_index != state.tip_index {
        return Err(VerifyError::CheckpointHeadMismatch.into());
    }
    Ok(())
}

fn parse_signature(encoded: &str) -> anyhow::Result<Signature> {
    let bytes = b64_decode(encoded).context("signature base64")?;
    Signature::from_slice(&bytes).context("signature")
}
