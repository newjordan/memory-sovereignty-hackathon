use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

// Default is derived.

/// Attachment metadata (no bytes stored in the log).
///
/// This is included in the entry hash chain and bound into encryption AAD so that any tampering with
/// attachment metadata can be detected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attachment {
    /// "file" | "url" | "ref".
    pub kind: String,
    /// Display name (e.g. filename, short label).
    pub name: String,
    /// A locator string (e.g. "file:./path", "https://...", "ipfs://...", "openclaw:...").
    pub locator: String,

    /// Optional sha256 of the attachment bytes, base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_b64: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub index: u64,
    /// RFC3339 timestamp.
    pub created_at: String,
    pub provenance: Provenance,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,

    /// Base64-encoded 24-byte XChaCha20 nonce.
    pub nonce_b64: String,
    /// Base64-encoded ciphertext (includes Poly1305 tag).
    pub ciphertext_b64: String,
    /// Base64-encoded 32-byte previous entry hash.
    pub prev_entry_hash_b64: String,
    /// Base64-encoded 32-byte entry hash.
    pub entry_hash_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    /// Base64-encoded 32-byte Ed25519 public key.
    pub agent_pubkey_b64: String,
    /// Base64-encoded 32-byte entry hash.
    pub entry_hash_b64: String,

    /// Base64-encoded 32-byte hash of `attachments` (blake3 over canonical JSON).
    pub attachments_hash_b64: String,

    pub index: u64,
    pub created_at: String,

    /// Base64-encoded 32-byte statement hash of the unsigned receipt fields.
    pub statement_hash_b64: String,

    /// Base64-encoded signature over `statement_hash`.
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptUnsigned {
    pub agent_pubkey_b64: String,
    pub entry_hash_b64: String,
    pub attachments_hash_b64: String,
    pub index: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryUnsigned {
    pub index: u64,
    pub created_at: String,
    pub provenance: Provenance,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,

    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub prev_entry_hash_b64: String,
}

/// A signed checkpoint statement that binds a human-readable `label` to the current chain head.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    /// Base64-encoded 32-byte Ed25519 public key.
    pub agent_pubkey_b64: String,
    /// Human label, typically a date like YYYY-MM-DD.
    pub label: String,
    /// RFC3339 timestamp.
    pub created_at: String,
    /// The current last index in the log, or None when the log is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_index: Option<u64>,
    /// Base64-encoded 32-byte head hash (the last entry_hash, or 32 zero bytes if empty).
    pub head_hash_b64: String,
    /// Base64-encoded 32-byte statement hash of the unsigned fields.
    pub statement_hash_b64: String,
    /// Base64-encoded signature over `statement_hash`.
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointUnsigned {
    pub agent_pubkey_b64: String,
    pub label: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_index: Option<u64>,
    pub head_hash_b64: String,
}
