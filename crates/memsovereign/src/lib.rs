//! memsovereign: local-first append-only encrypted + signed memory receipts.

pub mod crypto;
pub mod keys;
pub mod paths;
pub mod store;
pub mod types;
pub mod verify;

pub use crypto::os_rng;
pub use keys::{IdentityKeys, StoredKeys};
pub use store::{
    append_entry, checkpoint_path, create_checkpoint, head_state, init_keys, load_keys,
    load_receipt, open_entry, read_entries, save_receipt,
};
pub use types::{Attachment, Checkpoint, Entry, LogHead, Provenance, Receipt};
