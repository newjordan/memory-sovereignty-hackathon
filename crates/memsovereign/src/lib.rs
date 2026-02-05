//! memsovereign: local-first append-only encrypted + signed memory receipts.

pub mod crypto;
pub mod keys;
pub mod paths;
pub mod store;
pub mod types;
pub mod verify;

pub use keys::{IdentityKeys, StoredKeys};
pub use store::{
    append_entry, checkpoint_path, create_checkpoint, head_state, init_keys, load_keys,
    load_receipt, save_receipt,
};
pub use types::{Checkpoint, Entry, Receipt};
