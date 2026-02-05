# Story 02 — Append Entry + Signed Receipt

## Goal
Append an encrypted entry to an append-only JSONL log and emit a signed receipt.

## Tasks
- Define `Entry` + canonical serialization.
- Implement BLAKE3 hashing to compute `entry_hash`.
- Implement XChaCha20-Poly1305 encryption with AAD.
- Append to `entries.jsonl` with strict ordering.
- Produce `Receipt` and print/export as JSON.

## Acceptance
- Two sequential appends create a valid prev-hash chain.
- Receipt verifies with the stored public key.
- Editing ciphertext or provenance causes verification failure.
