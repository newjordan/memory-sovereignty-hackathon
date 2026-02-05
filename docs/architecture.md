# Architecture — Memory Sovereignty Module

## 1. Components
### A) Rust core crate (`memsovereign`)
Responsibilities:
- key management (Ed25519 + symmetric key)
- encryption/decryption
- append-only log format
- hashing + chain integrity
- receipt and checkpoint generation
- verification

### B) CLI (`memsovereign-cli`)
Responsibilities:
- `init`, `append`, `checkpoint`, `verify`, `export`, `doctor`
- demo scripts for hackathon voters

### C) OpenClaw skill wrapper
Responsibilities:
- expose a small stable interface to the agent runtime
- keep file paths predictable (configurable)
- enforce policy defaults (write-protected by default)

## 2. Data model
### Entry
- `index: u64`
- `created_at: RFC3339`
- `kind: enum` (note/preference/essence/op)
- `provenance: {source_type, source_ref, message_id, url, tool_name}` (all optional)
- `ciphertext: bytes`
- `prev_entry_hash: [u8;32]`
- `entry_hash: [u8;32]` (hash of canonical serialization of entry without signature)

### Receipt
- `agent_pubkey: bytes`
- `entry_hash: [u8;32]`
- `index: u64`
- `created_at: RFC3339`
- `signature: bytes (Ed25519)`

### Daily checkpoint
Two viable approaches:
1) **last-hash checkpoint**: for day D, store the last entry hash written on D.
2) **Merkle root checkpoint**: build a Merkle root of entries written on D.

V1 chooses (1) for speed.

## 3. Cryptography
- Hash: BLAKE3 (fast, safe, good for logs)
- Signatures: Ed25519
- Encryption: XChaCha20-Poly1305
- AAD includes: index + prev_hash + provenance hash to bind ciphertext to context.

## 4. Storage layout
Default under `~/.config/memsovereign/`:
- `keys/identity_ed25519` (private, 0600)
- `keys/identity_ed25519.pub`
- `keys/content_key` (private, 0600)
- `log/entries.jsonl` (append-only)
- `checkpoints/YYYY-MM-DD.json`

OpenClaw integration can also target the workspace `memory/` folder.

## 5. Verification flow
- recompute `entry_hash` from entry fields
- verify `signature` against `agent_pubkey`
- verify `prev_entry_hash` matches previous entry

## 6. Policy enforcement
- policy file `policy.yaml` with defaults:
  - `write_protected: true`
  - allowlist for `source_type`
  - `require_human_confirm_for_promotion: true`
  - optional TTL for unverified entries

## 7. Optional future plugin: public anchoring
A separate module can publish daily checkpoint hashes to a public chain, but:
- disabled by default
- BYO wallet
- never run automatically

This preserves “no cost to Frosty40” as a hard constraint.
