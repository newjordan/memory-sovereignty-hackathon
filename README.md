# memsovereign

Local, append-only memory log. Each entry is encrypted with XChaCha20-Poly1305 and signed with Ed25519. Receipts and checkpoints are signed statements over that log. Nothing is published on a chain.

The binary is `memsovereign` (`crates/memsovereign-cli`). The library is `crates/memsovereign`.

## Build

```bash
cargo build --release -p memsovereign-cli
```

The binary is `target/release/memsovereign`. A debug build is `target/debug/memsovereign`.

Requires Rust 1.89 or newer (the log uses `std::fs::File::lock`).

## Usage

The home directory holds keys and the log. Override it with `--home`, or set `MEMSOVEREIGN_HOME`. Otherwise it is the platform config directory plus `memsovereign` (on Linux, `~/.config/memsovereign`).

```bash
memsovereign --home ./demo-home init
memsovereign --home ./demo-home append \
  --content "I can prove what I knew, when I knew it." \
  --source-type chat \
  --attach-file ./evidence.txt \
  --receipt-out ./receipt_0.json
memsovereign --home ./demo-home show
memsovereign --home ./demo-home show 0
memsovereign --home ./demo-home verify-chain
memsovereign --home ./demo-home verify ./receipt_0.json
memsovereign --home ./demo-home verify-receipt ./receipt_0.json
memsovereign --home ./demo-home checkpoint --label 2026-11-25
memsovereign --home ./demo-home verify-checkpoint ./demo-home/checkpoints/checkpoint_2026-11-25.json
memsovereign --home ./demo-home receipt export 0
```

`verify` checks the receipt signature and that the receipt names the entry stored at that index (hash, timestamp, attachments hash, and the local identity). `verify-receipt` checks the signature only, so a receipt can be checked without the log. `show` verifies the chain, then decrypts.

`init --force` overwrites keys only when the log is empty. It refuses to replace keys while `log/entries.jsonl` has entries, because those entries would no longer verify.

One-command demo:

```bash
./demo/judge_demo.sh
```

## On-disk layout

```text
$HOME/
  keys/                      mode 0700
    identity_ed25519         Ed25519 seed, mode 0600
    identity_ed25519.pub
    content_key              32-byte XChaCha20-Poly1305 key, mode 0600
  log/
    LOCK                     exclusive lock for append and verify
    entries.jsonl            one JSON object per line
    HEAD.json                signed tip (index + entry hash)
    receipts/receipt_<n>.json
  checkpoints/checkpoint_<label>.json
```

Logs written before the signed-entry format in this tree do not verify. Create a new home with `init`.

## Threat model

**Assets.** Entry plaintext, the Ed25519 seed, and the content key. Receipts, checkpoints, hashes, and attachment metadata are not secret. Attachment bytes are not stored; only the metadata you pass in (and, for `--attach-file`, a SHA-256) is.

**Trust anchor.** The seed in `keys/identity_ed25519`. `init` stores the matching public key beside it and refuses to load a pair that does not match. Verification uses that pair. Anyone who can replace both files, or who can read the seed, can produce signatures that verify.

**In scope**

- A copy of `log/` without `keys/` does not reveal plaintext. XChaCha20-Poly1305 authenticates the ciphertext and the associated data (index, previous hash, timestamp, provenance, attachments).
- An editor who can change `entries.jsonl` but does not have the seed cannot produce a chain that `verify-chain` accepts. Each entry is signed. Recomputing BLAKE3 links is not enough.
- Truncating the log, or deleting `HEAD.json`, fails verification. `HEAD.json` is a signed commitment to the tip.
- A receipt presented to `verify` has to match the local entry at that index and the local public key.
- Two appends at once take an exclusive lock on `log/LOCK`, so they cannot fork the chain.
- A crash after the new line is synced and before `HEAD.json` is replaced can leave one already-signed entry ahead of the previous head. Verification allows that one entry. It does not allow an unsigned extension, and it does not allow the log to be shorter than the signed head.

**Out of scope**

- A reader who has `keys/` can decrypt every entry and sign new ones. There is no passphrase. The content key is a random 256-bit key stored next to the log, with directory mode `0700` and file mode `0600`. Encryption protects copies of the log that do not include the key files. It does not protect a stolen home directory.
- A saved snapshot of a log prefix together with the `HEAD.json` from that same moment will verify. That is a rollback. Detecting it needs a tip stored somewhere the attacker cannot restore (a witness, a transparency log, or a chain anchor). Those are not part of this tool.
- The tool does not hide that the log exists, how many entries it has, or the timestamps and provenance stored in the clear next to the ciphertext.
- It does not fetch attachment URLs or check that a file still matches `sha256_b64` at verify time. The hash is what was recorded at append time.

## Cryptography review

Algorithms: BLAKE3 (derive-key mode, hardcoded context) for entry, attachment, provenance, receipt, and checkpoint hashes. Ed25519 (`ed25519-dalek`, `verify_strict`) for entries, the log head, receipts, and checkpoints. XChaCha20-Poly1305 for entry bodies. Nonces and keys come from the operating system CSPRNG (`getrandom`).

Changes made after review:

1. **The hash chain was not authenticated.** `verify-chain` used to recompute BLAKE3 and check `prev_entry_hash`. BLAKE3 is not a MAC. Someone who can edit the file can change an entry and recompute every later hash, and the old check would pass. Each entry now carries an Ed25519 signature over a domain-separated message containing the entry hash. `verify-chain` checks that signature with `verify_strict`. The same pass signs `HEAD.json` so deleting a tail is visible.

2. **Nonce generation accepted any `RngCore`.** A caller could pass a non-cryptographic generator. Predictable nonces, or a repeated nonce under the same content key, break XChaCha20-Poly1305 confidentiality (the keystream would repeat). `encrypt_xchacha20poly1305` now draws a 192-bit nonce from the OS CSPRNG itself. There is no parameter for a caller-supplied nonce or RNG.

3. **Associated data was optional at decrypt time.** The low-level decrypt function authenticates whatever associated data the caller passes. Passing an empty slice would still check the Poly1305 tag over the ciphertext and skip the binding to index, time, and metadata. `open_entry` rebuilds that associated data from the entry and is the decrypt path `show` uses. A wrong key, a flipped ciphertext byte, or a changed bound field fails closed.

4. **`verify` did not bind a receipt to the log.** It checked that the receipt's signature was valid and that some chain was internally consistent up to that index. It did not check that the receipt's entry hash was the entry stored there. `verify` now checks the signature, the local public key, and the entry's index, timestamp, entry hash, and attachments hash.

5. **Key separation.** The content key is 32 bytes from the CSPRNG. It is not derived from the Ed25519 seed, and it is not a password hash. There is no password, so there is no KDF to get wrong. An all-zero buffer from the generator is rejected. `StoredKeys` implements `ZeroizeOnDrop`, and its `Debug` output redacts the seed and the content key. Key files are created mode `0600` and the keys directory mode `0700`.

6. **Signature domains.** Entry, head, receipt, and checkpoint signatures are over distinct, length-prefixed messages (`memsovereign\0` plus a label). A receipt signature is not a valid entry signature.

Canonical hashes are `serde_json`'s compact encoding of the unsigned structs in this crate (struct field order, omitted empty attachments and omitted `None` provenance fields). Verifiers have to use that encoding.

## Tests and CI

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo audit
```

GitHub Actions (`.github/workflows/ci.yml`) runs those on pull requests. The tests cover encryption round trips, wrong keys, flipped ciphertext and associated data, distinct nonces, tampered logs (including a rewritten hash that keeps the old signature), truncation against the signed head, and property tests over random plaintexts.
