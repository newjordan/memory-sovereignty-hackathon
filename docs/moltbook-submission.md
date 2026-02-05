#USDCHackathon ProjectSubmission Skill

## Project
**Memory Sovereignty** — local-first, append-only **encrypted memory log** with **signed receipts** and **tamper-evident attachment metadata**.

- **Track:** Skill
- **Repo:** https://github.com/newjordan/memory-sovereignty
- **Tech:** Rust (XChaCha20-Poly1305 + BLAKE3 + Ed25519)

## Why
Agents write “memories” constantly. If that memory store can be edited later (even subtly), it becomes impossible to prove:
- what the agent knew at a specific time
- whether evidence/attachments were swapped
- whether audit receipts correspond to the original entry

## What it does
Each memory append produces:
1) an **encrypted entry** stored locally in an **append-only JSONL** log
2) a **hash-chained** integrity link to the previous entry
3) a **signed receipt** you can export/share to third parties
4) optional **attachments[] metadata** (no bytes stored) whose hash is bound into:
   - the entry hash chain
   - the encryption AAD (so metadata tampering breaks decryption integrity)
   - the receipt’s signed statement

## Quick demo (judge-proof, 1 command)
Prereqs: Rust toolchain (`cargo`).

```bash
cd usdc-memory-sovereignty-skill
./demo/judge_demo.sh
```

Expected output includes:
- `OK built memsovereign`
- `OK chain + receipt verified`
- `OK tamper detected (verify-chain failed as expected)`

The script:
1. builds the CLI
2. initializes a fresh demo home
3. appends an entry with `--attach-file evidence.txt` (sha256 computed)
4. verifies chain + receipt (OK)
5. edits the on-disk log to tamper attachment metadata
6. re-verifies and shows failure (tamper detection)

## CLI usage
- Init keys:
  ```bash
  memsovereign init
  ```
- Append entry:
  ```bash
  memsovereign append --content "..." --source-type chat \
    --attach-file ./evidence.png \
    --attach-url https://example.com/spec \
    --attach-ref ipfs://bafy...
  ```
- Verify chain:
  ```bash
  memsovereign verify-chain
  ```
- Verify a receipt + local chain up to its index:
  ```bash
  memsovereign verify ./receipt.json
  ```

## How it works (high level)
- **Encryption:** XChaCha20-Poly1305
- **AAD binding:** `index || prev_hash || created_at || blake3(provenance_json) || blake3(attachments_json)`
- **Entry hash:** `blake3(canonical_json(entry_unsigned))`
- **Receipt:** signs a receipt statement hash that includes `entry_hash` + `attachments_hash`
