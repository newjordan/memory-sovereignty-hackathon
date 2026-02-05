# Memory Sovereignty (memsovereign) — OpenClaw Skill Wrapper

This repo contains a Rust library + CLI (`memsovereign`) that provides:

- **Init**: generate local keys
- **Append**: append an encrypted entry to an append-only hash chain and emit a signed receipt
- **Verify**: verify receipts and/or the local chain
- **Checkpoint**: write a **signed statement** binding a human label (usually a date) to the current chain head

This folder is a thin wrapper intended for OpenClaw-style integration.

## CLI quickstart

From the repo root:

```bash
cargo run -p memsovereign-cli -- --help
```

The CLI stores data under `~/.config/memsovereign` by default.
Override with `--home <path>` or `MEMSOVEREIGN_HOME`.

## Commands

- `init [--force]`
- `append --content "..." [--receipt-out <path>]`
- `verify-chain`
- `verify-receipt <path>`
- `verify <path>`
- `checkpoint [--label YYYY-MM-DD] [--out <path>]`
- `verify-checkpoint <path>`

## Demo

Run the demo script, which uses a temporary home directory (no secrets committed):

```bash
bash openclaw/demo.sh
```
