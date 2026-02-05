# Memory Sovereignty (Rust) + OpenClaw Skill

USDC Hackathon — Track: Skill

Core: local append-only encrypted + signed memory receipts (no onchain costs).

## Status

- Planning docs live in `docs/` (also mirrored in `_bmad-output/`).
- Rust workspace scaffolding + minimal CLI/core implemented (init → append → verify-chain).

## One-command judge demo

```bash
./demo/judge_demo.sh
```

## CLI (quick reference)

After building, the binary is at `./target/debug/memsovereign`.

Common commands:

```bash
./target/debug/memsovereign init
./target/debug/memsovereign append --content "hello" --source-type chat
./target/debug/memsovereign verify-chain
./target/debug/memsovereign verify ./receipt.json
```
