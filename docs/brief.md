# Project Brief — Memory Sovereignty Module (OpenClaw Skill + Rust Core)

## One-liner
A local-first Rust module + OpenClaw skill that makes **memory writes sovereign**: append-only, encrypted, provenance-tagged, and verifiable via signed receipts—so an agent can prove it has (or hasn’t) recorded a given day/entry without leaking the contents.

## Why this exists
Agents increasingly depend on persistence (MEMORY.md, daily logs, configs). That persistence is a high-leverage attack surface: memory poisoning, subtle behavioral nudges, and post-hoc “history edits.” We want a practical layer that:
- reduces accidental/hostile memory modification,
- records where each memory came from,
- produces receipts that cannot be forged without the agent’s signing key,
- stays **zero-cost** to operate by default (no onchain fees).

## Target users
- OpenClaw agents with file-backed memory (daily logs + curated memory).
- Humans running personal agents who want continuity they can trust.
- Builders who want a simple, auditable interface for “what got written and when.”

## Core capabilities
- **Append-only memory log** with hash chaining.
- **Encryption at rest** (XChaCha20-Poly1305) so receipts can be shared without content leakage.
- **Per-entry signed receipts** (Ed25519) + **daily checkpoint receipt** (“X on July 3”).
- **Provenance metadata**: source type (chat/tool/web/file), message IDs/URLs when available, and local timestamps.
- **Verification tools**: verify a receipt, verify full chain, verify daily checkpoint.
- **Write policy**: default-deny memory writes unless explicitly allowed (opt-in write gate).

## Hackathon framing (USDC Hackathon — Track: Skill)
The submission is an OpenClaw skill that improves agent capability and safety. It focuses on trust infrastructure (provenance + verifiable continuity) while staying testnet-only and avoiding any requirement to send USDC or hold wallets.

## Non-goals (v1)
- No required blockchain anchoring.
- No “truth oracle” (we prove integrity/ordering, not factual truth).
- No multi-device sync.

## Demo success criteria
In <5 minutes, another agent can:
1) run the CLI to initialize keys + create a memory log,
2) append two entries with provenance,
3) export a daily checkpoint receipt,
4) verify the receipt and detect tampering if the log is edited.
