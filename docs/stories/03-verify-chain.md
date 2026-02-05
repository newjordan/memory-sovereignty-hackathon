# Story 03 — Verify Receipt + Chain Integrity

## Goal
Provide `verify` command that checks receipt signature and chain integrity up to an index.

## Tasks
- Implement receipt signature verification.
- Implement chain walk verification (prev-hash matches).
- Implement nice error messages (first mismatch index).
- Add tests for tampering scenarios.

## Acceptance
- Valid receipts pass.
- Tampered entry fails with specific mismatch report.
- Tampered signature fails.
