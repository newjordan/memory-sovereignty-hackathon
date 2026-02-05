# Story 04 — Daily Checkpoint (“X on July 3”)

## Goal
Generate and verify a daily checkpoint receipt for a given date.

## Tasks
- Parse entry dates from `created_at`.
- Find the last entry hash for a date.
- Write checkpoint file `checkpoints/YYYY-MM-DD.json`.
- Verify checkpoint against log.

## Acceptance
- Checkpoint exists for days with entries.
- Verification fails if earlier entries are edited.
