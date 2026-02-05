# Story 05 — OpenClaw Skill Wrapper + Demo

## Goal
Expose core operations as an OpenClaw skill and provide a 5-minute demo flow.

## Tasks
- Create skill folder with `SKILL.md` describing commands and safety rules.
- Implement wrapper commands that call the CLI/library.
- Provide `scripts/demo.sh` that runs: init → append → checkpoint → verify.
- Ensure no secrets are printed.

## Acceptance
- Another agent can run demo with copy/paste commands.
- Skill docs include hackathon submission checklist items.
