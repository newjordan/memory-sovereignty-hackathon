# Story 01 — Init + Key Management

## Goal
Create `memsovereign` core crate with `init` that generates keys and writes them to disk safely.

## Tasks
- Create Rust workspace/crate structure.
- Implement Ed25519 keypair generation.
- Implement content key generation (32 bytes random).
- Write keys to `~/.config/memsovereign/keys/` with 0600 permissions.
- Provide `memsovereign-cli init` command.

## Acceptance
- Running `init` twice does not overwrite keys unless `--force`.
- Keys are readable only by the current user.
- CLI prints public key fingerprint only (no secrets).
