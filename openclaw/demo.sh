#!/usr/bin/env bash
set -euo pipefail

# Demo: init/append/verify/checkpoint using a temp MEMSOVEREIGN_HOME.
# No secrets are written to the repo.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOME_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$HOME_DIR"
}
trap cleanup EXIT

export MEMSOVEREIGN_HOME="$HOME_DIR"

cd "$ROOT_DIR"

echo "Using MEMSOVEREIGN_HOME=$MEMSOVEREIGN_HOME"

cargo run -q -p memsovereign-cli -- init
cargo run -q -p memsovereign-cli -- append --content "hello from demo" >/tmp/memsovereign_demo_receipt.json
cargo run -q -p memsovereign-cli -- verify-receipt /tmp/memsovereign_demo_receipt.json
cargo run -q -p memsovereign-cli -- verify-chain

# Create a checkpoint with an explicit label (so reruns are deterministic).
CHECKPOINT_PATH="$MEMSOVEREIGN_HOME/checkpoints/checkpoint_demo.json"
cargo run -q -p memsovereign-cli -- checkpoint --label demo --out "$CHECKPOINT_PATH" >/dev/null

# Verify that the checkpoint matches the current chain head.
cargo run -q -p memsovereign-cli -- verify-checkpoint "$CHECKPOINT_PATH"

echo "Demo complete. Receipt: /tmp/memsovereign_demo_receipt.json"
