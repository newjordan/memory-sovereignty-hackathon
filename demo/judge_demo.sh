#!/usr/bin/env bash
set -euo pipefail

say() { printf '%s\n' "$*"; }
ok()  { printf 'OK   %s\n' "$*"; }
fail(){ printf 'FAIL %s\n' "$*"; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_HOME="${DEMO_HOME:-$(mktemp -d)}"

say "== Memory Sovereignty judge demo =="
say "Home: ${DEMO_HOME}"

command -v cargo >/dev/null 2>&1 || fail "cargo not found. Install rustup (https://rustup.rs) and retry."

say "\n[1/5] Build CLI"
( cd "${ROOT_DIR}" && cargo build -q -p memsovereign-cli )
BIN="${ROOT_DIR}/target/debug/memsovereign"
[[ -x "${BIN}" ]] || fail "binary not found at ${BIN}"
ok "built memsovereign"

say "\n[2/5] Init keys"
"${BIN}" --home "${DEMO_HOME}" init >/dev/null
ok "initialized"

say "\n[3/5] Append entry WITH attachment metadata"
ATT_PATH="${DEMO_HOME}/evidence.txt"
printf 'This is an attachment used for integrity binding.\n' >"${ATT_PATH}"
"${BIN}" --home "${DEMO_HOME}" append \
  --content "I can prove what I knew, when I knew it (with tamper-evident attachment metadata)." \
  --source-type "judge-demo" \
  --attach-file "${ATT_PATH}" \
  --receipt-out "${DEMO_HOME}/receipt_0.json" >/dev/null
ok "appended entry + wrote receipt_0.json"

say "\n[4/5] Verify chain + receipt (expect OK)"
"${BIN}" --home "${DEMO_HOME}" verify-chain >/dev/null
"${BIN}" --home "${DEMO_HOME}" verify "${DEMO_HOME}/receipt_0.json" >/dev/null
ok "chain + receipt verified"

say "\n[5/5] Tamper attachment metadata in the log (expect FAIL)"
LOG_PATH="${DEMO_HOME}/log/entries.jsonl"
python3 - "$LOG_PATH" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
lines = p.read_text().splitlines()
obj = json.loads(lines[0])
obj["attachments"][0]["name"] = "evidence-TAMPERED.txt"
lines[0] = json.dumps(obj, separators=(",", ":"))
p.write_text("\n".join(lines) + "\n")
PY

set +e
"${BIN}" --home "${DEMO_HOME}" verify-chain >/dev/null 2>&1
RC=$?
set -e
if [[ $RC -eq 0 ]]; then
  fail "tamper was NOT detected (unexpected)"
fi
ok "tamper detected (verify-chain failed as expected)"

say "\nDONE"
