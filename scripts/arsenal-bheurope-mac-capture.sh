#!/usr/bin/env bash
# Black Hat Europe Arsenal: macOS replay + evidence capture readiness.
# Runs ONLY synthetic deterministic replay; does not enable packet enforcement.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: this capture workflow is intended for macOS." >&2
  exit 2
fi
branch="$(git branch --show-current)"
if [[ "$branch" != "arsenal/bheurope-2026" ]]; then
  echo "ERROR: switch to arsenal/bheurope-2026 first (currently: $branch)." >&2
  exit 2
fi

stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
OUT="$ROOT/artifacts/bheurope-2026/mac-capture-$stamp"
mkdir -p "$OUT"
echo "Evidence output: $OUT"
echo "$branch" > "$OUT/branch.txt"
git rev-parse HEAD > "$OUT/commit.txt"
uname -a > "$OUT/platform.txt"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "Setting up replay-only environment (requires internet for initial pip install)..."
  bash scripts/arsenal-bheurope-setup.sh 2>&1 | tee "$OUT/setup.log"
fi
PY="$ROOT/.venv/bin/python"

echo "== Read-only preflight =="
set +e
"$PY" tools/arsenal_preflight.py --output "$OUT/preflight.json" 2>&1 | tee "$OUT/preflight.log"
preflight_status=${PIPESTATUS[0]}
set -e
if [[ "$preflight_status" -ne 0 ]]; then
  echo "STOP: preflight did not pass; details in $OUT/preflight.json" >&2
  exit 3
fi

echo "== Deterministic scenario replay and evidence gate =="
set +e
"$PY" tools/arsenal_bheurope_2026.py --out "$OUT" 2>&1 | tee "$OUT/replay.log"
gate_status=${PIPESTATUS[0]}
set -e
if [[ "$gate_status" -ne 0 ]]; then
  echo "STOP: replay gate failed. Do NOT record this as a successful demo." >&2
  exit 4
fi

echo "== Verify actual output and demonstrate tamper detection on a COPY =="
"$PY" - "$OUT" <<'PY'
import json
import shutil
import sys
from pathlib import Path
out = Path(sys.argv[1])
root = Path.cwd()
sys.path.insert(0, str(root / "py"))
from azazel_edge.audit.logger import P0AuditLogger
gate = json.loads((out / "gate.json").read_text())
explanations = [json.loads(x) for x in (out / "explanations.jsonl").read_text().splitlines() if x.strip()]
result = json.loads((out / "result.json").read_text())
audit = out / "audit.jsonl"
if gate.get("ok") is not True or not explanations:
    raise SystemExit("gate invalid or explanation missing")
clean = P0AuditLogger.verify_chain(audit)
if not clean.get("ok") or clean.get("entries", 0) < 1:
    raise SystemExit(f"clean chain verification failed: {clean}")
last = explanations[-1]
if last.get("selected_action") != gate.get("action") or last.get("trace_id") != gate.get("trace_id"):
    raise SystemExit("gate/explanation mismatch")
tampered = out / "audit-tampered-COPY.jsonl"
shutil.copyfile(audit, tampered)
rows = tampered.read_text(encoding="utf-8").splitlines()
record = json.loads(rows[0])
# Modify a signed-into-hash field while deliberately retaining original chain_hash.
record["source"] = str(record.get("source", "")) + "-modified-for-demonstration"
rows[0] = json.dumps(record, ensure_ascii=False)
tampered.write_text("\n".join(rows) + "\n", encoding="utf-8")
broken = P0AuditLogger.verify_chain(tampered)
if broken.get("ok"):
    raise SystemExit("ERROR: tampered copy was not detected; do not use this as evidence")
report = {
    "recording_ready_replay": True,
    "selected_action": last.get("selected_action"),
    "trace_id": last.get("trace_id"),
    "release_condition": last.get("release_condition"),
    "policy_profile": last.get("policy_profile"),
    "config_hash": last.get("config_hash"),
    "rejected_actions": last.get("rejected_actions"),
    "why_not_others": last.get("why_not_others"),
    "audit_clean": clean,
    "audit_modified_copy": broken,
    "limits": "synthetic macOS replay only; no live packet enforcement or verified ARM64 device operation"
}
(out / "capture-report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(report, indent=2, ensure_ascii=False))
PY

echo
echo "PASS: local replay ran, explanation matched, clean chain passed and altered COPY failed."
echo "Evidence folder: $OUT"
echo "To display genuine results on the local read-only dashboard:"
echo "  .venv/bin/python tools/arsenal_bheurope_monitor.py --artifacts \"$OUT\""
echo "  Open http://127.0.0.1:8765 in the browser."
echo
echo "To capture a screenshot on this Mac (interactive selection, macOS permissions may apply):"
echo "  screencapture -i \"$OUT/dashboard.png\""
echo "Do not represent this macOS offline replay as real packet enforcement or Raspberry Pi footage."
