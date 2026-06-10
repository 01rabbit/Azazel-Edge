from __future__ import annotations

"""audit_review.py - Read-only operator audit trail review command.

Walks a decision through its v2 explanation record and the hash-chained
audit log.  Makes NO writes, NO policy changes, and NO enforcement.

Exit codes:
  0  explanation found AND chain verification passed
  2  explanation file missing/empty, or trace-id not found
  3  chain verification failed (mismatch or parse error)
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_DEFAULT_EXPLANATIONS_PATH = "/var/log/azazel-edge/decision-explanations.jsonl"
_DEFAULT_AUDIT_ENV_VAR = "AZAZEL_TRIAGE_AUDIT_PATH"
_DEFAULT_AUDIT_PATH = "/var/log/azazel-edge/triage-audit.jsonl"


# ---------------------------------------------------------------------------
# Helpers — read-only file operations only
# ---------------------------------------------------------------------------

def _load_explanations(path: Path) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Load all JSONL records from an explanations file.

    Returns ``([], None)`` if the file does not exist or is empty.
    Returns ``([], error)`` on the first malformed non-blank line.
    """
    if not path.exists():
        return [], None
    records: List[Dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            return [], f"invalid explanation JSONL at line {line_no}: {path}"
        if isinstance(obj, dict):
            records.append(obj)
    return records, None


def _select_record(
    records: List[Dict[str, Any]],
    trace_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Return the matching record or the last one when trace_id is None."""
    if not records:
        return None
    if trace_id is None:
        return records[-1]
    for rec in reversed(records):
        if str(rec.get("trace_id") or "") == trace_id:
            return rec
    return None


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _format_full(record: Dict[str, Any], chain_result: Dict[str, Any]) -> str:
    """Human-readable multi-line review output."""
    lines: List[str] = []

    lines.append("=" * 60)
    lines.append("AUDIT REVIEW — Decision Explanation Record")
    lines.append("=" * 60)

    lines.append(f"trace_id          : {record.get('trace_id', '')}")
    lines.append(f"ts                : {record.get('ts', '')}")
    lines.append(f"selected_action   : {record.get('selected_action', '')}")
    lines.append(f"release_condition : {record.get('release_condition', '')}")
    lines.append(f"policy_profile    : {record.get('policy_profile', '')}")
    lines.append(f"config_hash       : {record.get('config_hash', '')}")

    rejected_actions = record.get("rejected_actions", [])
    if rejected_actions:
        lines.append(f"rejected_actions  : {', '.join(str(a) for a in rejected_actions)}")
    else:
        lines.append("rejected_actions  : (none)")

    why_not_others = record.get("why_not_others", [])
    if why_not_others:
        lines.append("why_not_others:")
        for item in why_not_others:
            if isinstance(item, dict):
                lines.append(f"  - {item.get('action', '?')}: {item.get('reason', '?')}")
    else:
        lines.append("why_not_others    : (none)")

    evidence_ids = record.get("evidence_ids", [])
    if evidence_ids:
        lines.append(f"evidence_ids      : {', '.join(str(e) for e in evidence_ids)}")
    else:
        lines.append("evidence_ids      : (none)")

    operator_wording = record.get("operator_wording", "")
    if operator_wording:
        lines.append("")
        lines.append("operator_wording:")
        lines.append(f"  {operator_wording}")

    lines.append("")
    lines.append("-" * 60)
    lines.append("Schema validation:")

    from azazel_edge.explanations import validate_v2_explanation
    problems = validate_v2_explanation(record)
    if problems:
        lines.append("  INVALID — problems detected:")
        for prob in problems:
            lines.append(f"    * {prob}")
    else:
        lines.append("  OK — record is schema-valid (v2)")

    lines.append("")
    lines.append("-" * 60)
    lines.append("Audit chain:")

    if chain_result["ok"]:
        lines.append(f"  OK ({chain_result['entries']} entries)")
    else:
        lines.append(f"  MISMATCH: {chain_result.get('error', 'unknown error')}")

    lines.append("=" * 60)
    return "\n".join(lines)


def _format_compact(record: Dict[str, Any], chain_result: Dict[str, Any]) -> str:
    """Condensed single-screen output suitable for a booth display."""
    from azazel_edge.explanations import validate_v2_explanation
    problems = validate_v2_explanation(record)
    schema_status = "schema:OK" if not problems else f"schema:INVALID({len(problems)})"

    chain_status = (
        f"chain:OK({chain_result['entries']})"
        if chain_result["ok"]
        else f"chain:MISMATCH:{chain_result.get('error', '?')}"
    )

    return (
        f"trace={record.get('trace_id', '')} "
        f"action={record.get('selected_action', '')} "
        f"policy={record.get('policy_profile', '')} "
        f"hash={record.get('config_hash', '')} "
        f"release={record.get('release_condition', '')} "
        f"{schema_status} {chain_status}"
    )


def _format_json(
    record: Dict[str, Any],
    chain_result: Dict[str, Any],
) -> str:
    """Machine-readable JSON output."""
    from azazel_edge.explanations import validate_v2_explanation
    problems = validate_v2_explanation(record)

    output = {
        "trace_id": record.get("trace_id", ""),
        "ts": record.get("ts", ""),
        "selected_action": record.get("selected_action", ""),
        "rejected_actions": record.get("rejected_actions", []),
        "why_not_others": record.get("why_not_others", []),
        "release_condition": record.get("release_condition", ""),
        "policy_profile": record.get("policy_profile", ""),
        "config_hash": record.get("config_hash", ""),
        "evidence_ids": record.get("evidence_ids", []),
        "operator_wording": record.get("operator_wording", ""),
        "schema_valid": len(problems) == 0,
        "schema_problems": problems,
        "chain": {
            "ok": chain_result["ok"],
            "entries": chain_result["entries"],
            "error": chain_result.get("error", ""),
        },
    }
    return json.dumps(output, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.  Accepts an optional argv list for testing convenience."""
    parser = argparse.ArgumentParser(
        description=(
            "Read-only audit review: walks a decision through its v2 explanation"
            " record and the hash-chained audit log.  Makes no writes."
        )
    )
    parser.add_argument(
        "--explanations-path",
        default=_DEFAULT_EXPLANATIONS_PATH,
        help=(
            f"Path to the v2 decision-explanation JSONL file "
            f"(default: {_DEFAULT_EXPLANATIONS_PATH})"
        ),
    )
    default_audit = os.environ.get(_DEFAULT_AUDIT_ENV_VAR, _DEFAULT_AUDIT_PATH)
    parser.add_argument(
        "--audit-path",
        default=default_audit,
        help=(
            f"Path to the triage-audit JSONL file "
            f"(env: {_DEFAULT_AUDIT_ENV_VAR}, default: {_DEFAULT_AUDIT_PATH})"
        ),
    )
    parser.add_argument(
        "--trace-id",
        default=None,
        help=(
            "Select the explanation record whose trace_id matches this value."
            "  If omitted, the last (most recent) record is used."
        ),
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--compact",
        action="store_true",
        help="Condensed, single-line output suitable for a booth screen.",
    )
    output_group.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit a machine-readable JSON object instead of formatted text.",
    )

    args = parser.parse_args(argv)

    explanations_path = Path(args.explanations_path)
    audit_path = Path(args.audit_path)

    # ------------------------------------------------------------------
    # Load explanations (READ-ONLY)
    # ------------------------------------------------------------------
    records, parse_error = _load_explanations(explanations_path)
    if parse_error:
        print(f"[audit-review] {parse_error}", file=sys.stderr)
        return 3
    if not records:
        print(
            f"[audit-review] explanations file is missing or empty: {explanations_path}",
            file=sys.stderr,
        )
        return 2

    record = _select_record(records, args.trace_id)
    if record is None:
        print(
            f"[audit-review] trace_id not found: {args.trace_id!r}",
            file=sys.stderr,
        )
        return 2

    # ------------------------------------------------------------------
    # Verify audit chain (READ-ONLY classmethod)
    # ------------------------------------------------------------------
    from azazel_edge.audit import P0AuditLogger

    try:
        chain_result = P0AuditLogger.verify_chain(audit_path)
    except Exception as exc:
        print(f"[audit-review] error reading audit log: {exc}", file=sys.stderr)
        chain_result = {"ok": False, "entries": 0, "error": str(exc)}

    # ------------------------------------------------------------------
    # Render output
    # ------------------------------------------------------------------
    if args.json_output:
        print(_format_json(record, chain_result))
    elif args.compact:
        print(_format_compact(record, chain_result))
    else:
        print(_format_full(record, chain_result))

    # ------------------------------------------------------------------
    # Exit code
    # ------------------------------------------------------------------
    if not chain_result["ok"]:
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
