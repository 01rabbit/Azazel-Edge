from __future__ import annotations

"""audit_review.py - Read-only operator audit trail review command.

Walks a decision through its v2 explanation record and the hash-chained
audit log.  Makes NO writes, NO policy changes, and NO enforcement.

Exit codes:
  0  explanation found AND chain verification passed (or the audit file is
     missing/empty: reported as EMPTY, nothing verified)
  2  explanation file missing/empty, or trace-id not found
  3  chain verification failed (mismatch, parse error, a rotated file the
     next one does not continue, or a cut start)

The audit file may be a rotated chain (the core decision chain,
``core-decision-audit.jsonl`` + ``.1``; Edge#462 item 1).
:func:`verify_audit_chain` says what was verified: see its docstring.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Written by the AI agent from the core's decisions (Edge#477); the same file
# as the Web UI's Booth Focus (explanations.LIVE_DECISION_EXPLANATIONS_PATH).
_DEFAULT_EXPLANATIONS_PATH = "/var/log/azazel-edge/ai/decision-explanations.jsonl"
_DEFAULT_AUDIT_ENV_VAR = "AZAZEL_TRIAGE_AUDIT_PATH"
_DEFAULT_AUDIT_PATH = "/var/log/azazel-edge-web/triage-audit.jsonl"  # the Web UI log directory (Edge#471)


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
# Audit chain verification (READ-ONLY)
# ---------------------------------------------------------------------------

# What "chain OK" means, as printed and as returned in the JSON output.
SCOPE_FROM_GENESIS = "from_genesis"
SCOPE_FROM_ROTATION_BOUNDARY = "from_rotation_boundary"
SCOPE_EMPTY = "empty"
SCOPE_NOT_VERIFIED = "not_verified"

_MEANING = {
    SCOPE_FROM_GENESIS: (
        "every record from the chain's first record to the last complete one links to the one"
        " before it and its hash matches"
    ),
    SCOPE_FROM_ROTATION_BOUNDARY: (
        "every retained record links to the one before it and its hash matches, starting at a"
        " rotation boundary; the records before it were rotated out, are not retained and were"
        " not verified"
    ),
    SCOPE_EMPTY: "the audit file is missing or has no records; nothing was verified",
    SCOPE_NOT_VERIFIED: "verification failed; the chain is not OK",
}

# What OK never covers (chain hashes are not keyed; Edge#462 item 2).
_LIMITS = (
    "records are not signed: a writer of the file can forge a chain that verifies,"
    " and records removed from the end cannot be detected"
)


def _present(path: Path) -> bool:
    """Whether ``path`` exists. Unlike ``Path.exists`` an error other than
    "not found" (a directory this account cannot search) raises, so it is
    reported as a read error, never as an empty chain."""
    try:
        os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def _retained_files(path: Path, segments: int) -> List[Path]:
    """The files read_chain read, oldest first (its snapshot starts at the
    active file when it exists, then ``.1``, ``.2``, ...)."""
    from azazel_edge.audit.segments import segment_path

    newest_first = ([path] if _present(path) else []) + [segment_path(path, n) for n in range(1, segments + 1)]
    return list(reversed(newest_first[:segments]))


def verify_audit_chain(path: str | Path) -> Dict[str, Any]:
    """Verify an audit chain, rotated or not, as the P0 relay reads it.

    The retained files (the active file and, after a rotation, ``<name>.1``)
    are read as one snapshot with ``segments.read_chain``, the reader the P0
    relay's reconcile uses, and verified oldest first as one chain:

    * ``scope`` ``from_genesis``: the oldest retained record is the chain's
      first record (``chain_prev`` empty); everything up to the last complete
      record was verified.
    * ``scope`` ``from_rotation_boundary``: the oldest retained record
      continues older records that rotation removed (the reconcile's
      ``anchored``). It must be the first record of a rotated file (it carries
      ``chain_id``); its ``chain_prev`` is taken as the start and what was
      before it is not verified (``genesis_retained`` false).
    * ``scope`` ``empty``: no file or no record; ``ok`` stays true (as
      before) but nothing was verified, and the outputs say EMPTY, not OK.

    ``ok`` says no tampering was found (and keeps exit code 0 for an empty
    file); ``verified`` says there is verified evidence: true only for an OK
    ``from_genesis`` or ``from_rotation_boundary`` chain. A reader that needs
    evidence (``bhusa_verify``) checks ``verified``.

    A read that races a rotation is retaken (``read_chain``); if rotations
    keep moving files it fails with ``snapshot_inconsistent`` and a rerun
    normally passes.

    Failures (``ok`` false, ``scope`` ``not_verified``): a record whose hash
    does not match (rewritten), whose ``chain_prev`` is not the record before
    it (removed, reordered or inserted), a rotated file the next newer file
    does not continue (its tail was cut or rewritten, or the newer file was
    replaced by another chain: the reconcile's ``chain_replaced`` /
    ``chain_unlinked_segments``), an oldest record that continues a chain but
    is not a rotation boundary (the start was cut off), a ``chain_id`` other
    than the chain's, a line that is not JSON, and a last line without its
    newline. Positions (``..._at:N``) count records of the retained chain,
    oldest first (``.1`` before the active file), from 1.

    An ``OSError`` (a file this account cannot read) is raised: ``main``
    prints it and fails (exit 3). Read only. Chain hashes are not keyed: see
    ``_LIMITS``.
    """
    from azazel_edge.audit import P0AuditLogger
    from azazel_edge.audit.segments import chain_id_of, read_chain, segment_path

    log_path = Path(path)
    result: Dict[str, Any] = {
        "ok": False, "verified": False, "entries": 0, "error": "", "scope": SCOPE_NOT_VERIFIED,
        "genesis_retained": False, "files": [], "chain_id": "",
    }

    def fail(error: str) -> Dict[str, Any]:
        result.update(ok=False, verified=False, error=error, scope=SCOPE_NOT_VERIFIED)
        return result

    if not _present(log_path) and not _present(segment_path(log_path, 1)):
        result.update(ok=True, scope=SCOPE_EMPTY)
        return result
    # read_chain leaves a last line without its newline out of its lines;
    # its ``sync`` hook is called with the descriptor of every file it reads,
    # oldest first, so the check sees the same snapshot.
    torn: List[int] = []
    order: List[int] = []

    def _tail_check(fd: int) -> bool:
        order.append(fd)
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":
            torn.append(len(order) - 1)
        return False

    snapshot = read_chain(log_path, sync=_tail_check)  # OSError (permission) is the caller's: printed, exit 3
    files = _retained_files(log_path, int(snapshot["segments"]))
    result.update(files=[f.name for f in files], chain_id=str(snapshot["chain_id"] or ""))
    if not snapshot["consistent"]:
        return fail("snapshot_inconsistent:rotation_kept_moving_files")
    if snapshot["unlinked_segments"]:
        return fail(f"rotated_file_not_continued:{snapshot['unlinked_segments']}")
    if torn:
        idx = torn[0]
        name = files[idx].name if idx < len(files) else str(idx + 1)
        return fail(f"incomplete_last_line:{name}")
    rows: List[Dict[str, Any]] = []
    for idx, raw in enumerate(snapshot["lines"], start=1):
        try:
            row = json.loads(raw)
        except Exception:
            return fail(f"parse_error_at:{idx}")
        if not isinstance(row, dict):
            return fail(f"parse_error_at:{idx}")
        rows.append(row)
    if not rows:
        result.update(ok=True, scope=SCOPE_EMPTY)
        return result
    head = rows[0]
    prev = str(head.get("chain_prev") or "")
    if prev:
        cid = head.get("chain_id")
        if not (isinstance(cid, str) and cid):
            # Continues a chain but is not the first record of a rotated
            # file: the records before it were cut, not rotated.
            return fail("start_cut:oldest_record_is_not_a_rotation_boundary")
    chain_id = chain_id_of(head)
    for idx, row in enumerate(rows, start=1):
        if str(row.get("chain_prev") or "") != prev:
            result["entries"] = idx - 1
            return fail(f"chain_prev_mismatch_at:{idx}")
        if "chain_id" in row and row.get("chain_id") != chain_id:
            result["entries"] = idx - 1
            return fail(f"chain_id_mismatch_at:{idx}")
        body = dict(row)
        actual = str(body.pop("chain_hash", "") or "")
        if actual != P0AuditLogger._compute_chain_hash(body):
            result["entries"] = idx - 1
            return fail(f"chain_hash_mismatch_at:{idx}")
        prev = actual
    result.update(
        ok=True, verified=True, entries=len(rows), error="",
        scope=SCOPE_FROM_ROTATION_BOUNDARY if str(head.get("chain_prev") or "") else SCOPE_FROM_GENESIS,
        genesis_retained=not str(head.get("chain_prev") or ""),
    )
    return result


def _chain_meaning(chain_result: Dict[str, Any]) -> str:
    scope = chain_result.get("scope") or (SCOPE_NOT_VERIFIED if not chain_result.get("ok") else SCOPE_FROM_GENESIS)
    return _MEANING.get(scope, _MEANING[SCOPE_NOT_VERIFIED])


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _config_hash_basis(record: Dict[str, Any]) -> str:
    """What ``config_hash`` is a hash of, when the record says (the agent's
    live records: ``enforcement_settings``, not a policy file; Edge#477)."""
    machine = record.get("machine") if isinstance(record.get("machine"), dict) else {}
    arbiter = machine.get("arbiter") if isinstance(machine.get("arbiter"), dict) else {}
    policy = arbiter.get("policy") if isinstance(arbiter.get("policy"), dict) else {}
    return str(policy.get("hash_basis") or "")


def _capsule_signature_state(record: Dict[str, Any]) -> str:
    """The trust capsule's signature_state as written (Edge#477): ``signed``,
    ``unsigned``, or ``not_recorded`` for a record written before the field
    existed (unless the device had a key, signed with the public former
    default key). Display only: this tool holds no key and verifies nothing.
    """
    capsule = record.get("trust_capsule") if isinstance(record.get("trust_capsule"), dict) else {}
    state = capsule.get("signature_state")
    if state in ("signed", "unsigned"):
        return str(state)
    return "not_recorded" if "signature_state" not in capsule else "invalid"


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
    basis = _config_hash_basis(record)
    if basis:
        note = " (not a policy file hash)" if basis != "policy_file" else ""
        lines.append(f"config_hash_basis : {basis}{note}")

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
    lines.append(f"Trust capsule     : {_capsule_signature_state(record)} (not verified here)")

    lines.append("")
    lines.append("-" * 60)
    lines.append("Audit chain:")

    scope = chain_result.get("scope")
    files = ", ".join(chain_result.get("files") or []) or "(none)"
    if not chain_result["ok"]:
        lines.append(f"  MISMATCH: {chain_result.get('error', 'unknown error')}")
        lines.append(f"  verified ok   : {chain_result.get('entries', 0)} entries before the failure; the chain is NOT OK")
    elif scope == SCOPE_EMPTY:
        lines.append("  EMPTY (0 entries): nothing was verified")
    else:
        lines.append(f"  OK ({chain_result['entries']} entries, {scope})")
    lines.append(f"  files         : {files}")
    if chain_result.get("chain_id"):
        lines.append(f"  chain_id      : {chain_result['chain_id']}")
    lines.append(f"  meaning       : {_chain_meaning(chain_result)}")
    lines.append(f"  limits        : {_LIMITS}")

    lines.append("=" * 60)
    return "\n".join(lines)


def _format_compact(record: Dict[str, Any], chain_result: Dict[str, Any]) -> str:
    """Condensed single-screen output suitable for a booth display."""
    from azazel_edge.explanations import validate_v2_explanation
    problems = validate_v2_explanation(record)
    schema_status = "schema:OK" if not problems else f"schema:INVALID({len(problems)})"

    scope = chain_result.get("scope")
    if not chain_result["ok"]:
        chain_status = f"chain:MISMATCH:{chain_result.get('error', '?')}"
    elif scope == SCOPE_EMPTY:
        chain_status = "chain:EMPTY(0)"
    else:
        chain_status = (
            f"chain:OK({chain_result['entries']}) chain_scope={scope}"
            f" chain_files={len(chain_result.get('files') or [])}"
        )

    basis = _config_hash_basis(record)
    return (
        f"trace={record.get('trace_id', '')} "
        f"action={record.get('selected_action', '')} "
        f"policy={record.get('policy_profile', '')} "
        f"hash={record.get('config_hash', '')} "
        + (f"hash_basis={basis} " if basis else "")
        + f"release={record.get('release_condition', '')} "
        f"{schema_status} capsule:{_capsule_signature_state(record)} {chain_status}"
    )


def record_review(record: Dict[str, Any]) -> Dict[str, Any]:
    """The explanation fields of the ``--json`` output (everything but
    ``chain``). Read only; also used by the Web UI's decision trace
    (``azazel_edge.explanations.trace``), so both show a record the same way."""
    from azazel_edge.explanations import validate_v2_explanation
    problems = validate_v2_explanation(record)
    return {
        "trace_id": record.get("trace_id", ""),
        "ts": record.get("ts", ""),
        "selected_action": record.get("selected_action", ""),
        "rejected_actions": record.get("rejected_actions", []),
        "why_not_others": record.get("why_not_others", []),
        "release_condition": record.get("release_condition", ""),
        "policy_profile": record.get("policy_profile", ""),
        "config_hash": record.get("config_hash", ""),
        "config_hash_basis": _config_hash_basis(record),
        "evidence_ids": record.get("evidence_ids", []),
        "operator_wording": record.get("operator_wording", ""),
        "schema_valid": len(problems) == 0,
        "schema_problems": problems,
        "capsule_signature_state": _capsule_signature_state(record),
    }


def chain_review(chain_result: Dict[str, Any]) -> Dict[str, Any]:
    """The ``chain`` object of the ``--json`` output for a
    :func:`verify_audit_chain` result (also used by the Web UI's decision
    trace)."""
    return {
        "ok": bool(chain_result.get("ok")),
        "verified": bool(chain_result.get("verified")),
        "entries": chain_result.get("entries", 0),
        "error": chain_result.get("error", ""),
        "scope": chain_result.get("scope", SCOPE_NOT_VERIFIED),
        "genesis_retained": bool(chain_result.get("genesis_retained")),
        "files": list(chain_result.get("files") or []),
        "chain_id": chain_result.get("chain_id", ""),
        "meaning": _chain_meaning(chain_result),
        "limits": _LIMITS,
    }


def _format_json(
    record: Dict[str, Any],
    chain_result: Dict[str, Any],
) -> str:
    """Machine-readable JSON output."""
    output = dict(record_review(record))
    output["chain"] = chain_review(chain_result)
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
    try:
        chain_result = verify_audit_chain(audit_path)
    except Exception as exc:
        print(f"[audit-review] error reading audit log: {exc}", file=sys.stderr)
        chain_result = {"ok": False, "entries": 0, "error": str(exc), "scope": SCOPE_NOT_VERIFIED}

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
