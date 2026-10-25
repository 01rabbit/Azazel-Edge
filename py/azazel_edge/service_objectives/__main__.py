"""Run service-objective harnesses or validate their records.

    python -m azazel_edge.service_objectives run --objective all|SO-03,SO-07 [--ci] --out-dir DIR
    python -m azazel_edge.service_objectives validate [--expect-commit SHA] [--ci --objective SO-03,...] DIR_OR_FILE...

``run`` writes one record per objective and exits 0 only if every record is a
valid ``pass``: 1 if any failed, 2 if any could not be measured, 3 if a record
is invalid or a harness crashed. A harness that crashes still leaves a
``not_measurable`` record behind; nothing is ever skipped into green.
``validate --expect-commit SHA`` also rejects a record whose owner.commit is
not SHA, so a record carried over from another commit cannot stand in.

``--ci`` (CI mode) changes only the exit status, never a verdict. It exits 0
only if every requested objective has a record, every record is structurally
valid, every harness actually executed (took its required samples; see
``record.not_executed_reasons``), every part's pass rule holds (no violation,
no unfinished sample), every unmet prerequisite is in
``record.CI_DECLARED_PREREQUISITES`` (empty today), and every verdict is
``pass`` or ``not_measurable``. So a green ``not_measurable`` is a clean
measurement blocked only by declared gaps; CI shows it in a verdict table
written to ``$GITHUB_STEP_SUMMARY`` by ``validate --ci``. Non-zero: 1 a
``fail``, 2 a ``not_measurable`` over the bound or with unfinished samples,
3 an invalid or missing record, 4 a harness that did not execute (skipped,
crashed, root missing so no samples) or a run-health prerequisite unmet.
``validate --ci`` needs ``--objective`` so a missing record is detected.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path
import os
from typing import Any, Callable, Dict, List, Optional, Sequence

from .record import (
    EXIT_INVALID,
    RULE_ZERO_VIOLATIONS,
    build_part,
    build_record,
    ci_exit_code_for,
    exit_code_for,
    load_and_validate,
    ci_measurement_problems,
    not_executed_reasons,
    prerequisite,
    utc_now,
    validate_record,
    write_record,
)


def _harnesses(args: argparse.Namespace) -> Dict[str, Callable[[], Dict[str, Any]]]:
    from . import so02_source_failure, so03_alert_queue, so04_lease_rollback, so07_audit_ordering

    return {
        "SO-02": lambda: so02_source_failure.run(seed=args.seed),
        "SO-03": lambda: so03_alert_queue.run(core_bin=Path(args.core_bin) if args.core_bin else None, seed=args.seed),
        "SO-04": lambda: so04_lease_rollback.run(core_bin=Path(args.core_bin) if args.core_bin else None, seed=args.seed),
        "SO-07": lambda: so07_audit_ordering.run(seed=args.seed),
    }


def _crash_record(objective_id: str, exc: BaseException) -> Dict[str, Any]:
    part = build_part(
        name="harness_crashed",
        pass_rule={"kind": RULE_ZERO_VIOLATIONS, "description": "harness did not complete"},
        required_samples=1,
        samples=[],
        prerequisites=[prerequisite("harness_completed", False, "".join(traceback.format_exception_only(type(exc), exc)).strip())],
        gaps=[],
    )
    return build_record(
        objective_id=objective_id,
        title="harness crashed before measuring",
        started_monotonic_ns=time.monotonic_ns(),
        started_at=utc_now(),
        product_configuration={"product": "azazel-edge"},
        clock={"name": "CLOCK_MONOTONIC"},
        sample_rule={},
        parts=[part],
        method="none (crash)",
    )


def _summary(record: Dict[str, Any]) -> str:
    bits = [f"{record['objective_id']}: verdict={record['verdict']}"]
    for part in record["parts"]:
        ev = part["pass_rule"].get("evaluated", {})
        unmet = [p["id"] for p in part["prerequisites"] if not p["met"]]
        blocking = [g["id"] for g in part["gaps"] if g["blocks_verdict"]]
        bits.append(
            f"  [{part['name']}] verdict={part['verdict']} samples={len(part['samples'])}/{part['sample_rule']['required_samples']}"
            f" holds={ev.get('holds')} max_ms={ev.get('max_elapsed_ms')} violations={ev.get('violations')}"
            + (f" unmet={unmet}" if unmet else "")
            + (f" gaps={blocking}" if blocking else "")
        )
    return "\n".join(bits)


OBJECTIVES = ("SO-02", "SO-03", "SO-04", "SO-07")


def parse_objectives(value: str) -> List[str]:
    """``all`` or a comma-separated list of known objectives, in the order given."""

    if value == "all":
        return list(OBJECTIVES)
    wanted: List[str] = []
    for item in value.split(","):
        oid = item.strip()
        if oid not in OBJECTIVES:
            raise argparse.ArgumentTypeError(f"unknown objective {oid!r}; expected 'all' or a comma-separated list of {', '.join(OBJECTIVES)}")
        if oid not in wanted:
            wanted.append(oid)
    return wanted


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def summary_table(rows: Sequence[Dict[str, Any]]) -> str:
    """Markdown verdict table: one row per part, so not_measurable is never hidden."""

    lines = [
        "| objective | part | verdict | executed | samples | max ms | violations | blocking gaps | unmet prerequisites | CI |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        record = row.get("record")
        if record is None:
            lines.append(f"| {_cell(row['objective'])} | {_cell(row.get('note', '-'))[:300]} | - | no | - | - | - | - | - | {_cell(row['ci'])} |")
            continue
        not_run = not_executed_reasons(record)
        for part in record.get("parts") or []:
            ev = (part.get("pass_rule") or {}).get("evaluated") or {}
            unmet = [p.get("id") for p in part.get("prerequisites") or [] if not p.get("met")]
            gaps = [g.get("id") for g in part.get("gaps") or [] if g.get("blocks_verdict")]
            executed = not any(r.startswith(f"{part.get('name')}:") for r in not_run)
            lines.append(
                f"| {_cell(record.get('objective_id'))} | {_cell(part.get('name'))} | {_cell(part.get('verdict'))}"
                f" | {'yes' if executed else 'no'}"
                f" | {len(part.get('samples') or [])}/{_cell((part.get('sample_rule') or {}).get('required_samples'))}"
                f" | {_cell(ev.get('max_elapsed_ms', '-'))} | {_cell(ev.get('violations', '-'))}"
                f" | {_cell(', '.join(gaps) or '-')} | {_cell(', '.join(str(u) for u in unmet) or '-')} | {_cell(row['ci'])} |"
            )
    return "\n".join(lines)


_CI_RESULT = {
    0: "ok",
    1: "FAIL (verdict fail)",
    2: "FAIL (over the bound or unfinished samples, though gap-blocked)",
    3: "FAIL (invalid or missing record)",
    4: "FAIL (harness did not execute, or a run-health prerequisite is unmet)",
}


def write_step_summary(title: str, rows: Sequence[Dict[str, Any]], code: int) -> Optional[Path]:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return None
    verdict_line = "CI result: **green**" if code == 0 else f"CI result: **red** (exit {code})"
    text = (
        f"### {title}\n\n{verdict_line}. `not_measurable` with executed=yes is green only because its gaps are declared;"
        " it is not a pass and not gate evidence.\n\n" + summary_table(rows) + "\n\n"
    )
    path = Path(target)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text)
    return path


def cmd_run(args: argparse.Namespace) -> int:
    harnesses = _harnesses(args)
    wanted = args.objective
    out_dir = Path(args.out_dir)
    codes: List[int] = []
    for oid in wanted:
        try:
            record = harnesses[oid]()
        except Exception as exc:  # never let a crash read as a skip
            record = _crash_record(oid, exc)
        path = write_record(record, out_dir)
        errors = validate_record(record)
        print(_summary(record))
        print(f"  record: {path}")
        if errors:
            print("  INVALID RECORD: " + "; ".join(errors))
        if args.ci:
            code = ci_exit_code_for(record, errors)
            for reason in not_executed_reasons(record):
                print(f"  NOT EXECUTED: {reason}")
            for reason in ci_measurement_problems(record) if not errors else []:
                print(f"  CI PROBLEM: {reason}")
            print(f"  ci: {_CI_RESULT.get(code, code)}")
            codes.append(code)
        else:
            codes.append(EXIT_INVALID if errors else exit_code_for(record["verdict"]))
    return max(codes) if codes else EXIT_INVALID


def cmd_validate(args: argparse.Namespace) -> int:
    files: List[Path] = []
    for item in args.paths:
        p = Path(item)
        files.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
    if args.ci:
        return _validate_ci(args, files)
    if not files:
        print("no records found: nothing validated is not a pass")
        return EXIT_INVALID
    code = 0
    for f in files:
        errors = load_and_validate(f, expect_commit=args.expect_commit)
        if errors:
            print(f"{f}: INVALID: " + "; ".join(errors))
            code = max(code, EXIT_INVALID)
            continue
        record = json.loads(f.read_text(encoding="utf-8"))
        print(f"{f}: valid, " + _summary(record))
        code = max(code, exit_code_for(record["verdict"]))
    return code


def _validate_ci(args: argparse.Namespace, files: List[Path]) -> int:
    wanted: List[str] = args.objective or []
    rows: List[Dict[str, Any]] = []
    codes: List[int] = []
    seen = set()
    for f in files:
        errors = load_and_validate(f, expect_commit=args.expect_commit)
        try:
            record = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            record = None
        if not isinstance(record, dict):
            record = None
            errors = errors or ["not a JSON object"]
        oid = record.get("objective_id") if record else f.name
        if record and oid not in wanted:
            # A record nobody asked for is not evidence for this job.
            errors = list(errors) + [f"objective {oid!r} was not requested ({','.join(wanted)})"]
        code = ci_exit_code_for(record or {}, errors)
        status = _CI_RESULT.get(code, code)
        if errors:
            print(f"{f}: INVALID: " + "; ".join(errors))
        else:
            print(f"{f}: valid, " + _summary(record))
        for reason in not_executed_reasons(record or {}) if not errors else []:
            print(f"  NOT EXECUTED: {reason}")
        for reason in ci_measurement_problems(record or {}) if not errors else []:
            print(f"  CI PROBLEM: {reason}")
        print(f"  ci: {status}")
        codes.append(code)
        if not errors:
            seen.add(oid)
        rows.append({"objective": oid, "record": None if errors else record, "ci": status, "note": f"{f.name}: " + "; ".join(errors)})
    for oid in wanted:
        if oid not in seen:
            print(f"{oid}: MISSING: no valid record for a requested objective")
            codes.append(EXIT_INVALID)
            rows.append({"objective": oid, "record": None, "ci": _CI_RESULT[EXIT_INVALID], "note": "no valid record"})
    code = max(codes) if codes else EXIT_INVALID
    write_step_summary("Service objectives: " + ", ".join(wanted), rows, code)
    return code


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m azazel_edge.service_objectives", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    run_p = sub.add_parser("run")
    ci_help = "CI mode: exit 0 iff every requested record exists, is valid, executed, and is pass or not_measurable"
    run_p.add_argument("--objective", type=parse_objectives, default=list(OBJECTIVES), metavar="all|SO-xx[,SO-yy...]")
    run_p.add_argument("--out-dir", required=True)
    run_p.add_argument("--core-bin", default="")
    run_p.add_argument("--seed", type=int, default=None)
    run_p.add_argument("--ci", action="store_true", help=ci_help)
    val_p = sub.add_parser("validate")
    val_p.add_argument("--expect-commit", default=None, metavar="SHA", help="reject a record whose owner.commit differs")
    val_p.add_argument("--ci", action="store_true", help=ci_help + "; needs --objective")
    val_p.add_argument("--objective", type=parse_objectives, default=None, metavar="all|SO-xx[,SO-yy...]", help="objectives that must each have a record (CI mode)")
    val_p.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    if args.cmd == "validate" and args.ci and not args.objective:
        parser.error("validate --ci needs --objective, so a missing record is detected")
    if args.cmd == "validate" and args.objective and not args.ci:
        parser.error("validate --objective is only meaningful with --ci")
    return cmd_run(args) if args.cmd == "run" else cmd_validate(args)


if __name__ == "__main__":
    sys.exit(main())
