"""Run service-objective harnesses or validate their records.

    python -m azazel_edge.service_objectives run --objective all --out-dir DIR
    python -m azazel_edge.service_objectives validate [--expect-commit SHA] DIR_OR_FILE...

``run`` writes one record per objective and exits 0 only if every record is a
valid ``pass``: 1 if any failed, 2 if any could not be measured, 3 if a record
is invalid or a harness crashed. A harness that crashes still leaves a
``not_measurable`` record behind; nothing is ever skipped into green.
``validate --expect-commit SHA`` also rejects a record whose owner.commit is
not SHA, so a record carried over from another commit cannot stand in.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List

from .record import (
    EXIT_INVALID,
    RULE_ZERO_VIOLATIONS,
    build_part,
    build_record,
    exit_code_for,
    load_and_validate,
    prerequisite,
    utc_now,
    validate_record,
    write_record,
)


def _harnesses(args: argparse.Namespace) -> Dict[str, Callable[[], Dict[str, Any]]]:
    from . import so03_alert_queue, so04_lease_rollback, so07_audit_ordering

    return {
        "SO-03": lambda: so03_alert_queue.run(seed=args.seed),
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


def cmd_run(args: argparse.Namespace) -> int:
    harnesses = _harnesses(args)
    wanted = list(harnesses) if args.objective == "all" else [args.objective]
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
            codes.append(EXIT_INVALID)
        else:
            codes.append(exit_code_for(record["verdict"]))
    return max(codes) if codes else EXIT_INVALID


def cmd_validate(args: argparse.Namespace) -> int:
    files: List[Path] = []
    for item in args.paths:
        p = Path(item)
        files.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m azazel_edge.service_objectives", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    run_p = sub.add_parser("run")
    run_p.add_argument("--objective", choices=["all", "SO-03", "SO-04", "SO-07"], default="all")
    run_p.add_argument("--out-dir", required=True)
    run_p.add_argument("--core-bin", default="")
    run_p.add_argument("--seed", type=int, default=None)
    val_p = sub.add_parser("validate")
    val_p.add_argument("--expect-commit", default=None, metavar="SHA", help="reject a record whose owner.commit differs")
    val_p.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    return cmd_run(args) if args.cmd == "run" else cmd_validate(args)


if __name__ == "__main__":
    sys.exit(main())
