from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_RECORD_PATH = "/tmp/azazel-edge-bhusa-rehearsal.jsonl"
DEFAULT_SCENARIO = "mixed_correlation_demo"
VARIANTS = ("visitor-90s", "walkthrough-5m", "full", "fallback-drill", "daily-short-form")


def _run_command(cmd: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )


def _evidence_paths(args: argparse.Namespace) -> tuple[str, str]:
    if args.explanations_path and args.audit_path:
        return args.explanations_path, args.audit_path
    record_path = Path(args.record_path)
    base = record_path.with_suffix("")
    explanations_path = args.explanations_path or f"{base}-demo-explanations.jsonl"
    audit_path = args.audit_path or f"{base}-demo-triage-audit.jsonl"
    return explanations_path, audit_path


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(stdout: str, *, context: str) -> Dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{context} returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{context} returned non-object JSON")
    return payload


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at line {line_no}: {path}: {exc}") from exc
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _record_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = sub.add_parser("record", help="Run booth verification and append a rehearsal record")
    parser.add_argument("--variant", choices=VARIANTS, required=True, help="Rehearsal variant being logged")
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO, help="Demo scenario to verify")
    parser.add_argument(
        "--trace-id",
        default=None,
        help="Expected trace ID. Defaults to demo:<scenario>.",
    )
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"JSONL log path (default: {DEFAULT_RECORD_PATH})",
    )
    parser.add_argument(
        "--duration-sec",
        type=float,
        default=None,
        help="Actual presenter-script duration in seconds for this rehearsal variant.",
    )
    parser.add_argument(
        "--notes",
        default="",
        help="Optional operator note stored with the rehearsal record.",
    )
    parser.add_argument(
        "--fallback-drill",
        action="store_true",
        help="Mark that this rehearsal included the minimum fallback drill.",
    )
    parser.add_argument(
        "--verify-services",
        action="store_true",
        help="Include booth service checks instead of skipping them.",
    )
    parser.add_argument(
        "--explanations-path",
        default=None,
        help="Optional explanation JSONL path used for isolated booth verification evidence.",
    )
    parser.add_argument(
        "--audit-path",
        default=None,
        help="Optional audit JSONL path used for isolated booth verification evidence.",
    )
    parser.add_argument(
        "--clear-after",
        action="store_true",
        help="Run azazel-edge-demo clear after verification and record the result.",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")


def _summary_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = sub.add_parser("summary", help="Summarize recorded BHUSA rehearsal runs")
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"JSONL log path (default: {DEFAULT_RECORD_PATH})",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-rehearse",
        description="Record and summarize BHUSA 2026 booth rehearsals.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _record_parser(sub)
    _summary_parser(sub)
    return parser


def _record_run(args: argparse.Namespace) -> Dict[str, Any]:
    scenario = args.scenario
    trace_id = args.trace_id or f"demo:{scenario}"
    explanations_path, audit_path = _evidence_paths(args)
    verify_cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-verify"),
        "--scenario",
        scenario,
        "--trace-id",
        trace_id,
        "--explanations-path",
        explanations_path,
        "--audit-path",
        audit_path,
        "--json",
    ]
    if not args.verify_services:
        verify_cmd.append("--skip-services")

    verify_started = time.monotonic()
    verify_result = _run_command(verify_cmd)
    verify_duration_sec = round(time.monotonic() - verify_started, 3)
    errors: List[str] = []
    verify_payload: Dict[str, Any]
    if verify_result.returncode != 0:
        stderr = verify_result.stderr.strip() or verify_result.stdout.strip() or f"exit {verify_result.returncode}"
        raise ValueError(f"booth verification failed: {stderr}")
    verify_payload = _load_json(verify_result.stdout, context="azazel-edge-bhusa-verify")
    if not verify_payload.get("ok"):
        errors.extend(str(item) for item in verify_payload.get("errors", []))

    clear_payload: Dict[str, Any] = {"requested": bool(args.clear_after), "ok": None}
    if args.clear_after:
        clear_cmd = [str(BIN_DIR / "azazel-edge-demo"), "clear", "--format", "json"]
        clear_started = time.monotonic()
        clear_result = _run_command(clear_cmd)
        clear_duration_sec = round(time.monotonic() - clear_started, 3)
        clear_payload["duration_sec"] = clear_duration_sec
        clear_payload["command"] = " ".join(clear_cmd)
        if clear_result.returncode != 0:
            stderr = clear_result.stderr.strip() or clear_result.stdout.strip() or f"exit {clear_result.returncode}"
            errors.append(f"clear failed: {stderr}")
            clear_payload["ok"] = False
            clear_payload["detail"] = stderr
        else:
            clear_json = _load_json(clear_result.stdout, context="azazel-edge-demo clear")
            clear_payload["ok"] = bool(clear_json.get("ok"))
            clear_payload["detail"] = clear_json
            if not clear_payload["ok"]:
                errors.append("clear reported ok=false")

    record = {
        "ts": _now_iso(),
        "variant": args.variant,
        "scenario_id": scenario,
        "trace_id": trace_id,
        "result": "pass" if not errors else "fail",
        "fallback_drill": bool(args.fallback_drill or args.variant == "fallback-drill"),
        "presenter_duration_sec": args.duration_sec,
        "notes": args.notes,
        "verify_services": bool(args.verify_services),
        "booth_verify": {
            "ok": bool(verify_payload.get("ok")) and not errors,
            "duration_sec": verify_duration_sec,
            "report": verify_payload,
            "command": " ".join(verify_cmd),
            "explanations_path": explanations_path,
            "audit_path": audit_path,
        },
        "clear_after": clear_payload,
        "errors": errors,
    }

    record_path = Path(args.record_path)
    _append_jsonl(record_path, record)
    return {
        "ok": not errors,
        "record_path": str(record_path),
        "record": record,
    }


def _summary_run(args: argparse.Namespace) -> Dict[str, Any]:
    record_path = Path(args.record_path)
    rows = _read_jsonl(record_path)
    variant_counts: Dict[str, int] = {}
    variant_passes: Dict[str, int] = {}
    variant_fallbacks: Dict[str, int] = {}
    duration_totals: Dict[str, float] = {}
    duration_counts: Dict[str, int] = {}

    for row in rows:
        variant = str(row.get("variant") or "unknown")
        variant_counts[variant] = variant_counts.get(variant, 0) + 1
        if row.get("result") == "pass":
            variant_passes[variant] = variant_passes.get(variant, 0) + 1
        if row.get("fallback_drill"):
            variant_fallbacks[variant] = variant_fallbacks.get(variant, 0) + 1
        duration = row.get("presenter_duration_sec")
        if isinstance(duration, (int, float)):
            duration_totals[variant] = duration_totals.get(variant, 0.0) + float(duration)
            duration_counts[variant] = duration_counts.get(variant, 0) + 1

    variants: List[Dict[str, Any]] = []
    for variant in sorted(variant_counts):
        avg_duration = None
        if duration_counts.get(variant):
            avg_duration = round(duration_totals[variant] / duration_counts[variant], 3)
        variants.append(
            {
                "variant": variant,
                "runs": variant_counts[variant],
                "passes": variant_passes.get(variant, 0),
                "fallback_drills": variant_fallbacks.get(variant, 0),
                "avg_presenter_duration_sec": avg_duration,
            }
        )

    return {
        "ok": True,
        "record_path": str(record_path),
        "total_runs": len(rows),
        "pass_runs": sum(1 for row in rows if row.get("result") == "pass"),
        "fallback_drill_runs": sum(1 for row in rows if row.get("fallback_drill")),
        "variants": variants,
        "latest_record": rows[-1] if rows else None,
    }


def _format_record_text(report: Dict[str, Any]) -> str:
    record = report["record"]
    lines = [
        "BHUSA 2026 REHEARSAL RECORDED",
        f"record_path: {report['record_path']}",
        f"variant: {record['variant']}",
        f"scenario: {record['scenario_id']}",
        f"trace_id: {record['trace_id']}",
        f"result: {record['result'].upper()}",
        f"verify_duration_sec: {record['booth_verify']['duration_sec']}",
        f"presenter_duration_sec: {record['presenter_duration_sec']}",
        f"fallback_drill: {record['fallback_drill']}",
    ]
    if record["errors"]:
        lines.extend(f"error: {item}" for item in record["errors"])
    return "\n".join(lines)


def _format_summary_text(report: Dict[str, Any]) -> str:
    lines = [
        "BHUSA 2026 REHEARSAL SUMMARY",
        f"record_path: {report['record_path']}",
        f"total_runs: {report['total_runs']}",
        f"pass_runs: {report['pass_runs']}",
        f"fallback_drill_runs: {report['fallback_drill_runs']}",
    ]
    for item in report["variants"]:
        lines.append(
            "variant: "
            f"{item['variant']} runs={item['runs']} passes={item['passes']} "
            f"fallback_drills={item['fallback_drills']} "
            f"avg_presenter_duration_sec={item['avg_presenter_duration_sec']}"
        )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            report = _record_run(args)
            if args.json_output:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(_format_record_text(report))
            return 0 if report["ok"] else 1

        report = _summary_run(args)
        if args.json_output:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(_format_summary_text(report))
        return 0
    except ValueError as exc:
        if getattr(args, "json_output", False):
            print(json.dumps({"ok": False, "errors": [str(exc)]}, ensure_ascii=False, indent=2))
        else:
            print(f"result: FAIL\nerror: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
