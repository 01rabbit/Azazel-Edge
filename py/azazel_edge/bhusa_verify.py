from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_SCENARIO = "mixed_correlation_demo"
DEFAULT_TRACE_ID = f"demo:{DEFAULT_SCENARIO}"
DEFAULT_EXPLANATIONS_PATH = "/tmp/azazel-edge-demo-explanations.jsonl"
DEFAULT_AUDIT_PATH = "/tmp/azazel-edge-demo-triage-audit.jsonl"
DEFAULT_SERVICES: tuple[tuple[str, bool], ...] = (
    ("azazel-edge-web", True),
    ("azazel-edge-control-daemon", True),
    ("azazel-edge-core", False),
    ("azazel-edge-opencanary", False),
)


def _run_command(cmd: List[str], *, extra_env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _load_json(stdout: str, *, context: str) -> Dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{context} returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{context} returned non-object JSON")
    return payload


def _check_service(unit: str) -> Dict[str, Any]:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return {
            "unit": unit,
            "status": "skipped",
            "detail": "systemctl not available",
            "ok": True,
        }
    try:
        result = subprocess.run(
            [systemctl, "is-active", unit],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        return {
            "unit": unit,
            "status": "skipped",
            "detail": str(exc),
            "ok": True,
        }

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if result.returncode == 0 and stdout == "active":
        return {
            "unit": unit,
            "status": "active",
            "detail": stdout,
            "ok": True,
        }
    if "System has not been booted with systemd" in stderr:
        return {
            "unit": unit,
            "status": "skipped",
            "detail": stderr,
            "ok": True,
        }
    detail = stderr or stdout or f"systemctl exit {result.returncode}"
    return {
        "unit": unit,
        "status": "inactive",
        "detail": detail,
        "ok": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-verify",
        description=(
            "Run the BHUSA 2026 booth verification sequence: replay the primary "
            "scenario, verify compact audit review, and optionally check booth services."
        ),
    )
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO, help="Demo scenario to verify.")
    parser.add_argument(
        "--trace-id",
        default=None,
        help=(
            "Expected trace ID for audit review. Defaults to demo:<scenario> for the "
            "selected scenario."
        ),
    )
    parser.add_argument(
        "--explanations-path",
        default=DEFAULT_EXPLANATIONS_PATH,
        help="Explanation JSONL path passed to azazel-edge-audit-review.",
    )
    parser.add_argument(
        "--audit-path",
        default=DEFAULT_AUDIT_PATH,
        help="Audit JSONL path passed to azazel-edge-audit-review.",
    )
    parser.add_argument(
        "--skip-services",
        action="store_true",
        help="Skip systemctl service checks.",
    )
    parser.add_argument(
        "--strict-services",
        action="store_true",
        help="Fail if a checked service is inactive instead of reporting a warning-only optional miss.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit machine-readable JSON instead of formatted text.",
    )
    return parser


def _verify_services(skip_services: bool, strict_services: bool) -> tuple[List[Dict[str, Any]], List[str]]:
    if skip_services:
        return [], []

    checks: List[Dict[str, Any]] = []
    errors: List[str] = []
    for unit, required in DEFAULT_SERVICES:
        result = _check_service(unit)
        result["required"] = required
        checks.append(result)
        if result["status"] == "skipped":
            continue
        if result["ok"]:
            continue
        if required or strict_services:
            errors.append(f"service {unit} is not active: {result['detail']}")
    return checks, errors


def _verify_demo_run(
    scenario: str,
    expected_trace_id: str,
    explanations_path: str,
    audit_path: str,
) -> tuple[Dict[str, Any], Dict[str, Any], List[str], str]:
    demo_cmd = [str(BIN_DIR / "azazel-edge-scenario-replay"), "run", scenario, "--format", "json"]
    result = _run_command(
        demo_cmd,
        extra_env={
            "AZAZEL_DEMO_EXPLANATIONS_PATH": explanations_path,
            "AZAZEL_DEMO_AUDIT_PATH": audit_path,
        },
    )
    errors: List[str] = []
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        return {}, {}, [f"demo run failed: {stderr}"], " ".join(demo_cmd)

    payload = _load_json(result.stdout, context="azazel-edge-scenario-replay")
    demo_result = payload.get("result")
    if not isinstance(demo_result, dict):
        return payload, {}, ["demo run returned no result object"], " ".join(demo_cmd)

    execution = demo_result.get("execution")
    arbiter = demo_result.get("arbiter")
    explanation = demo_result.get("explanation")
    if not isinstance(execution, dict):
        errors.append("demo run payload missing execution block")
    if not isinstance(arbiter, dict):
        errors.append("demo run payload missing arbiter block")
    if not isinstance(explanation, dict):
        errors.append("demo run payload missing explanation block")

    if isinstance(execution, dict):
        if execution.get("trace_id") != expected_trace_id:
            errors.append(
                f"demo trace_id mismatch: expected {expected_trace_id}, got {execution.get('trace_id')}"
            )
        if execution.get("mode") != "deterministic_replay":
            errors.append(f"demo mode is not deterministic_replay: {execution.get('mode')}")
        if execution.get("ai_used") is not False:
            errors.append(f"demo ai_used must be false, got {execution.get('ai_used')!r}")
        if execution.get("local_only") is not True:
            errors.append(f"demo local_only must be true, got {execution.get('local_only')!r}")
        if execution.get("offline_demo") is not True:
            errors.append(f"demo offline_demo must be true, got {execution.get('offline_demo')!r}")

    if isinstance(arbiter, dict):
        if arbiter.get("action") != "throttle":
            errors.append(f"demo selected action changed from booth baseline: {arbiter.get('action')}")

    return payload, demo_result, errors, " ".join(demo_cmd)


def _verify_audit_review(
    expected_trace_id: str,
    explanations_path: str,
    audit_path: str,
    demo_result: Dict[str, Any],
) -> tuple[Dict[str, Any], List[str], str]:
    audit_cmd = [
        str(BIN_DIR / "azazel-edge-audit-review"),
        "--explanations-path",
        explanations_path,
        "--audit-path",
        audit_path,
        "--trace-id",
        expected_trace_id,
        "--json",
    ]
    result = _run_command(audit_cmd)
    errors: List[str] = []
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        return {}, [f"audit review failed: {stderr}"], " ".join(audit_cmd)

    payload = _load_json(result.stdout, context="azazel-edge-audit-review")
    chain = payload.get("chain")
    if payload.get("trace_id") != expected_trace_id:
        errors.append(
            f"audit review trace_id mismatch: expected {expected_trace_id}, got {payload.get('trace_id')}"
        )
    if payload.get("selected_action") != demo_result.get("arbiter", {}).get("action"):
        errors.append(
            "audit review selected_action does not match demo arbiter action"
        )
    if payload.get("policy_profile") != demo_result.get("explanation", {}).get("policy_profile"):
        errors.append(
            "audit review policy_profile does not match demo explanation policy profile"
        )
    if payload.get("config_hash") != demo_result.get("explanation", {}).get("config_hash"):
        errors.append("audit review config_hash does not match demo explanation config hash")
    if payload.get("schema_valid") is not True:
        errors.append(f"audit review schema_valid must be true, got {payload.get('schema_valid')!r}")
    if not isinstance(chain, dict) or chain.get("ok") is not True:
        errors.append("audit review chain verification did not report ok=true")
    return payload, errors, " ".join(audit_cmd)


def _build_report(args: argparse.Namespace) -> Dict[str, Any]:
    scenario = args.scenario
    expected_trace_id = args.trace_id or f"demo:{scenario}"
    service_checks, service_errors = _verify_services(args.skip_services, args.strict_services)
    demo_payload, demo_result, demo_errors, demo_cmd = _verify_demo_run(
        scenario,
        expected_trace_id,
        args.explanations_path,
        args.audit_path,
    )
    audit_payload: Dict[str, Any] = {}
    audit_errors: List[str] = []
    audit_cmd = ""
    if not demo_errors:
        audit_payload, audit_errors, audit_cmd = _verify_audit_review(
            expected_trace_id,
            args.explanations_path,
            args.audit_path,
            demo_result,
        )

    errors = [*service_errors, *demo_errors, *audit_errors]
    execution = demo_result.get("execution", {}) if isinstance(demo_result, dict) else {}
    arbiter = demo_result.get("arbiter", {}) if isinstance(demo_result, dict) else {}
    explanation = demo_result.get("explanation", {}) if isinstance(demo_result, dict) else {}
    chain = audit_payload.get("chain", {}) if isinstance(audit_payload, dict) else {}

    return {
        "ok": not errors,
        "scenario_id": scenario,
        "trace_id": expected_trace_id,
        "errors": errors,
        "commands": {
            "demo_run": demo_cmd,
            "audit_review": audit_cmd,
        },
        "services": service_checks,
        "demo": {
            "mode": execution.get("mode"),
            "ai_used": execution.get("ai_used"),
            "local_only": execution.get("local_only"),
            "offline_demo": execution.get("offline_demo"),
            "action": arbiter.get("action"),
            "release_condition": arbiter.get("release_condition"),
            "policy_profile": explanation.get("policy_profile"),
            "config_hash": explanation.get("config_hash"),
            "explanations_path": execution.get("explanations_path"),
            "audit_path": execution.get("audit_path"),
            "payload_ok": bool(demo_payload.get("ok")),
        },
        "audit_review": {
            "selected_action": audit_payload.get("selected_action"),
            "schema_valid": audit_payload.get("schema_valid"),
            "chain_ok": chain.get("ok"),
            "chain_entries": chain.get("entries"),
            "rejected_actions": audit_payload.get("rejected_actions", []),
        },
    }


def _format_text(report: Dict[str, Any]) -> str:
    lines = [
        "BHUSA 2026 BOOTH VERIFY",
        f"scenario: {report['scenario_id']}",
        f"trace_id: {report['trace_id']}",
        (
            "demo: "
            f"mode={report['demo'].get('mode')} "
            f"ai_used={report['demo'].get('ai_used')} "
            f"local_only={report['demo'].get('local_only')} "
            f"offline_demo={report['demo'].get('offline_demo')} "
            f"action={report['demo'].get('action')} "
            f"policy={report['demo'].get('policy_profile')} "
            f"hash={report['demo'].get('config_hash')}"
        ),
        (
            "audit: "
            f"action={report['audit_review'].get('selected_action')} "
            f"schema_valid={report['audit_review'].get('schema_valid')} "
            f"chain_ok={report['audit_review'].get('chain_ok')} "
            f"entries={report['audit_review'].get('chain_entries')}"
        ),
    ]
    if report["services"]:
        for item in report["services"]:
            requirement = "required" if item.get("required") else "optional"
            lines.append(
                f"service: {item.get('unit')} {requirement} {item.get('status')} {item.get('detail')}"
            )
    else:
        lines.append("service: skipped")

    if report["errors"]:
        lines.append("result: FAIL")
        lines.extend(f"error: {item}" for item in report["errors"])
    else:
        lines.append("result: PASS")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = _build_report(args)
    except ValueError as exc:
        message = {"ok": False, "errors": [str(exc)]}
        if args.json_output:
            print(json.dumps(message, ensure_ascii=False, indent=2))
        else:
            print(f"result: FAIL\nerror: {exc}")
        return 2

    if args.json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(_format_text(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
