"""One JSON evidence record per service-objective run, and its validator.

The record format is the one `01rabbit/Azazel` assigns in
`docs/roadmaps/service-objective-assignments.md` section 2: objective id,
owning repository and commit, product configuration, every sample with its
start and end instants, the pass rule as evaluated, and the verdict.

Three verdicts exist and only three:

``pass``
    Every prerequisite the definition needs is present, the sample rule is met,
    and the pass rule holds.
``fail``
    Every prerequisite is present, the sample rule is met, and the pass rule
    does not hold.
``not_measurable``
    Something the definition needs does not exist (a prerequisite is unmet or
    a gap blocks the verdict), or too few samples were taken. Observed numbers
    may still be carried, under ``pass_rule.evaluated``, as a regression
    signal; they are never gate evidence.

A harness that could not measure never writes ``pass``. "Skipped" is not a
verdict: a missing prerequisite yields ``not_measurable`` and a non-zero exit.

The validator re-derives the verdict from the record's own contents rather
than trusting the field, so a record whose verdict disagrees with its samples,
prerequisites or gaps is rejected.

Measurement is observation. Nothing in this package decides, enforces, or
changes how the arbiter behaves.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

RECORD_SCHEMA = "azazel-edge/service-objective-record/v1"
HARNESS_VERSION = "1"
OWNING_REPOSITORY = "01rabbit/Azazel-Edge"
ASSIGNMENT_DOC = "01rabbit/Azazel:docs/roadmaps/service-objective-assignments.md"

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_NOT_MEASURABLE = "not_measurable"
VERDICTS = (VERDICT_PASS, VERDICT_FAIL, VERDICT_NOT_MEASURABLE)

# Exit status of a harness run. Zero is reserved for ``pass``.
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_NOT_MEASURABLE = 2
EXIT_INVALID = 3

RULE_EVERY_SAMPLE_MAX = "every_sample_max_elapsed"
RULE_ZERO_VIOLATIONS = "zero_violations"
# Each sample against the bound its action type declares in Edge's declaration
# file (``declarations``), never against a bound the record carries.
RULE_EVERY_SAMPLE_MAX_PER_ACTION = "every_sample_max_elapsed_per_action"
RULE_KINDS = (RULE_EVERY_SAMPLE_MAX, RULE_ZERO_VIOLATIONS, RULE_EVERY_SAMPLE_MAX_PER_ACTION)

# The fixed definition of every objective this repository measures. The
# validator compares each record against this table and never against the
# record's own declarations, so a record cannot pass by declaring a looser
# bound, fewer samples, or fewer prerequisites. The harnesses read their bounds
# and sample counts from here too. Changing a row here changes what counts as
# evidence: it needs the review a target change needs, and closing a gap means
# removing it here in the same change that makes the missing thing exist.
SO07_INJECTION_POINTS = (
    "after_report",
    "random_time",
    "between_write_and_close",
    "after_close_before_return",
    "during_fabric_projection",
)
# 0: a record well under Python's 8 KiB write buffer; 16 KiB: one larger than
# it, which the buffered writer passes straight to the kernel.
SO07_RECORD_PADS = (0, 16 * 1024)

# SO-02 lab source types, and where the read-only operator surface
# (GET /api/state) names each one's failure. Edge declares no source-type list
# (gap SO02-SOURCE-TYPES-UNDECLARED); these are the logical types whose failure
# the surface names by source today. Each entry: the source id, the surface
# field, and the value that field shows while the source is healthy / failed.
SO02_CAPTURE_PROCESS = "capture_process_death"
SO02_CAPTURE_INTERFACE = "capture_interface_link_down"
SO02_LAB_SOURCE_TYPES = (SO02_CAPTURE_PROCESS, SO02_CAPTURE_INTERFACE)
SO02_SURFACE = {
    # azazel_edge_web/app.py get_monitoring_state(): ON/OFF per daemon.
    SO02_CAPTURE_PROCESS: {"source_id": "suricata", "field": "monitoring.suricata"},
    # The control daemon's NOC projection: interfaces whose path probes fail.
    # br0 is Edge's default capture interface (SURICATA_IFACE) and internal
    # monitor bridge (AZAZEL_INTERNAL_BRIDGE_IF).
    SO02_CAPTURE_INTERFACE: {"source_id": "br0", "field": "noc_blast_radius.affected_uplinks"},
}
SO02_PER_SOURCE_TYPE_SAMPLES = 10

OBJECTIVE_SPECS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "SO-02": {
        "source_failure_visible": {
            "kind": "every_sample_max_elapsed",
            "bound_ms": 10000.0,
            # 20 injections covering every declared source type; the lab
            # types split them evenly (recomputed: every_lab_source_type_sampled).
            "required_samples": 20,
            # The release form of the logical source types is virtual-lab. The
            # physical-NIC variant is hardware-only (R7): no record of this
            # objective is evidence for it.
            "row_class": "virtual-lab",
            "prerequisites": (
                "lab_built",
                "no_live_capture_touched",
                "edge_stack_answering",
                # Recomputed from the samples by the validator.
                "every_injection_from_healthy_baseline",
                "every_lab_source_type_sampled",
            ),
            "gaps": (
                "SO02-NOT-NEXUS-INTEGRATED",
                "SO02-SOURCE-TYPES-UNDECLARED",
                "SO02-NO-COMMISSIONED-INTERFACE-IDENTITY",
            ),
        },
    },
    "SO-03": {
        "decision_durable_to_alert_enqueued": {
            "kind": "every_sample_max_elapsed",
            "bound_ms": 2000.0,
            "required_samples": 200,
            # All but the chain check are recomputed from the samples by the validator.
            "prerequisites": (
                "visual_voice_delivery_queue_declared",
                "alert_audit_chain_verifies",
                "enqueue_record_names_decision_id",
                "enqueue_record_classifies_p0",
                "decision_and_enqueue_records_fsynced",
            ),
            "gaps": (
                "SO03-NO-VISUAL-VOICE-QUEUE",
                "SO03-NO-P0-ALERT-PATH",
                # The Rust core's throttle/redirect/isolate decisions are not
                # written as action_decision records through P0AuditLogger, so
                # the P0 relay never sees them; which decision path is
                # authoritative is Edge#412. No sample can close this one: it
                # is deliberately absent from gaps_closed_by_samples, so SO-03
                # stays not_measurable until that path is wired.
                "SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS",
            ),
            # Closed only by recomputation from every sample (GAP_CLOSERS):
            # each sample's end is the P0 queue's fsynced enqueue record, on
            # both channels, naming the decision and built from its
            # audit-chain record under the owner's P0 rule.
            "gaps_closed_by_samples": (
                "SO03-NO-VISUAL-VOICE-QUEUE",
                "SO03-NO-P0-ALERT-PATH",
            ),
        },
    },
    "SO-04": {
        "rollback_start_after_expiry": {
            "kind": "every_sample_max_elapsed",
            "bound_ms": 5000.0,
            "required_samples": 150,
            # 50 leases per declared action type (assignment SO-04 sample rule).
            "per_action_samples": 50,
            "prerequisites": (
                "core_binary_present",
                "core_daemon_started",
                "wall_clock_stable_during_run",
                "no_release_record_before_expiry",
                "load_phase_applied",
                # The end event is the core's rollback_started audit-chain
                # record: the chain must verify, and the record must already be
                # there when the attempt's outcome appears.
                "rollback_start_chain_verifies",
                "rollback_start_recorded_before_outcome",
            ),
            "gaps": (
                "SO04-LEASE-EXPIRY-ON-WALL-CLOCK",
                "SO04-HOSTILE-LOAD-UNDECLARED",
            ),
            # A record may leave these out only when its samples show, by
            # recomputation (GAP_CLOSERS), that the missing thing exists.
            # SO04-LEASE-EXPIRY-ON-WALL-CLOCK: every lease expired on its
            # monotonic deadline and every start is measured from it.
            "gaps_closed_by_samples": ("SO04-LEASE-EXPIRY-ON-WALL-CLOCK",),
        },
        # OF-05: the bound is per action type and comes from
        # config/service_objectives/rollback_completion_bounds.json, which the
        # validator reads itself. The first three prerequisites are recomputed
        # from that file and the samples. The bounds there are provisional, so
        # SO04-COMPLETION-BOUND-PROVISIONAL stays until a hardware-derived
        # declaration replaces them.
        "rollback_completion": {
            "kind": "every_sample_max_elapsed_per_action",
            "bound_ms": None,
            "required_samples": 150,
            "per_action_samples": 50,
            "prerequisites": (
                "per_action_completion_bound_declared",
                "owned_state_installed_before_expiry",
                "completion_confirmed_by_readback",
                "core_binary_present",
                "core_daemon_started",
                "load_phase_applied",
                "wall_clock_stable_during_run",
            ),
            "gaps": (
                "SO04-COMPLETION-BOUND-PROVISIONAL",
                "SO04-LEASE-EXPIRY-ON-WALL-CLOCK",
                "SO04-HOSTILE-LOAD-UNDECLARED",
            ),
            # Same start as the start half, so the same recomputation closes it.
            "gaps_closed_by_samples": ("SO04-LEASE-EXPIRY-ON-WALL-CLOCK",),
        },
    },
    "SO-07": {
        "reported_complete_implies_record_present": {
            "kind": "zero_violations",
            "bound_ms": None,
            # 11 audit kinds x 5 injection points x 2 record sizes. A test pins
            # this to VALID_KINDS so a new kind cannot silently shrink coverage.
            "required_samples": 110,
            "prerequisites": (
                "every_record_kind_at_every_injection_point",
                "kill_landed_after_a_report",
            ),
            "gaps": (),
        },
    },
}
KNOWN_OBJECTIVES = tuple(OBJECTIVE_SPECS)
CRASH_PART = "harness_crashed"
# Prerequisites a record may carry beyond its objective's row: the one
# build_record adds when it downgrades a pass taken on an unidentifiable or
# modified tree, and (on a crash part only) the one the CLI's crash record sets.
DOWNGRADE_PREREQUISITE = "owner_commit_identified"
CRASH_PREREQUISITE = "harness_completed"

# The only fields a record, a part and a sample may carry. Anything else is
# rejected, so a record cannot smuggle in content the validator never reads.
# The sample fields are what each harness writes; adding one here is a schema
# change and needs the same review as the harness change that adds it.
RECORD_FIELDS = frozenset(
    {
        "schema", "objective_id", "title", "assignment_ref", "owner", "run",
        "product_configuration", "clock", "method", "sample_rule", "parts",
        "verdict", "evidence_class", "notes",
    }
)
PART_FIELDS = frozenset({"name", "sample_rule", "samples", "pass_rule", "prerequisites", "gaps", "verdict"})
_COMMON_SAMPLE_FIELDS = ("sample_id", "start_monotonic_ns", "end_monotonic_ns", "elapsed_ms", "start_event", "end_event")
SAMPLE_FIELDS: Dict[str, frozenset] = {
    "SO-02": frozenset(
        _COMMON_SAMPLE_FIELDS
        + (
            "source_type", "source_id", "injection", "surface", "surface_field",
            "baseline_healthy", "baseline_poll_started_monotonic_ns", "baseline_surface_value",
            "end_poll_started_monotonic_ns", "end_surface_value",
            "polls_after_injection", "poll_errors_after_injection", "recovered",
            # Diagnostic stage stamps (wall clock); never read for the verdict.
            "injection_wall_epoch", "end_noc_updated_epoch", "end_snapshot_epoch",
        )
    ),
    "SO-03": frozenset(
        _COMMON_SAMPLE_FIELDS
        + (
            "action", "reason", "decision_suspicion_label", "decision_chain_hash",
            "harness_log_call_monotonic_ns", "harness_log_returned_monotonic_ns",
            "edge_decision_durable_monotonic_ns", "queue_records", "enqueue_result_durability",
            "decision_record_fsynced", "enqueue_record_fsynced",
        )
    ),
    "SO-04": frozenset(
        _COMMON_SAMPLE_FIELDS
        + (
            "action_type", "condition", "due_epoch", "attempted_at_epoch",
            "edge_reported_start_after_expiry_ms", "release_status", "release_result",
            "observed_before_expiry", "start_record_chain_line", "start_record_attempt",
            "edge_recorded_start_monotonic_ns", "start_record_before_outcome",
            "sample_clock", "expiry_clock", "lease_due_boottime_ns", "lease_boot_id",
            "start_record_boot_id", "edge_recorded_start_boottime_ns", "edge_recorded_start_wall_epoch_ns",
            # rollback_completion samples
            "completion_bound_ms", "completion_attempts", "completion_result",
            "owned_state_installed", "owned_state_absent_after_run",
        )
    ),
    "SO-07": frozenset(
        _COMMON_SAMPLE_FIELDS
        + (
            "record_kind", "injection_point", "record_pad_bytes", "pause_at_seq",
            "reported_complete", "reported_complete_record_absent", "unreported_record_present",
            "problems", "chain_after_restart", "violations",
        )
    ),
}


def spec_for(objective_id: str, part_name: str) -> Dict[str, Any]:
    return OBJECTIVE_SPECS[objective_id][part_name]


def so07_sample_violations(sample: Mapping[str, Any]) -> int:
    """Violations of one SO-07 injection, recomputed from its observed fields.

    -1 means the sample could not observe (it had problems, or its fields are
    missing or inconsistent); the pass rule counts that against the run.
    """

    problems = sample.get("problems")
    absent = sample.get("reported_complete_record_absent")
    reported = sample.get("reported_complete")
    if not isinstance(problems, list) or problems:
        return -1
    if not isinstance(absent, list) or not isinstance(reported, int) or isinstance(reported, bool):
        return -1
    if reported < 0 or len(absent) > reported:
        return -1
    return len(absent)

REPO_ROOT = Path(__file__).resolve().parents[3]
MEASURED_PATHS = ("py", "rust", "config", "requirements")


def _verdict_rank(verdict: str) -> int:
    # fail is worse than not_measurable, which is worse than pass.
    return {VERDICT_PASS: 0, VERDICT_NOT_MEASURABLE: 1, VERDICT_FAIL: 2}[verdict]


def worst_verdict(verdicts: Iterable[str]) -> str:
    items = list(verdicts)
    if not items:
        return VERDICT_NOT_MEASURABLE
    return max(items, key=_verdict_rank)


def exit_code_for(verdict: str) -> int:
    return {
        VERDICT_PASS: EXIT_PASS,
        VERDICT_FAIL: EXIT_FAIL,
        VERDICT_NOT_MEASURABLE: EXIT_NOT_MEASURABLE,
    }.get(verdict, EXIT_INVALID)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _git(*args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-c", "safe.directory=*", *args],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except Exception:
        return None
    return out.stdout.strip()


def owner_block() -> Dict[str, Any]:
    commit = _git("rev-parse", "HEAD") or os.environ.get("GITHUB_SHA", "")
    # Modified or untracked files under the code the harnesses measure. The
    # record output directory and build products are deliberately outside it.
    status = _git("status", "--porcelain", "--", *MEASURED_PATHS)
    return {
        "repository": OWNING_REPOSITORY,
        "commit": commit or "",
        # None means "could not be determined", which the validator treats as
        # not clean. A pass taken on a modified tree names no commit.
        "worktree_clean": None if status is None else status == "",
    }


def run_block(started_monotonic_ns: int, started_at: str) -> Dict[str, Any]:
    return {
        "run_id": str(uuid.uuid4()),
        "harness_version": HARNESS_VERSION,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "started_monotonic_ns": started_monotonic_ns,
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "ci": {
            "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "github_workflow": os.environ.get("GITHUB_WORKFLOW", ""),
            "github_job": os.environ.get("GITHUB_JOB", ""),
        },
    }


def prerequisite(pid: str, met: bool, detail: str) -> Dict[str, Any]:
    return {"id": pid, "met": bool(met), "detail": str(detail)}


def gap(gid: str, summary: str, *, refs: Sequence[str] = ()) -> Dict[str, Any]:
    # A gap is something the definition needs that does not exist. It always
    # blocks the verdict; an observation that does not block belongs in notes.
    return {"id": gid, "summary": str(summary), "blocks_verdict": True, "refs": list(refs)}


def evaluate_every_sample_max(samples: Sequence[Mapping[str, Any]], bound_ms: float) -> Dict[str, Any]:
    """Evaluate "every sample <= bound". A sample with no end never met the bound."""

    elapsed = [s.get("elapsed_ms") for s in samples]
    finished = [float(v) for v in elapsed if isinstance(v, (int, float))]
    unfinished = sum(1 for v in elapsed if not isinstance(v, (int, float)))
    violations = sum(1 for v in finished if v > bound_ms) + unfinished
    return {
        "sample_count": len(samples),
        "unfinished_samples": unfinished,
        "violations": violations,
        "max_elapsed_ms": max(finished) if finished else None,
        "min_elapsed_ms": min(finished) if finished else None,
        "holds": bool(samples) and violations == 0,
    }


def evaluate_every_sample_max_per_action(
    samples: Sequence[Mapping[str, Any]], bounds_ms: Mapping[str, float]
) -> Dict[str, Any]:
    """Evaluate "every sample <= the bound its action type declares".

    A sample with no end, or whose action type declares no bound, is a
    violation: a missing declaration can never hold.
    """

    violations = 0
    unfinished = 0
    undeclared = 0
    per_action: Dict[str, Dict[str, Any]] = {}
    for s in samples:
        action = str(s.get("action_type"))
        bound = bounds_ms.get(action)
        elapsed = s.get("elapsed_ms")
        row = per_action.setdefault(action, {"bound_ms": bound, "sample_count": 0, "violations": 0, "max_elapsed_ms": None})
        row["sample_count"] += 1
        bad = False
        if not isinstance(elapsed, (int, float)):
            unfinished += 1
            bad = True
        else:
            row["max_elapsed_ms"] = float(elapsed) if row["max_elapsed_ms"] is None else max(row["max_elapsed_ms"], float(elapsed))
        if bound is None:
            undeclared += 1
            bad = True
        elif isinstance(elapsed, (int, float)) and float(elapsed) > float(bound):
            bad = True
        if bad:
            violations += 1
            row["violations"] += 1
    return {
        "sample_count": len(samples),
        "unfinished_samples": unfinished,
        "undeclared_action_samples": undeclared,
        "violations": violations,
        "per_action": per_action,
        "holds": bool(samples) and violations == 0,
    }


def evaluate_zero_violations(samples: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    counts = [s.get("violations") for s in samples]
    bad = sum(1 for v in counts if not isinstance(v, int) or v < 0)
    total = sum(v for v in counts if isinstance(v, int) and v > 0)
    return {
        "sample_count": len(samples),
        "malformed_samples": bad,
        "violations": total + bad,
        "holds": bool(samples) and total == 0 and bad == 0,
    }


def evaluate_rule(pass_rule: Mapping[str, Any], samples: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    kind = pass_rule.get("kind")
    if kind == RULE_EVERY_SAMPLE_MAX:
        return evaluate_every_sample_max(samples, float(pass_rule["bound_ms"]))
    if kind == RULE_ZERO_VIOLATIONS:
        return evaluate_zero_violations(samples)
    if kind == RULE_EVERY_SAMPLE_MAX_PER_ACTION:
        bounds = pass_rule.get("bounds_ms")
        return evaluate_every_sample_max_per_action(samples, bounds if isinstance(bounds, dict) else {})
    raise ValueError(f"unknown pass rule kind: {kind!r}")


def per_action_shortfall(samples: Sequence[Mapping[str, Any]], required: int) -> Dict[str, int]:
    """Declared action types with fewer than ``required`` samples, and their counts."""

    if not required:
        return {}
    from .declarations import ROLLBACK_ACTION_TYPES

    counts = {a: 0 for a in ROLLBACK_ACTION_TYPES}
    for s in samples:
        if s.get("action_type") in counts:
            counts[s["action_type"]] += 1
    return {a: n for a, n in counts.items() if n < int(required)}


def derive_verdict(
    *,
    prerequisites: Sequence[Mapping[str, Any]],
    gaps: Sequence[Mapping[str, Any]],
    required_samples: int,
    samples: Sequence[Mapping[str, Any]],
    evaluated: Mapping[str, Any],
    per_action_required: int = 0,
) -> str:
    if any(not p.get("met") for p in prerequisites):
        return VERDICT_NOT_MEASURABLE
    if gaps:
        return VERDICT_NOT_MEASURABLE
    if len(samples) < int(required_samples) or not samples:
        return VERDICT_NOT_MEASURABLE
    # The total is not enough: every declared action type needs its own count.
    if per_action_shortfall(samples, per_action_required):
        return VERDICT_NOT_MEASURABLE
    return VERDICT_PASS if evaluated.get("holds") else VERDICT_FAIL


def build_part(
    *,
    name: str,
    pass_rule: Dict[str, Any],
    required_samples: int,
    samples: List[Dict[str, Any]],
    prerequisites: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    per_action_required: int = 0,
) -> Dict[str, Any]:
    evaluated = evaluate_rule(pass_rule, samples) if samples else {"sample_count": 0, "holds": False}
    rule = dict(pass_rule)
    rule["evaluated"] = evaluated
    verdict = derive_verdict(
        prerequisites=prerequisites,
        gaps=gaps,
        required_samples=required_samples,
        samples=samples,
        evaluated=evaluated,
        per_action_required=per_action_required,
    )
    sample_rule: Dict[str, Any] = {"required_samples": int(required_samples)}
    if per_action_required:
        sample_rule["per_action_required"] = int(per_action_required)
        sample_rule["per_action_shortfall"] = per_action_shortfall(samples, per_action_required)
    return {
        "name": name,
        "sample_rule": sample_rule,
        "samples": samples,
        "pass_rule": rule,
        "prerequisites": prerequisites,
        "gaps": gaps,
        "verdict": verdict,
    }


def build_record(
    *,
    objective_id: str,
    title: str,
    started_monotonic_ns: int,
    started_at: str,
    product_configuration: Dict[str, Any],
    clock: Dict[str, Any],
    sample_rule: Dict[str, Any],
    parts: List[Dict[str, Any]],
    method: str,
    notes: Sequence[str] = (),
) -> Dict[str, Any]:
    """Assemble a record. The top-level verdict is the worst part verdict."""

    verdict = worst_verdict(p["verdict"] for p in parts)
    owner = owner_block()
    record: Dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "objective_id": objective_id,
        "title": title,
        "assignment_ref": f"{ASSIGNMENT_DOC} section 3 {objective_id}",
        "owner": owner,
        "run": run_block(started_monotonic_ns, started_at),
        "product_configuration": product_configuration,
        "clock": clock,
        "method": method,
        "sample_rule": sample_rule,
        "parts": parts,
        "verdict": verdict,
        "evidence_class": "gate" if verdict in (VERDICT_PASS, VERDICT_FAIL) else "diagnostic_only",
        "notes": list(notes),
    }
    if verdict == VERDICT_PASS and (not owner["commit"] or owner["worktree_clean"] is not True):
        # A pass must name the code it measured. On an unidentifiable or
        # modified tree the measurement still ran, but it is not evidence.
        for part in parts:
            part["prerequisites"].append(
                prerequisite(
                    DOWNGRADE_PREREQUISITE,
                    False,
                    "commit unknown or worktree modified; a pass must name the exact commit measured",
                )
            )
            part["verdict"] = VERDICT_NOT_MEASURABLE
        record["verdict"] = VERDICT_NOT_MEASURABLE
        record["evidence_class"] = "diagnostic_only"
    return record


def write_record(record: Mapping[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"{record['objective_id']}-{record['run']['run_id']}.json"
    path = out_dir / name
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


# ---------------------------------------------------------------- validation


class RecordInvalid(ValueError):
    pass


_TOP_KEYS = {
    "schema": str,
    "objective_id": str,
    "title": str,
    "assignment_ref": str,
    "owner": dict,
    "run": dict,
    "product_configuration": dict,
    "clock": dict,
    "method": str,
    "sample_rule": dict,
    "parts": list,
    "verdict": str,
    "evidence_class": str,
}


def _require(cond: bool, message: str, errors: List[str]) -> None:
    if not cond:
        errors.append(message)


def _reject_unknown_fields(obj: Mapping[str, Any], allowed: Iterable[str], where: str, errors: List[str]) -> None:
    unknown = sorted(str(k) for k in obj if k not in allowed)
    if unknown:
        errors.append(f"{where}: unknown field(s) {unknown}")


def _validate_sample(sample: Any, where: str, errors: List[str], allowed: Iterable[str] = _COMMON_SAMPLE_FIELDS) -> None:
    if not isinstance(sample, dict):
        errors.append(f"{where}: sample is not an object")
        return
    _reject_unknown_fields(sample, allowed, where, errors)
    _require(isinstance(sample.get("sample_id"), str) and bool(sample.get("sample_id")), f"{where}: sample_id missing", errors)
    start = sample.get("start_monotonic_ns")
    end = sample.get("end_monotonic_ns")
    _require(isinstance(start, int) and not isinstance(start, bool), f"{where}: start_monotonic_ns must be an integer", errors)
    _require(end is None or (isinstance(end, int) and not isinstance(end, bool)), f"{where}: end_monotonic_ns must be an integer or null", errors)
    elapsed = sample.get("elapsed_ms")
    if isinstance(start, int) and isinstance(end, int):
        _require(end >= start, f"{where}: end precedes start", errors)
        if elapsed is not None:
            _require(
                isinstance(elapsed, (int, float)) and abs(float(elapsed) - (end - start) / 1e6) < 0.01,
                f"{where}: elapsed_ms disagrees with start/end",
                errors,
            )
    elif end is None and elapsed is not None:
        errors.append(f"{where}: elapsed_ms given for a sample that never ended")


def _recomputed_latency_samples(samples: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Elapsed times taken from start/end only, never from the declared field."""

    out = []
    for s in samples:
        start, end = s.get("start_monotonic_ns"), s.get("end_monotonic_ns")
        ok = isinstance(start, int) and isinstance(end, int) and end >= start
        out.append({"elapsed_ms": (end - start) / 1e6 if ok else None, "action_type": s.get("action_type")})
    return out


# SO-03: the P0 queue and the owner's P0 rule (Edge#414, 2026-10-25), written
# here independently of azazel_edge.notify.p0_alert so the validator does not
# take the product's word for which decisions are P0.
SO03_QUEUE_SCHEMA = "azazel-edge/p0-alert-queue/v1"
SO03_CHANNELS = ("visual", "voice")
SO03_P0_RULE = "edge-p0/v1:enforcement-bearing-or-soc-critical"
SO03_ENFORCEMENT_ACTIONS = ("throttle", "redirect", "isolate")
SO03_QUEUE_RECORD_FIELDS = frozenset(
    {
        "channel", "schema", "record_type", "seq", "decision_id", "decision_chain_hash", "p0_class", "p0_basis",
        "p0_rule", "enqueued_monotonic_ns", "decision_durable_monotonic_ns", "decision_record_durable",
    }
)


def so03_expected_p0_basis(action: Any, suspicion_label: Any) -> str:
    """The owner's P0 rule: enforcement-bearing decision, or SOC critical."""

    if isinstance(action, str) and action in SO03_ENFORCEMENT_ACTIONS:
        return f"enforcement:{action}"
    if suspicion_label == "critical":
        return "soc_critical"
    return ""


def _so03_queue_records(sample: Mapping[str, Any]) -> Optional[List[Mapping[str, Any]]]:
    """The sample's queue records, one per channel, or None if they are not exactly that."""

    recs = sample.get("queue_records")
    if not isinstance(recs, list) or len(recs) != len(SO03_CHANNELS):
        return None
    if not all(isinstance(r, dict) and set(r) == SO03_QUEUE_RECORD_FIELDS for r in recs):
        return None
    if sorted(r.get("channel") for r in recs if isinstance(r.get("channel"), str)) != sorted(SO03_CHANNELS):
        return None
    if not all(r.get("schema") == SO03_QUEUE_SCHEMA and r.get("record_type") == "alert" and _int(r.get("seq")) for r in recs):
        return None
    return recs


def so03_enqueue_observed(sample: Mapping[str, Any]) -> bool:
    """SO-03: the sample's end is the P0 queue's enqueue record for its decision.

    The start is the Edge-recorded instant the decision record was durable
    (read after its fsync, inside the harness's call window); both channel
    entries name the decision and the audit-chain record (by chain hash) the
    alert was built from, carry that start, and were stamped inside the
    sample's window.
    """

    sid = sample.get("sample_id")
    start, end = sample.get("start_monotonic_ns"), sample.get("end_monotonic_ns")
    call, returned = sample.get("harness_log_call_monotonic_ns"), sample.get("harness_log_returned_monotonic_ns")
    chain = sample.get("decision_chain_hash")
    if not all(_int(v) for v in (start, end, call, returned)):
        return False
    if not (isinstance(sid, str) and sid and isinstance(chain, str) and chain):
        return False
    if sample.get("edge_decision_durable_monotonic_ns") != start or not (call <= start <= returned):
        return False
    recs = _so03_queue_records(sample)
    if recs is None:
        return False
    return all(
        r.get("decision_id") == sid
        and r.get("decision_chain_hash") == chain
        and r.get("decision_durable_monotonic_ns") == start
        and r.get("decision_record_durable") is True
        and _int(r.get("enqueued_monotonic_ns"))
        and start <= r["enqueued_monotonic_ns"] <= end
        for r in recs
    )


def so03_p0_classified(sample: Mapping[str, Any]) -> bool:
    """Every queue record carries the P0 class the owner's rule gives the decision."""

    expected = so03_expected_p0_basis(sample.get("action"), sample.get("decision_suspicion_label"))
    recs = _so03_queue_records(sample)
    return (
        bool(expected)
        and recs is not None
        and all(r.get("p0_class") == "P0" and r.get("p0_basis") == expected and r.get("p0_rule") == SO03_P0_RULE for r in recs)
    )


def so03_records_fsynced(sample: Mapping[str, Any]) -> bool:
    return (
        sample.get("decision_record_fsynced") is True
        and sample.get("enqueue_record_fsynced") is True
        and sample.get("enqueue_result_durability") == "fsynced"
    )


def so03_end_observed(sample: Mapping[str, Any]) -> bool:
    """The end event happened: a durable enqueue record for this decision."""

    return so03_enqueue_observed(sample) and so03_records_fsynced(sample)


def so03_observed_prerequisites(samples: Sequence[Mapping[str, Any]]) -> Dict[str, bool]:
    """SO-03 record prerequisites, recomputed from every sample's observed fields."""

    items = list(samples)
    return {
        "visual_voice_delivery_queue_declared": bool(items) and all(_so03_queue_records(s) is not None for s in items),
        "enqueue_record_names_decision_id": bool(items) and all(so03_enqueue_observed(s) for s in items),
        "enqueue_record_classifies_p0": bool(items) and all(so03_p0_classified(s) for s in items),
        "decision_and_enqueue_records_fsynced": bool(items) and all(so03_records_fsynced(s) for s in items),
    }


def so03_visual_voice_queue_observed(samples: Sequence[Mapping[str, Any]]) -> bool:
    """Closes SO03-NO-VISUAL-VOICE-QUEUE: every sample ended on a durable
    enqueue record of the P0 queue, on both the visual and the voice channel."""

    items = list(samples)
    return bool(items) and all(isinstance(s, dict) and so03_end_observed(s) for s in items)


def so03_p0_alert_path_observed(samples: Sequence[Mapping[str, Any]]) -> bool:
    """Closes SO03-NO-P0-ALERT-PATH: in addition, every alert is P0 under the
    owner's rule, recomputed from the decision fields, and names the
    audit-chain record it was built from."""

    items = list(samples)
    return bool(items) and all(isinstance(s, dict) and so03_end_observed(s) and so03_p0_classified(s) for s in items)


def _so02_surface_healthy(source_type: Any, value: Any) -> bool:
    entry = SO02_SURFACE.get(source_type) if isinstance(source_type, str) else None
    if entry is None:
        return False
    if source_type == SO02_CAPTURE_PROCESS:
        return value == "ON"
    return isinstance(value, list) and all(isinstance(v, str) for v in value) and entry["source_id"] not in value


def _so02_surface_failed(source_type: Any, value: Any) -> bool:
    entry = SO02_SURFACE.get(source_type) if isinstance(source_type, str) else None
    if entry is None:
        return False
    if source_type == SO02_CAPTURE_PROCESS:
        return value == "OFF"
    return isinstance(value, list) and entry["source_id"] in value


def so02_baseline_observed(sample: Mapping[str, Any]) -> bool:
    """SO-02: the surface showed this source healthy on a poll begun before the injection."""

    base, start = sample.get("baseline_poll_started_monotonic_ns"), sample.get("start_monotonic_ns")
    return (
        sample.get("baseline_healthy") is True
        and _int(base)
        and _int(start)
        and base <= start
        and _so02_surface_healthy(sample.get("source_type"), sample.get("baseline_surface_value"))
    )


def so02_failure_observed(sample: Mapping[str, Any]) -> bool:
    """SO-02: the sample's end is a poll of the operator surface, begun after the
    injection, on which the field for this source type names the source failed;
    and the same field showed it healthy before the injection.

    Recomputed from the observed fields, never from the sample's elapsed time.
    """

    source_type = sample.get("source_type")
    entry = SO02_SURFACE.get(source_type) if isinstance(source_type, str) else None
    if entry is None:
        return False
    if sample.get("source_id") != entry["source_id"] or sample.get("surface_field") != entry["field"]:
        return False
    if not so02_baseline_observed(sample):
        return False
    start, polled, end = sample.get("start_monotonic_ns"), sample.get("end_poll_started_monotonic_ns"), sample.get("end_monotonic_ns")
    if not (_int(start) and _int(polled) and _int(end) and start <= polled <= end):
        return False
    return _so02_surface_failed(source_type, sample.get("end_surface_value"))


def so02_sequence_problems(samples: Sequence[Any]) -> List[str]:
    """SO-02 samples are one run's injections in order: each injected after the
    previous one ended (or, if it never ended, after it began), from a baseline
    polled after that, with a strictly later end and at least one poll seen. A
    copied sample under a new id overlaps its original and is refused."""

    problems: List[str] = []
    prev_start: Optional[int] = None
    prev_end: Optional[int] = None
    for idx, s in enumerate(samples):
        if not isinstance(s, dict):
            continue
        start, end, base = s.get("start_monotonic_ns"), s.get("end_monotonic_ns"), s.get("baseline_poll_started_monotonic_ns")
        if not _int(start):
            continue
        if end is not None:
            if not (_int(end) and end > start):
                problems.append(f"samples[{idx}]: end must be strictly after the injection")
            polls = s.get("polls_after_injection")
            if not (_int(polls) and polls > 0):
                problems.append(f"samples[{idx}]: an ended sample must have seen at least one poll after the injection")
        if prev_start is not None:
            floor = prev_end if prev_end is not None else prev_start
            if start <= floor:
                problems.append(f"samples[{idx}]: injected before the previous sample ended (overlapping or out of order)")
            if _int(base) and base <= floor:
                problems.append(f"samples[{idx}]: baseline polled before the previous sample ended")
        prev_start, prev_end = start, (end if _int(end) else None)
    return problems


def so02_observed_prerequisites(samples: Sequence[Mapping[str, Any]]) -> Dict[str, bool]:
    """SO-02 record prerequisites, recomputed from every sample's observed fields."""

    items = list(samples)
    counts = {t: 0 for t in SO02_LAB_SOURCE_TYPES}
    for s in items:
        if s.get("source_type") in counts:
            counts[s["source_type"]] += 1
    return {
        "every_injection_from_healthy_baseline": bool(items) and all(so02_baseline_observed(s) for s in items),
        "every_lab_source_type_sampled": bool(items)
        and all(s.get("source_type") in counts for s in items)
        and all(n >= SO02_PER_SOURCE_TYPE_SAMPLES for n in counts.values()),
    }


def _so07_observed_prerequisites(samples: Sequence[Mapping[str, Any]]) -> Dict[str, bool]:
    """SO-07 coverage, recomputed from the samples against the code's record kinds."""

    from azazel_edge.audit.logger import VALID_KINDS

    clean = {
        (s.get("record_kind"), s.get("injection_point"), s.get("record_pad_bytes"))
        for s in samples
        if so07_sample_violations(s) >= 0
    }
    wanted = {(k, p, pad) for k in VALID_KINDS for p in SO07_INJECTION_POINTS for pad in SO07_RECORD_PADS}
    after_report = sum(
        int(s.get("reported_complete") or 0)
        for s in samples
        if s.get("injection_point") == "after_report" and so07_sample_violations(s) >= 0
    )
    return {
        "every_record_kind_at_every_injection_point": wanted <= clean,
        "kill_landed_after_a_report": after_report > 0,
    }


def _so04_observed_prerequisites(samples: Sequence[Mapping[str, Any]]) -> Dict[str, bool]:
    """SO-04 start-record ordering, recomputed from the samples.

    Every sample must show its start record in the chain when its outcome
    appeared. A sample whose outcome was never seen did not show the order.
    """

    return {
        "rollback_start_recorded_before_outcome": bool(samples)
        and all(s.get("start_record_before_outcome") is True for s in samples),
    }


# release.rs WALL_ATTRIBUTION_TOLERANCE_NS: both deadlines passed, and the wall
# one passed more than this much earlier, means the wall deadline fired.
SO04_WALL_ATTRIBUTION_TOLERANCE_NS = 50_000_000


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def so04_expired_on_monotonic_deadline(sample: Mapping[str, Any]) -> bool:
    """SO-04: this lease expired on its monotonic deadline, and the sample's
    start is that deadline, on the clock the end was read on.

    Recomputed from the observed fields, never from ``expiry_clock`` alone:
    the core's own start stamp on ``CLOCK_BOOTTIME`` lies at or after the
    lease's monotonic deadline and no later than the harness saw the record,
    the boot the deadline belongs to is the boot the record was written in,
    and the wall deadline did not pass materially earlier (a wall clock
    stepped forward would have expired the lease first).
    """

    start, end = sample.get("start_monotonic_ns"), sample.get("end_monotonic_ns")
    due_boot = sample.get("lease_due_boottime_ns")
    edge_boot = sample.get("edge_recorded_start_boottime_ns")
    edge_wall = sample.get("edge_recorded_start_wall_epoch_ns")
    due_epoch = sample.get("due_epoch")
    if not all(_int(v) for v in (start, end, due_boot, edge_boot, edge_wall)):
        return False
    if not isinstance(due_epoch, (int, float)) or isinstance(due_epoch, bool) or not (0 <= due_epoch < 1e12):
        return False
    boot = sample.get("lease_boot_id")
    if not (isinstance(boot, str) and boot and sample.get("start_record_boot_id") == boot):
        return False
    if sample.get("sample_clock") != "CLOCK_BOOTTIME" or sample.get("expiry_clock") != "monotonic":
        return False
    if start != due_boot or not (due_boot <= edge_boot <= end):
        return False
    wall_overshoot = edge_wall - round(due_epoch * 1e9)
    return wall_overshoot <= (edge_boot - due_boot) + SO04_WALL_ATTRIBUTION_TOLERANCE_NS


def so04_monotonic_expiry_observed(samples: Sequence[Mapping[str, Any]]) -> bool:
    """Every SO-04 sample expired on its monotonic deadline (see above)."""

    items = list(samples)
    return bool(items) and all(isinstance(s, dict) and so04_expired_on_monotonic_deadline(s) for s in items)


# The recomputation that lets a record leave out a gap listed under
# ``gaps_closed_by_samples``. A gap with no entry here can never be left out.
GAP_CLOSERS = {
    "SO04-LEASE-EXPIRY-ON-WALL-CLOCK": so04_monotonic_expiry_observed,
    "SO03-NO-VISUAL-VOICE-QUEUE": so03_visual_voice_queue_observed,
    "SO03-NO-P0-ALERT-PATH": so03_p0_alert_path_observed,
}


def _so04_completion_observed_prerequisites(
    samples: Sequence[Mapping[str, Any]], declaration: Mapping[str, Any]
) -> Dict[str, bool]:
    """SO-04 completion prerequisites, recomputed from the declaration file and the samples.

    Every declared action type must have a valid bound in the file, and every
    sample's action type too; every lease's owned state must have been read back
    before the core started; and every completion the core reported must be
    confirmed absent by the harness's own readback.
    """

    from .declarations import ROLLBACK_ACTION_TYPES

    bounds = declaration.get("bounds_ms") or {}
    items = list(samples)
    return {
        "per_action_completion_bound_declared": all(a in bounds for a in ROLLBACK_ACTION_TYPES)
        and all(s.get("action_type") in bounds for s in items),
        "owned_state_installed_before_expiry": bool(items) and all(s.get("owned_state_installed") is True for s in items),
        "completion_confirmed_by_readback": bool(items)
        and all(s.get("owned_state_absent_after_run") is True for s in items if s.get("end_monotonic_ns") is not None),
    }


def _validate_sample_ids(samples: Sequence[Any], where: str, errors: List[str]) -> None:
    seen: Dict[str, int] = {}
    for sidx, sample in enumerate(samples):
        sid = sample.get("sample_id") if isinstance(sample, dict) else None
        if not isinstance(sid, str) or not sid:
            continue
        if sid in seen:
            errors.append(f"{where}.samples[{sidx}]: duplicate sample_id {sid!r} (first at samples[{seen[sid]}])")
        else:
            seen[sid] = sidx


def _validate_crash_part(part: Mapping[str, Any], where: str, errors: List[str]) -> str:
    for p in part.get("prerequisites", []):
        if isinstance(p, dict) and p.get("id") != CRASH_PREREQUISITE:
            errors.append(f"{where}: prerequisite {p.get('id')!r} is not one a crash part carries")
    unmet = [p for p in part.get("prerequisites", []) if isinstance(p, dict) and p.get("id") == CRASH_PREREQUISITE and p.get("met") is False]
    _require(bool(unmet), f"{where}: a crash part must carry the unmet harness_completed prerequisite", errors)
    _require(part.get("verdict") == VERDICT_NOT_MEASURABLE, f"{where}: a crash part is always not_measurable", errors)
    _require(not part.get("samples"), f"{where}: a crash part carries no samples", errors)
    return VERDICT_NOT_MEASURABLE


def validate_record(record: Any, *, expect_commit: Optional[str] = None) -> List[str]:
    """Return every problem found. An empty list means the record is valid.

    ``expect_commit``, when given, is the commit the caller knows was measured
    (CI passes ``$GITHUB_SHA``); a record naming any other commit is rejected.

    The record is checked against ``OBJECTIVE_SPECS``, not against itself: the
    rule kind, bound, sample count, part names, and mandatory prerequisite and
    gap ids are fixed per objective. Omitting a mandatory prerequisite or gap
    invalidates the record, and for the verdict it counts as unmet / present,
    so leaving something out can only make the verdict worse. For SO-07 the violations
    and coverage, and for SO-04 the start-record ordering, are recomputed from
    each sample's observed fields. A gap under ``gaps_closed_by_samples`` may
    be left out only when its ``GAP_CLOSERS`` recomputation holds for every
    sample.
    """

    errors: List[str] = []
    if not isinstance(record, dict):
        return ["record is not an object"]
    for key, typ in _TOP_KEYS.items():
        if not isinstance(record.get(key), typ):
            errors.append(f"{key}: missing or not {typ.__name__}")
    if "notes" in record and not (isinstance(record["notes"], list) and all(isinstance(n, str) for n in record["notes"])):
        errors.append("notes: not a list of strings")
    _reject_unknown_fields(record, RECORD_FIELDS, "record", errors)
    if errors:
        return errors
    _require(record["schema"] == RECORD_SCHEMA, "schema: unexpected value", errors)
    _require(record["verdict"] in VERDICTS, "verdict: not one of pass/fail/not_measurable", errors)
    objective = record["objective_id"]
    if objective not in OBJECTIVE_SPECS:
        errors.append("objective_id: unknown objective")
        return errors
    specs = OBJECTIVE_SPECS[objective]
    owner = record["owner"]
    _require(owner.get("repository") == OWNING_REPOSITORY, "owner.repository: must be the owning repository", errors)
    _require(isinstance(owner.get("commit"), str), "owner.commit: missing", errors)
    if expect_commit is not None:
        _require(
            owner.get("commit") == expect_commit,
            f"owner.commit: record names {owner.get('commit')!r}, expected {expect_commit!r}",
            errors,
        )
    _require(isinstance(record["run"].get("run_id"), str) and bool(record["run"].get("run_id")), "run.run_id: missing", errors)
    _require(bool(record["clock"].get("name")), "clock.name: missing", errors)
    parts = record["parts"]
    _require(bool(parts), "parts: a record must evaluate at least one part", errors)

    names = [p.get("name") for p in parts if isinstance(p, dict)]
    crashed = names == [CRASH_PART]
    if not crashed:
        _require(
            sorted(n for n in names if isinstance(n, str)) == sorted(specs) and len(names) == len(parts),
            f"parts: {objective} must evaluate exactly {sorted(specs)}, got {names}",
            errors,
        )

    derived_parts: List[str] = []
    for idx, part in enumerate(parts):
        where = f"parts[{idx}]"
        if not isinstance(part, dict):
            errors.append(f"{where}: not an object")
            continue
        for key, typ in (("name", str), ("sample_rule", dict), ("samples", list), ("pass_rule", dict), ("prerequisites", list), ("gaps", list), ("verdict", str)):
            if not isinstance(part.get(key), typ):
                errors.append(f"{where}.{key}: missing or not {typ.__name__}")
        if any(e.startswith(where + ".") for e in errors):
            continue
        _reject_unknown_fields(part, PART_FIELDS, where, errors)
        _validate_sample_ids(part["samples"], where, errors)
        if crashed:
            derived_parts.append(_validate_crash_part(part, where, errors))
            continue
        spec = specs.get(part["name"])
        if spec is None:
            continue
        rule = part["pass_rule"]
        if rule.get("kind") != spec["kind"]:
            errors.append(f"{where}.pass_rule.kind: {objective} requires {spec['kind']!r}")
            continue
        if spec["bound_ms"] is not None and rule.get("bound_ms") != spec["bound_ms"]:
            errors.append(f"{where}.pass_rule.bound_ms: {objective} requires {spec['bound_ms']}, record declares {rule.get('bound_ms')!r}")
        declaration: Dict[str, Any] = {}
        if spec["kind"] == RULE_EVERY_SAMPLE_MAX_PER_ACTION:
            # The bounds are the declaration file's as it stands in this tree,
            # never the record's. A record taken against another version of the
            # file is rejected rather than re-judged.
            from .declarations import load_rollback_completion_bounds

            declaration = load_rollback_completion_bounds()
            if rule.get("bounds_ms") != declaration["bounds_ms"]:
                errors.append(f"{where}.pass_rule.bounds_ms: the declaration gives {declaration['bounds_ms']}, record declares {rule.get('bounds_ms')!r}")
            if rule.get("declaration") != declaration["path"] or rule.get("declaration_sha256") != declaration["sha256"]:
                errors.append(f"{where}.pass_rule.declaration: record does not cite {declaration['path']} at sha256 {declaration['sha256']}")
        if spec.get("row_class") is not None:
            config = record["product_configuration"]
            if config.get("row_class") != spec["row_class"]:
                errors.append(f"product_configuration.row_class: {objective} is measured as {spec['row_class']!r}, record declares {config.get('row_class')!r}")
            if config.get("hardware_evidence") is not False:
                errors.append(f"product_configuration.hardware_evidence: a {spec['row_class']} record must declare false; it never gates a hardware-only variant")
        if part["sample_rule"].get("per_action_required", 0) != spec.get("per_action_samples", 0):
            errors.append(
                f"{where}.sample_rule.per_action_required: {objective} requires {spec.get('per_action_samples', 0)}, "
                f"record declares {part['sample_rule'].get('per_action_required')!r}"
            )
        required = part["sample_rule"].get("required_samples")
        if required != spec["required_samples"]:
            errors.append(f"{where}.sample_rule.required_samples: {objective} requires {spec['required_samples']}, record declares {required!r}")

        declared_prereqs = []
        for p in part["prerequisites"]:
            if isinstance(p, dict) and isinstance(p.get("id"), str) and isinstance(p.get("met"), bool):
                declared_prereqs.append(p)
            else:
                errors.append(f"{where}: malformed prerequisite")
        declared_gaps = []
        for g in part["gaps"]:
            if isinstance(g, dict) and isinstance(g.get("id"), str):
                declared_gaps.append(g)
                if g.get("blocks_verdict") is not True:
                    errors.append(f"{where}: gap {g.get('id')!r} declared non-blocking; every gap blocks the verdict")
            else:
                errors.append(f"{where}: malformed gap")
        allowed_prereqs = set(spec["prerequisites"]) | {DOWNGRADE_PREREQUISITE}
        for p in declared_prereqs:
            if p["id"] not in allowed_prereqs:
                errors.append(f"{where}: prerequisite {p['id']!r} is not in the {objective} definition")
        sample_fields = SAMPLE_FIELDS.get(objective, _COMMON_SAMPLE_FIELDS)
        for sidx, sample in enumerate(part["samples"]):
            _validate_sample(sample, f"{where}.samples[{sidx}]", errors, sample_fields)

        # Effective prerequisites: what the record declares, with every
        # mandatory one it omits counted as unmet, and (for SO-07) the
        # observable ones replaced by what the samples show.
        effective_prereqs = [dict(p) for p in declared_prereqs]
        have = {p["id"] for p in declared_prereqs}
        for pid in spec["prerequisites"]:
            if pid not in have:
                errors.append(f"{where}: mandatory prerequisite {pid!r} omitted")
                effective_prereqs.append({"id": pid, "met": False})
        effective_gaps = [{"id": g["id"], "blocks_verdict": True} for g in declared_gaps]
        have_gaps = {g["id"] for g in declared_gaps}
        dict_samples = [s for s in part["samples"] if isinstance(s, dict)]
        closed_gaps = {
            gid
            for gid in spec.get("gaps_closed_by_samples", ())
            if gid in GAP_CLOSERS and len(dict_samples) == len(part["samples"]) and GAP_CLOSERS[gid](dict_samples)
        }
        for gid in spec["gaps"]:
            if gid not in have_gaps and gid not in closed_gaps:
                errors.append(f"{where}: mandatory gap {gid!r} omitted")
                effective_gaps.append({"id": gid, "blocks_verdict": True})
        if objective == "SO-03" and part["name"] == "decision_durable_to_alert_enqueued":
            # The record prerequisites are what the samples show, never what
            # the record declares.
            so03_observed = so03_observed_prerequisites([s for s in part["samples"] if isinstance(s, dict)])
            for p in effective_prereqs:
                if p["id"] in so03_observed:
                    if p["met"] and not so03_observed[p["id"]]:
                        errors.append(f"{where}: prerequisite {p['id']!r} declared met but the samples do not show it")
                    p["met"] = bool(p["met"]) and so03_observed[p["id"]]

        if objective == "SO-03" and part["name"] == "decision_durable_to_alert_enqueued":
            so03_ends = [isinstance(sm, dict) and so03_end_observed(sm) for sm in part["samples"]]
        else:
            so03_ends = None

        if spec["kind"] == RULE_ZERO_VIOLATIONS:
            for sidx, sample in enumerate(part["samples"]):
                if isinstance(sample, dict) and sample.get("violations") != so07_sample_violations(sample):
                    errors.append(
                        f"{where}.samples[{sidx}].violations: declares {sample.get('violations')!r}, "
                        f"observed fields give {so07_sample_violations(sample)}"
                    )
            eval_samples = [{"violations": so07_sample_violations(s) if isinstance(s, dict) else -1} for s in part["samples"]]
            if objective == "SO-07":
                observed = _so07_observed_prerequisites([s for s in part["samples"] if isinstance(s, dict)])
                for p in effective_prereqs:
                    if p["id"] in observed:
                        if p["met"] and not observed[p["id"]]:
                            errors.append(f"{where}: prerequisite {p['id']!r} declared met but the samples do not show it")
                        p["met"] = bool(p["met"]) and observed[p["id"]]
        else:
            eval_samples = _recomputed_latency_samples([s if isinstance(s, dict) else {} for s in part["samples"]])
            if objective == "SO-02" and part["name"] == "source_failure_visible":
                errors.extend(f"{where}.{p}" for p in so02_sequence_problems(part["samples"]))
                # An end counts only where the sample's own fields show the
                # surface naming the source failed after a healthy baseline;
                # otherwise the sample never ended, whatever its timestamps say.
                for sidx, sample in enumerate(part["samples"]):
                    observed_end = isinstance(sample, dict) and so02_failure_observed(sample)
                    if not observed_end:
                        if isinstance(sample, dict) and sample.get("end_monotonic_ns") is not None:
                            errors.append(f"{where}.samples[{sidx}]: end given but the observed fields do not show the surface naming the source failed")
                        eval_samples[sidx]["elapsed_ms"] = None
                observed = so02_observed_prerequisites([s for s in part["samples"] if isinstance(s, dict)])
                for p in effective_prereqs:
                    if p["id"] in observed:
                        if p["met"] and not observed[p["id"]]:
                            errors.append(f"{where}: prerequisite {p['id']!r} declared met but the samples do not show it")
                        p["met"] = bool(p["met"]) and observed[p["id"]]
            if so03_ends is not None:
                # The end is the queue's durable enqueue record for the
                # decision, recomputed; a sample without one never ended.
                for sidx, ended in enumerate(so03_ends):
                    if not ended:
                        sample = part["samples"][sidx]
                        if isinstance(sample, dict) and sample.get("end_monotonic_ns") is not None:
                            errors.append(f"{where}.samples[{sidx}]: end given but the observed fields do not show a durable enqueue record for the decision")
                        eval_samples[sidx]["elapsed_ms"] = None
            if objective == "SO-04" and part["name"] in ("rollback_start_after_expiry", "rollback_completion"):
                dict_samples = [s for s in part["samples"] if isinstance(s, dict)]
                if part["name"] == "rollback_start_after_expiry":
                    observed = _so04_observed_prerequisites(dict_samples)
                else:
                    observed = _so04_completion_observed_prerequisites(dict_samples, declaration)
                for p in effective_prereqs:
                    if p["id"] in observed:
                        if p["met"] and not observed[p["id"]]:
                            errors.append(f"{where}: prerequisite {p['id']!r} declared met but the samples do not show it")
                        p["met"] = bool(p["met"]) and observed[p["id"]]

        if spec["kind"] == RULE_EVERY_SAMPLE_MAX_PER_ACTION:
            authoritative = dict(rule, bounds_ms=declaration.get("bounds_ms") or {})
        else:
            authoritative = dict(rule, bound_ms=spec["bound_ms"])
        evaluated = evaluate_rule(authoritative, eval_samples) if eval_samples else {"holds": False}
        claimed = rule.get("evaluated")
        if not isinstance(claimed, dict) or bool(claimed.get("holds")) != bool(evaluated.get("holds")):
            errors.append(f"{where}.pass_rule.evaluated: disagrees with the samples")
        derived = derive_verdict(
            prerequisites=effective_prereqs,
            gaps=effective_gaps,
            required_samples=spec["required_samples"],
            samples=eval_samples,
            evaluated=evaluated,
            per_action_required=spec.get("per_action_samples", 0),
        )
        if part["verdict"] != derived:
            errors.append(f"{where}.verdict: claims {part['verdict']!r} but the record supports {derived!r}")
        derived_parts.append(derived)

    if derived_parts and len(derived_parts) == len(parts):
        top = worst_verdict(derived_parts)
        if record["verdict"] != top:
            errors.append(f"verdict: claims {record['verdict']!r} but parts support {top!r}")
    if record["verdict"] == VERDICT_PASS:
        _require(bool(owner.get("commit")), "owner.commit: a pass must name the commit measured", errors)
        _require(owner.get("worktree_clean") is True, "owner.worktree_clean: a pass must be taken on an unmodified tree", errors)
        _require(record["evidence_class"] == "gate", "evidence_class: a pass is gate evidence", errors)
    if record["verdict"] == VERDICT_NOT_MEASURABLE:
        _require(record["evidence_class"] == "diagnostic_only", "evidence_class: not_measurable is never gate evidence", errors)
    return errors


def load_and_validate(path: Path, *, expect_commit: Optional[str] = None) -> List[str]:
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"unreadable record: {exc}"]
    return validate_record(record, expect_commit=expect_commit)
