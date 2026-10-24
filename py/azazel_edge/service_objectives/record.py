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
RULE_KINDS = (RULE_EVERY_SAMPLE_MAX, RULE_ZERO_VIOLATIONS)

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

OBJECTIVE_SPECS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "SO-03": {
        "decision_durable_to_alert_enqueued": {
            "kind": "every_sample_max_elapsed",
            "bound_ms": 2000.0,
            "required_samples": 200,
            "prerequisites": (
                "visual_voice_delivery_queue_declared",
                "enqueue_record_names_decision_id",
                "synthetic_decisions_are_p0_stand_ins",
            ),
            "gaps": (
                "SO03-NO-VISUAL-VOICE-QUEUE",
                "SO03-ENQUEUE-RECORD-LACKS-DECISION-ID",
                "SO03-NO-P0-CLASS-OR-PATH",
            ),
        },
    },
    "SO-04": {
        "rollback_start_after_expiry": {
            "kind": "every_sample_max_elapsed",
            "bound_ms": 5000.0,
            "required_samples": 150,
            "prerequisites": (
                "core_binary_present",
                "core_daemon_started",
                "wall_clock_stable_during_run",
                "no_release_record_before_expiry",
                "load_phase_applied",
            ),
            "gaps": (
                "SO04-END-RECORD-NOT-AUDIT-CHAIN",
                "SO04-LEASE-EXPIRY-ON-WALL-CLOCK",
                "SO04-HOSTILE-LOAD-UNDECLARED",
            ),
        },
        "rollback_completion": {
            "kind": "every_sample_max_elapsed",
            "bound_ms": 0.0,
            "required_samples": 150,
            "prerequisites": ("per_action_completion_bound_declared",),
            "gaps": ("OF-05",),
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
    "SO-03": frozenset(
        _COMMON_SAMPLE_FIELDS
        + ("action", "reason", "level", "enqueue_record_names_decision", "notification_audit_names_decision")
    ),
    "SO-04": frozenset(
        _COMMON_SAMPLE_FIELDS
        + (
            "action_type", "condition", "due_epoch", "attempted_at_epoch",
            "edge_reported_start_after_expiry_ms", "release_status", "release_result",
            "observed_before_expiry",
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
    raise ValueError(f"unknown pass rule kind: {kind!r}")


def derive_verdict(
    *,
    prerequisites: Sequence[Mapping[str, Any]],
    gaps: Sequence[Mapping[str, Any]],
    required_samples: int,
    samples: Sequence[Mapping[str, Any]],
    evaluated: Mapping[str, Any],
) -> str:
    if any(not p.get("met") for p in prerequisites):
        return VERDICT_NOT_MEASURABLE
    if gaps:
        return VERDICT_NOT_MEASURABLE
    if len(samples) < int(required_samples) or not samples:
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
    )
    return {
        "name": name,
        "sample_rule": {"required_samples": int(required_samples)},
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
        out.append({"elapsed_ms": (end - start) / 1e6 if ok else None})
    return out


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
    and coverage are recomputed from each sample's observed fields.
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
        for gid in spec["gaps"]:
            if gid not in have_gaps:
                errors.append(f"{where}: mandatory gap {gid!r} omitted")
                effective_gaps.append({"id": gid, "blocks_verdict": True})

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

        evaluated = evaluate_rule(dict(rule, bound_ms=spec["bound_ms"]), eval_samples) if eval_samples else {"holds": False}
        claimed = rule.get("evaluated")
        if not isinstance(claimed, dict) or bool(claimed.get("holds")) != bool(evaluated.get("holds")):
            errors.append(f"{where}.pass_rule.evaluated: disagrees with the samples")
        derived = derive_verdict(
            prerequisites=effective_prereqs,
            gaps=effective_gaps,
            required_samples=spec["required_samples"],
            samples=eval_samples,
            evaluated=evaluated,
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
