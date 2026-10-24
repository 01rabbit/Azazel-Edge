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

KNOWN_OBJECTIVES = ("SO-03", "SO-04", "SO-07")

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


def gap(gid: str, summary: str, *, blocks_verdict: bool = True, refs: Sequence[str] = ()) -> Dict[str, Any]:
    return {"id": gid, "summary": str(summary), "blocks_verdict": bool(blocks_verdict), "refs": list(refs)}


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
    if any(g.get("blocks_verdict") for g in gaps):
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
                    "owner_commit_identified",
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


def _validate_sample(sample: Any, where: str, errors: List[str]) -> None:
    if not isinstance(sample, dict):
        errors.append(f"{where}: sample is not an object")
        return
    _require(isinstance(sample.get("sample_id"), str) and bool(sample.get("sample_id")), f"{where}: sample_id missing", errors)
    start = sample.get("start_monotonic_ns")
    end = sample.get("end_monotonic_ns")
    _require(isinstance(start, int), f"{where}: start_monotonic_ns must be an integer", errors)
    _require(end is None or isinstance(end, int), f"{where}: end_monotonic_ns must be an integer or null", errors)
    if isinstance(start, int) and isinstance(end, int):
        _require(end >= start, f"{where}: end precedes start", errors)
        elapsed = sample.get("elapsed_ms")
        if elapsed is not None:
            _require(
                isinstance(elapsed, (int, float)) and abs(float(elapsed) - (end - start) / 1e6) < 0.01,
                f"{where}: elapsed_ms disagrees with start/end",
                errors,
            )


def validate_record(record: Any) -> List[str]:
    """Return every problem found. An empty list means the record is valid."""

    errors: List[str] = []
    if not isinstance(record, dict):
        return ["record is not an object"]
    for key, typ in _TOP_KEYS.items():
        if not isinstance(record.get(key), typ):
            errors.append(f"{key}: missing or not {typ.__name__}")
    if errors:
        return errors
    _require(record["schema"] == RECORD_SCHEMA, "schema: unexpected value", errors)
    _require(record["objective_id"] in KNOWN_OBJECTIVES, "objective_id: unknown objective", errors)
    _require(record["verdict"] in VERDICTS, "verdict: not one of pass/fail/not_measurable", errors)
    owner = record["owner"]
    _require(owner.get("repository") == OWNING_REPOSITORY, "owner.repository: must be the owning repository", errors)
    _require(isinstance(owner.get("commit"), str), "owner.commit: missing", errors)
    _require(isinstance(record["run"].get("run_id"), str) and bool(record["run"].get("run_id")), "run.run_id: missing", errors)
    _require(bool(record["clock"].get("name")), "clock.name: missing", errors)
    parts = record["parts"]
    _require(bool(parts), "parts: a record must evaluate at least one part", errors)

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
        rule = part["pass_rule"]
        if rule.get("kind") not in RULE_KINDS:
            errors.append(f"{where}.pass_rule.kind: unknown")
            continue
        if rule["kind"] == RULE_EVERY_SAMPLE_MAX and not isinstance(rule.get("bound_ms"), (int, float)):
            errors.append(f"{where}.pass_rule.bound_ms: missing")
            continue
        for p in part["prerequisites"]:
            _require(isinstance(p, dict) and isinstance(p.get("id"), str) and isinstance(p.get("met"), bool), f"{where}: malformed prerequisite", errors)
        for g in part["gaps"]:
            _require(isinstance(g, dict) and isinstance(g.get("id"), str) and isinstance(g.get("blocks_verdict"), bool), f"{where}: malformed gap", errors)
        for sidx, sample in enumerate(part["samples"]):
            _validate_sample(sample, f"{where}.samples[{sidx}]", errors)
        required = part["sample_rule"].get("required_samples")
        if not isinstance(required, int) or required < 1:
            errors.append(f"{where}.sample_rule.required_samples: must be a positive integer")
            continue
        try:
            evaluated = evaluate_rule(rule, part["samples"]) if part["samples"] else {"holds": False}
        except Exception as exc:  # malformed rule parameters
            errors.append(f"{where}.pass_rule: cannot be evaluated ({exc})")
            continue
        claimed = rule.get("evaluated")
        if not isinstance(claimed, dict) or bool(claimed.get("holds")) != bool(evaluated.get("holds")):
            errors.append(f"{where}.pass_rule.evaluated: disagrees with the samples")
        derived = derive_verdict(
            prerequisites=part["prerequisites"],
            gaps=part["gaps"],
            required_samples=required,
            samples=part["samples"],
            evaluated=evaluated,
        )
        if part["verdict"] != derived:
            errors.append(f"{where}.verdict: claims {part['verdict']!r} but the record supports {derived!r}")
        if part["verdict"] == VERDICT_NOT_MEASURABLE:
            reasons = [p for p in part["prerequisites"] if not p.get("met")] + [g for g in part["gaps"] if g.get("blocks_verdict")]
            if not reasons and len(part["samples"]) >= required:
                errors.append(f"{where}: not_measurable without an unmet prerequisite, blocking gap, or sample shortfall")
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


def load_and_validate(path: Path) -> List[str]:
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"unreadable record: {exc}"]
    return validate_record(record)
