"""Edge's declarations that service-objective rows cite (Edge#414).

A declaration is a value a row's definition presumes exists but that the
assignment leaves to Edge, such as SO-04's "action-specific" rollback
completion bound (OF-05). It lives in a file under ``config/service_objectives``
so the harness and the validator read the same thing, and a change to it shows
up as a change to the measured tree.

Reading a declaration is all this module does. It decides nothing at run time:
the core never reads these files, and no bound here changes when or how a lease
is released. An entry that is missing, malformed or carries an unknown status is
treated as not declared, so a missing declaration can only make a verdict worse.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
DECLARATIONS_DIR = REPO_ROOT / "config" / "service_objectives"

ROLLBACK_COMPLETION_BOUNDS_PATH = DECLARATIONS_DIR / "rollback_completion_bounds.json"
ROLLBACK_COMPLETION_BOUNDS_SCHEMA = "azazel-edge/rollback-completion-bounds/v1"
# The action types Edge holds a lease for: the only ones the core's
# ``build_release_task`` accepts. SO-04 samples each of them.
ROLLBACK_ACTION_TYPES = ("throttle", "isolate", "redirect")
# The only status an entry may carry today. A provisional bound is derived from
# a container run, not from hardware, and the SO-04 completion part keeps a
# blocking gap for it (SO04-COMPLETION-BOUND-PROVISIONAL).
PROVISIONAL = "provisional"
KNOWN_STATUSES = (PROVISIONAL,)
_BASIS_KEYS = ("method", "sample_count", "max_observed_ms", "margin_rule")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _entry_problems(entry: Any) -> List[str]:
    if not isinstance(entry, dict):
        return ["entry is not an object"]
    problems = []
    action = entry.get("action_type")
    if action not in ROLLBACK_ACTION_TYPES:
        problems.append(f"action_type {action!r} is not one of {list(ROLLBACK_ACTION_TYPES)}")
    bound = entry.get("bound_ms")
    if not isinstance(bound, (int, float)) or isinstance(bound, bool) or not math.isfinite(bound) or bound <= 0:
        problems.append("bound_ms must be a positive finite number")
    if entry.get("status") not in KNOWN_STATUSES:
        problems.append(f"status {entry.get('status')!r} is not one of {list(KNOWN_STATUSES)}")
    if not isinstance(entry.get("hardware_class"), str) or not entry.get("hardware_class"):
        problems.append("hardware_class missing")
    basis = entry.get("basis")
    if not isinstance(basis, dict):
        problems.append("basis missing")
    else:
        for key in _BASIS_KEYS:
            if key not in basis:
                problems.append(f"basis.{key} missing")
        count = basis.get("sample_count")
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            problems.append("basis.sample_count must be a positive integer")
        observed = basis.get("max_observed_ms")
        if isinstance(observed, (int, float)) and not isinstance(observed, bool) and isinstance(bound, (int, float)):
            if observed > bound:
                problems.append("bound_ms is below the basis's own max_observed_ms")
        elif "max_observed_ms" in basis:
            problems.append("basis.max_observed_ms must be a number")
    return problems


def load_rollback_completion_bounds(path: Optional[Path] = None) -> Dict[str, Any]:
    """The declared per-action rollback completion bounds.

    Returns ``bounds_ms`` (action type -> bound, only for valid entries),
    ``statuses`` (action type -> status), ``problems`` (why an entry or the
    file was not accepted), the file's repository-relative ``path`` and its
    ``sha256``. A file that is absent or unreadable declares nothing.
    """

    target = Path(path) if path is not None else ROLLBACK_COMPLETION_BOUNDS_PATH
    try:
        rel = str(target.resolve().relative_to(REPO_ROOT))
    except ValueError:
        rel = str(target)
    out: Dict[str, Any] = {"path": rel, "sha256": None, "bounds_ms": {}, "statuses": {}, "problems": []}
    try:
        raw = target.read_bytes()
    except OSError as exc:
        out["problems"].append(f"declaration unreadable: {exc.__class__.__name__}")
        return out
    out["sha256"] = _sha256(raw)
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        out["problems"].append(f"declaration is not JSON: {exc}")
        return out
    if not isinstance(doc, dict) or doc.get("schema") != ROLLBACK_COMPLETION_BOUNDS_SCHEMA:
        out["problems"].append(f"schema is not {ROLLBACK_COMPLETION_BOUNDS_SCHEMA}")
        return out
    entries = doc.get("bounds")
    if not isinstance(entries, list):
        out["problems"].append("bounds is not a list")
        return out
    seen: Dict[str, int] = {}
    for idx, entry in enumerate(entries):
        problems = _entry_problems(entry)
        action = entry.get("action_type") if isinstance(entry, dict) else None
        if isinstance(action, str) and action in seen:
            problems.append(f"action_type {action!r} declared twice (first at bounds[{seen[action]}])")
        if problems:
            out["problems"].append(f"bounds[{idx}]: " + "; ".join(problems))
            if isinstance(action, str) and action in out["bounds_ms"]:
                # A duplicate makes the action's bound ambiguous: declare neither.
                del out["bounds_ms"][action]
                out["statuses"].pop(action, None)
            continue
        seen[action] = idx
        out["bounds_ms"][action] = float(entry["bound_ms"])
        out["statuses"][action] = entry["status"]
    return out


def undeclared_action_types(declaration: Mapping[str, Any]) -> List[str]:
    bounds = declaration.get("bounds_ms") or {}
    return [a for a in ROLLBACK_ACTION_TYPES if a not in bounds]


# -- OF-06: the Core's ingress quota ------------------------------------------
#
# Unlike the rollback bounds above, these values are enforced: the core
# compiles the same numbers in (``IngressLimits::DECLARED`` in
# ``rust/azazel-edge-core/src/ingress.rs``) and a core unit test keeps the two
# equal. This file is how a harness learns them without reading Rust.

INGRESS_QUOTA_PATH = DECLARATIONS_DIR / "ingress_quota.json"
INGRESS_QUOTA_SCHEMA = "azazel-edge/ingress-quota/v1"
INGRESS_QUOTA_UNIT = "eve_non_alert_lines_per_second"
_INGRESS_INT_KEYS = (
    "value",
    "non_alert_burst",
    "alerts_per_poll",
    "examine_per_poll",
    "poll_work_limit_ms",
    "max_line_bytes",
    "backlog_bound_bytes",
    "alert_backlog_bound_bytes",
    "audit_interval_ms",
    "audit_log_cap_bytes",
)
_INGRESS_BASIS_KEYS = ("method", "runs", "min_observed_lines_per_s", "margin_rule")


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _ingress_entry_problems(entry: Any) -> List[str]:
    if not isinstance(entry, dict):
        return ["entry is not an object"]
    problems = []
    if not isinstance(entry.get("ingress"), str) or not entry.get("ingress"):
        problems.append("ingress missing")
    if entry.get("unit") != INGRESS_QUOTA_UNIT:
        problems.append(f"unit is not {INGRESS_QUOTA_UNIT}")
    for key in _INGRESS_INT_KEYS:
        if not _positive_int(entry.get(key)):
            problems.append(f"{key} must be a positive integer")
    if entry.get("status") not in KNOWN_STATUSES:
        problems.append(f"status {entry.get('status')!r} is not one of {list(KNOWN_STATUSES)}")
    if not isinstance(entry.get("hardware_class"), str) or not entry.get("hardware_class"):
        problems.append("hardware_class missing")
    basis = entry.get("basis")
    if not isinstance(basis, dict):
        problems.append("basis missing")
    else:
        for key in _INGRESS_BASIS_KEYS:
            if key not in basis:
                problems.append(f"basis.{key} missing")
        observed = basis.get("min_observed_lines_per_s")
        value = entry.get("value")
        if isinstance(observed, (int, float)) and not isinstance(observed, bool) and _positive_int(value):
            if value > observed:
                problems.append("value is above the basis's own min_observed_lines_per_s")
        elif "min_observed_lines_per_s" in basis:
            problems.append("basis.min_observed_lines_per_s must be a number")
    return problems


def load_ingress_quotas(path: Optional[Path] = None) -> Dict[str, Any]:
    """The declared ingress quotas (OF-06).

    Returns ``quotas`` (ingress name -> the accepted entry), ``problems``,
    ``path`` and ``sha256``. A file that is absent, unreadable or malformed
    declares nothing, so SO-11 has nothing to iterate rather than a wrong value.
    """

    target = Path(path) if path is not None else INGRESS_QUOTA_PATH
    try:
        rel = str(target.resolve().relative_to(REPO_ROOT))
    except ValueError:
        rel = str(target)
    out: Dict[str, Any] = {"path": rel, "sha256": None, "quotas": {}, "problems": []}
    try:
        raw = target.read_bytes()
    except OSError as exc:
        out["problems"].append(f"declaration unreadable: {exc.__class__.__name__}")
        return out
    out["sha256"] = _sha256(raw)
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        out["problems"].append(f"declaration is not JSON: {exc}")
        return out
    if not isinstance(doc, dict) or doc.get("schema") != INGRESS_QUOTA_SCHEMA:
        out["problems"].append(f"schema is not {INGRESS_QUOTA_SCHEMA}")
        return out
    entries = doc.get("quotas")
    if not isinstance(entries, list):
        out["problems"].append("quotas is not a list")
        return out
    seen: Dict[str, int] = {}
    for idx, entry in enumerate(entries):
        problems = _ingress_entry_problems(entry)
        name = entry.get("ingress") if isinstance(entry, dict) else None
        if isinstance(name, str) and name in seen:
            problems.append(f"ingress {name!r} declared twice (first at quotas[{seen[name]}])")
        if problems:
            out["problems"].append(f"quotas[{idx}]: " + "; ".join(problems))
            if isinstance(name, str):
                out["quotas"].pop(name, None)
            continue
        seen[name] = idx
        out["quotas"][name] = dict(entry)
    return out


# -- SO-04: the hostile-load profile, derived from the OF-06 quota -------------
#
# SO-04's sample rule asks for leases expiring under hostile load. The profile
# names that load, and every rate in it is a rule applied to the ingress quota
# above. The loader re-derives each rate from the quota file as it stands and
# refuses the profile when one differs, so the profile can never drift away
# from the quota it claims to be derived from. Like the other declarations it
# decides nothing at run time: the core never reads it.

HOSTILE_LOAD_PROFILE_PATH = DECLARATIONS_DIR / "hostile_load_profile.json"
HOSTILE_LOAD_PROFILE_SCHEMA = "azazel-edge/hostile-load-profile/v1"
# The line classes a phase may offer. ``invalid_utf8`` and ``oversized`` are
# non-alert lines the core cannot parse or will not read whole.
HOSTILE_LINE_CLASSES = ("alert", "flow", "dns", "stats", "http", "invalid_utf8", "oversized")
HOSTILE_NON_ALERT_KINDS = ("flow", "dns", "stats", "http", "invalid_utf8")
# A profile is provisional until the owner confirms its factors by changing
# the declaration in the tree: status "confirmed", and owner_defaults no longer
# pending. Only then may SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL be left out
# (record.PART_GAP_CLOSERS). There is no other way to confirm it.
CONFIRMED = "confirmed"
HOSTILE_PROFILE_STATUSES = (PROVISIONAL, CONFIRMED)
_HOSTILE_MS_KEYS = ("core_default_poll_ms", "line_bytes", "warmup_ms", "hold_after_ms", "quiet_gap_ms", "audit_attribution_slack_ms")


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def derived_phase_rates(phase: Mapping[str, Any], quota: Mapping[str, Any], poll_ms: int) -> Dict[str, Any]:
    """The rates and oversized line size the profile's rules give for one phase.

    Pure: the same arithmetic the profile's ``rules`` state, applied to the
    quota entry. Raises ``ValueError`` when the phase's factors cannot give a
    rate (a non-whole per-kind share, an oversized line not over the limit).
    """

    kinds = list(phase.get("non_alert_kinds") or [])
    factor = phase.get("non_alert_factor")
    fill = phase.get("alert_poll_fill")
    o_factor = phase.get("oversized_line_factor")
    o_share = phase.get("oversized_backlog_share")
    for name, value in (("non_alert_factor", factor), ("alert_poll_fill", fill), ("oversized_line_factor", o_factor), ("oversized_backlog_share", o_share)):
        if not _number(value) or value < 0:
            raise ValueError(f"{name} must be a non-negative number")
    if any(k not in HOSTILE_NON_ALERT_KINDS for k in kinds) or len(set(kinds)) != len(kinds):
        raise ValueError(f"non_alert_kinds must be distinct members of {list(HOSTILE_NON_ALERT_KINDS)}")
    non_alert_total = round(quota["value"] * factor)
    if non_alert_total and not kinds:
        raise ValueError("a non-alert rate needs non_alert_kinds")
    if kinds and non_alert_total % len(kinds):
        raise ValueError(f"{non_alert_total} non-alert lines/s do not split equally over {len(kinds)} kinds")
    rates: Dict[str, Any] = {c: 0 for c in HOSTILE_LINE_CLASSES}
    for k in kinds:
        rates[k] = non_alert_total // len(kinds)
    rates["alert"] = round(fill * quota["alerts_per_poll"] * 1000 / poll_ms)
    oversized_bytes = 0
    if o_factor or o_share:
        oversized_bytes = round(o_factor * quota["max_line_bytes"])
        if oversized_bytes <= quota["max_line_bytes"]:
            raise ValueError("an oversized line must be longer than max_line_bytes")
        rates["oversized"] = o_share * quota["backlog_bound_bytes"] / oversized_bytes
        if rates["oversized"] <= 0:
            raise ValueError("oversized_backlog_share gives no oversized lines")
    burst = phase.get("burst_interval_ms", 0)
    if not isinstance(burst, int) or isinstance(burst, bool) or burst < 0:
        raise ValueError("burst_interval_ms must be a non-negative integer")
    return {
        "rates_per_s": rates,
        "non_alert_lines_per_s": non_alert_total,
        "oversized_line_bytes": oversized_bytes,
        "burst_interval_ms": burst,
    }


# The factors a phase declares; an owner's confirmation names these values.
HOSTILE_PHASE_FACTORS = ("non_alert_factor", "alert_poll_fill", "oversized_line_factor", "oversized_backlog_share", "burst_interval_ms")


def phase_factors(phases: Any) -> Dict[str, Dict[str, Any]]:
    return {
        ph.get("name"): {k: ph.get(k, 0 if k == "burst_interval_ms" else None) for k in HOSTILE_PHASE_FACTORS}
        for ph in (phases if isinstance(phases, list) else [])
        if isinstance(ph, dict)
    }


def burst_backlog_bytes(derived: Mapping[str, Any], line_bytes: int) -> float:
    """Unread non-alert bytes one burst puts in front of the core (0 when written continuously)."""

    if not derived.get("burst_interval_ms"):
        return 0.0
    return derived["non_alert_lines_per_s"] * derived["burst_interval_ms"] / 1000.0 * line_bytes


def _hostile_phase_problems(phase: Any, quota: Mapping[str, Any], poll_ms: int) -> List[str]:
    if not isinstance(phase, dict):
        return ["phase is not an object"]
    problems = []
    if not isinstance(phase.get("name"), str) or not phase.get("name") or phase.get("name") == "nominal":
        problems.append("name missing (or 'nominal', which is the unloaded condition)")
    try:
        derived = derived_phase_rates(phase, quota, poll_ms)
    except (ValueError, KeyError, TypeError) as exc:
        return problems + [str(exc)]
    declared = phase.get("rates_per_s")
    if not isinstance(declared, dict) or set(declared) != set(HOSTILE_LINE_CLASSES):
        problems.append(f"rates_per_s must name exactly {list(HOSTILE_LINE_CLASSES)}")
    else:
        for cls in HOSTILE_LINE_CLASSES:
            want, have = derived["rates_per_s"][cls], declared[cls]
            if not _number(have) or abs(have - want) > 1e-9:
                problems.append(f"rates_per_s.{cls} is {have!r}; the rules give {want!r} from the quota")
    if phase.get("oversized_line_bytes") != derived["oversized_line_bytes"]:
        problems.append(f"oversized_line_bytes is {phase.get('oversized_line_bytes')!r}; the rules give {derived['oversized_line_bytes']}")
    if not any(derived["rates_per_s"].values()):
        problems.append("the phase offers no load")
    return problems


def load_hostile_load_profile(path: Optional[Path] = None, *, quota_path: Optional[Path] = None) -> Dict[str, Any]:
    """The declared SO-04 hostile-load profile, re-derived from the ingress quota.

    Returns ``phases`` (only when the whole profile is valid: every phase's
    rates re-derived from the quota, and the three kinds of hostile load SO-04
    needs all present), ``problems``, ``path``/``sha256`` of the profile,
    ``quota_path``/``quota_sha256`` of the quota it was checked against,
    ``quota`` (the quota entry) and the timing keys. A profile with any problem
    declares nothing, so it can never close a gap.
    """

    target = Path(path) if path is not None else HOSTILE_LOAD_PROFILE_PATH
    try:
        rel = str(target.resolve().relative_to(REPO_ROOT))
    except ValueError:
        rel = str(target)
    quota_decl = load_ingress_quotas(quota_path)
    out: Dict[str, Any] = {
        "path": rel,
        "sha256": None,
        "quota_path": quota_decl["path"],
        "quota_sha256": quota_decl["sha256"],
        "quota": None,
        "phases": [],
        "problems": [],
    }
    try:
        raw = target.read_bytes()
    except OSError as exc:
        out["problems"].append(f"declaration unreadable: {exc.__class__.__name__}")
        return out
    out["sha256"] = _sha256(raw)
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        out["problems"].append(f"declaration is not JSON: {exc}")
        return out
    if not isinstance(doc, dict) or doc.get("schema") != HOSTILE_LOAD_PROFILE_SCHEMA:
        out["problems"].append(f"schema is not {HOSTILE_LOAD_PROFILE_SCHEMA}")
        return out
    problems: List[str] = []
    if doc.get("status") not in HOSTILE_PROFILE_STATUSES:
        problems.append(f"status {doc.get('status')!r} is not one of {list(HOSTILE_PROFILE_STATUSES)}")
    owner = doc.get("owner_defaults")
    if doc.get("status") == CONFIRMED:
        # Confirmed only explicitly, and only for the values confirmed.
        if not isinstance(owner, dict) or owner.get("status") != CONFIRMED:
            problems.append("status is confirmed but owner_defaults.status is not exactly 'confirmed'")
        elif owner.get("confirmed_phase_factors") != phase_factors(doc.get("phases")):
            problems.append("owner_defaults.confirmed_phase_factors does not name every phase's current factors")
    if not isinstance(doc.get("hardware_class"), str) or not doc.get("hardware_class"):
        problems.append("hardware_class missing")
    quota = quota_decl["quotas"].get(doc.get("ingress")) if isinstance(doc.get("ingress"), str) else None
    if quota is None:
        problems.append(f"ingress {doc.get('ingress')!r} has no valid quota in {quota_decl['path']}")
    if doc.get("derived_from") != quota_decl["path"]:
        problems.append(f"derived_from is {doc.get('derived_from')!r}, not {quota_decl['path']}")
    for key in _HOSTILE_MS_KEYS:
        if not _positive_int(doc.get(key)):
            problems.append(f"{key} must be a positive integer")
    tol = doc.get("rate_tolerance")
    if not _number(tol) or not (0 < tol <= 0.2):
        problems.append("rate_tolerance must be a number in (0, 0.2]")
    shed_tol = doc.get("shed_tolerance")
    if not _number(shed_tol) or not (0 <= shed_tol <= 0.2):
        problems.append("shed_tolerance must be a number in [0, 0.2]")
    if not _positive_int(doc.get("leases_per_phase_per_action")):
        problems.append("leases_per_phase_per_action must be a positive integer")
    share = doc.get("min_hostile_share")
    if not _number(share) or not (0 < share <= 1):
        problems.append("min_hostile_share must be a number in (0, 1]")
    phases = doc.get("phases")
    if not isinstance(phases, list) or not phases:
        problems.append("phases is not a non-empty list")
        phases = []
    if quota is None or problems:
        out["problems"] = problems
        return out
    out["quota"] = dict(quota)
    poll_ms = doc["core_default_poll_ms"]
    names: Dict[str, int] = {}
    derived_all = []
    for idx, phase in enumerate(phases):
        p = _hostile_phase_problems(phase, quota, poll_ms)
        name = phase.get("name") if isinstance(phase, dict) else None
        if isinstance(name, str) and name in names:
            p.append(f"phase {name!r} declared twice (first at phases[{names[name]}])")
        if p:
            problems.append(f"phases[{idx}]: " + "; ".join(p))
            continue
        names[name] = idx
        derived = derived_phase_rates(phase, quota, poll_ms)
        derived_all.append((phase, derived))
        over = derived["non_alert_lines_per_s"] - quota["value"]
        if over > 0 and doc["warmup_ms"] * over < 1000 * quota["non_alert_burst"]:
            problems.append(
                f"phases[{idx}]: warmup_ms {doc['warmup_ms']} does not empty the {quota['non_alert_burst']}-token bucket at "
                f"{derived['non_alert_lines_per_s']} non-alert lines/s against the {quota['value']}/s quota"
            )
    if doc["audit_attribution_slack_ms"] < quota["audit_interval_ms"]:
        problems.append("audit_attribution_slack_ms is shorter than the quota's audit_interval_ms")
    if doc["quiet_gap_ms"] <= doc["audit_attribution_slack_ms"]:
        problems.append("quiet_gap_ms must exceed audit_attribution_slack_ms, or a summary could belong to two phases")
    rates = [d["rates_per_s"] for _, d in derived_all]
    fill_max = max((ph["alert_poll_fill"] for ph, _ in derived_all), default=0)
    if not any(d["non_alert_lines_per_s"] > quota["value"] for _, d in derived_all):
        problems.append("no phase offers non-alert lines above the quota")
    if not any(
        ph["non_alert_factor"] > 10 and burst_backlog_bytes(d, doc["line_bytes"]) >= 2 * quota["backlog_bound_bytes"]
        for ph, d in derived_all
    ):
        problems.append("no backlog phase: non-alert lines over 10 times the quota, in bursts of at least twice backlog_bound_bytes")
    if fill_max < 1.0:
        problems.append("no phase offers alerts at the poll cap (alert_poll_fill >= 1)")
    if not any(r["invalid_utf8"] > 0 and r["oversized"] > 0 for r in rates):
        problems.append("no phase mixes invalid UTF-8 and oversized lines")
    out["problems"] = problems
    if problems:
        return out
    for key in _HOSTILE_MS_KEYS:
        out[key] = doc[key]
    out["rate_tolerance"] = float(tol)
    out["status"] = doc["status"]
    out["shed_tolerance"] = float(shed_tol)
    out["leases_per_phase_per_action"] = doc["leases_per_phase_per_action"]
    out["min_hostile_share"] = float(share)
    out["phases"] = [
        {
            "name": ph["name"],
            "rates_per_s": dict(d["rates_per_s"]),
            "non_alert_lines_per_s": d["non_alert_lines_per_s"],
            "oversized_line_bytes": d["oversized_line_bytes"],
            "alert_poll_fill": ph["alert_poll_fill"],
            "burst_interval_ms": d["burst_interval_ms"],
            "backlog_phase": burst_backlog_bytes(d, doc["line_bytes"]) >= 2 * quota["backlog_bound_bytes"],
        }
        for ph, d in derived_all
    ]
    return out
