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
