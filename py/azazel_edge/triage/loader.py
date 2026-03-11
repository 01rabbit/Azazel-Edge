from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

import yaml

from .types import TriageFlow


DEFAULT_FLOW_DIR = Path(__file__).resolve().parent / "flows"


def _flow_dirs() -> List[Path]:
    dirs: List[Path] = []
    env_dir = os.environ.get("AZAZEL_TRIAGE_FLOW_DIR")
    if env_dir:
        dirs.append(Path(env_dir))
    dirs.append(DEFAULT_FLOW_DIR)
    return dirs


def _resolve_flow_file(flow_id: str) -> Path:
    for base in _flow_dirs():
        candidate = base / f"{flow_id}.yaml"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"triage_flow_not_found:{flow_id}")


def validate_flow(flow: TriageFlow) -> TriageFlow:
    step_ids = [step.step_id for step in flow.steps]
    if len(step_ids) != len(set(step_ids)):
        raise ValueError(f"duplicate_step_id:{flow.flow_id}")
    if flow.entry_state not in step_ids:
        raise ValueError(f"entry_state_not_found:{flow.flow_id}:{flow.entry_state}")
    diagnostic_ids = {item.state_id for item in flow.diagnostic_states}
    valid_targets = set(step_ids) | diagnostic_ids
    for step in flow.steps:
        for target in list(step.transition_map.values()) + [step.fallback_transition]:
            if target not in valid_targets:
                raise ValueError(f"invalid_transition_target:{flow.flow_id}:{step.step_id}:{target}")
    return flow


def load_flow(flow_id: str) -> TriageFlow:
    path = _resolve_flow_file(flow_id)
    with path.open("r", encoding="utf-8") as fh:
        payload: Dict[str, object] = yaml.safe_load(fh) or {}
    flow = TriageFlow.from_dict(payload)
    return validate_flow(flow)


def list_flows() -> List[TriageFlow]:
    flows: List[TriageFlow] = []
    seen: set[str] = set()
    for base in _flow_dirs():
        if not base.exists():
            continue
        for path in sorted(base.glob("*.yaml")):
            if path.stem in seen:
                continue
            flows.append(load_flow(path.stem))
            seen.add(path.stem)
    return flows
