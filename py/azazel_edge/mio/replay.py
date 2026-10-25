from __future__ import annotations

from dataclasses import dataclass

from .contracts import MioSituationFrame
from .playbook import DEFAULT_PLAYBOOKS, select_playbook
from .reasoning import BoundedReasoningLoop, ReasoningOutcome


@dataclass(frozen=True)
class ReplayFixture:
    fixture_id: str
    frame: MioSituationFrame
    playbook_id: str


def run_replay(loop: BoundedReasoningLoop, fixture: ReplayFixture) -> ReasoningOutcome:
    playbook = DEFAULT_PLAYBOOKS.get(fixture.playbook_id)
    if playbook is None:
        raise ValueError("unknown_playbook")
    return loop.run(frame=fixture.frame, playbook=playbook, cycle_id=f"replay:{fixture.fixture_id}")


def run_selected(
    loop: BoundedReasoningLoop, frame: MioSituationFrame, *, cycle_id: str, requested_id: str | None = None
) -> ReasoningOutcome:
    """Run with deterministic playbook selection.

    ``requested_id`` is a trusted caller choice (operator config), never model
    output; an unregistered id falls back to generic (``explicit_unknown_fallback``).
    Any generic fallback is recorded in provenance and as ``generic_fallback:<reason>``.
    """
    selection = select_playbook(frame, requested_id=requested_id)
    return loop.run(frame=frame, playbook=selection.playbook, cycle_id=cycle_id, selection=selection)
