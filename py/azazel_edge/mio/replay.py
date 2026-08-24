from __future__ import annotations

from dataclasses import dataclass

from .contracts import MioSituationFrame
from .playbook import DEFAULT_PLAYBOOKS
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
