"""Keeps the governance and model-lane Knowledge status vocabularies identical.

The production module carries its own literal copy (no import coupling), so this
test is the only place the two sets are tied together.
"""

from azazel_edge.ai_governance import KNOWLEDGE_STATUS_VALUES
from azazel_edge_ai.mio_model_lane import KNOWLEDGE_STATUSES


MODEL_STATUSES_REQUIRED = frozenset({"projected", "rejected", "unavailable"})
# Distinct envelope vocabularies, deliberately outside the Knowledge status set.
ENVELOPE_ONLY_VOCABULARY = frozenset({"not_queried", "not_provided", "absent"})


def test_governance_knowledge_status_vocabulary_matches_model_lane():
    assert isinstance(KNOWLEDGE_STATUSES, frozenset)
    assert KNOWLEDGE_STATUSES  # non-empty
    assert KNOWLEDGE_STATUS_VALUES == KNOWLEDGE_STATUSES


def test_knowledge_vocabulary_has_model_statuses_and_excludes_envelope_only_values():
    assert MODEL_STATUSES_REQUIRED <= KNOWLEDGE_STATUSES
    assert not (ENVELOPE_ONLY_VOCABULARY & KNOWLEDGE_STATUSES)
