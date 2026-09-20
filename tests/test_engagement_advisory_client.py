"""Edge consumes Knowledge's `EngagementAdvisory` (Azazel-Fabric#23, R1c).

Before this, Edge and Knowledge both *produced* the Engage-aligned types and
neither read what the other wrote. A contract that has only ever been
serialized is not known to interoperate; the first read is where a
disagreement shows. These tests are that read, plus the two disciplines it
has to keep.

The fixture is built from Fabric's own model rather than hand-written JSON:
a hand-written wire shape drifts from the contract, and it drifts silently
because the test that uses it never checks it against anything.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "py"))

from azazel_edge.engagement_advisory_client import (  # noqa: E402
    ADVISORY_KEY,
    REPEATABILITY_KEY,
    EngagementAdvisoryReader,
    EngagementAdvisoryResult,
    OptionalEngagementAdvisorySource,
    fabric_engagement_available,
)

pytestmark = pytest.mark.skipif(
    not fabric_engagement_available(),
    reason="azazel_fabric engagement contracts are an optional Edge extra",
)


def _advisory_payload(**overrides) -> dict:
    """A valid advisory, produced through the contract Knowledge produces it with."""
    from azazel_fabric.engagement_contracts import EngagementAdvisory, PostureSuggestion

    advisory = EngagementAdvisory(
        advisory_id="adv-1",
        advisor="azazel-knowledge",
        seen_before=True,
        behavior_class="adaptive_probe",
        confidence=0.62,
        prior_outcomes={"decoy": {"count": 3, "engaged": True}},
        posture_suggestion=PostureSuggestion(
            objective="collect",
            approach="channel",
            supported_activities=("redirect_to_decoy",),
            reasons=("prior decoy engagement observed",),
        ),
        reasons=("three prior decoy reactions",),
        limitations=("delay and deception have no canonical activity",),
    )
    payload = advisory.model_dump(mode="json")
    payload.update(overrides)
    return payload


def _context_response(advisory=..., repeatability=4) -> dict:
    body = {
        "recommendation": {"action": "observe"},
        REPEATABILITY_KEY: repeatability,
        ADVISORY_KEY: _advisory_payload() if advisory is ... else advisory,
    }
    return body


class _FakeHTTP:
    """Stands in for urllib. Records the request; returns a canned body."""

    def __init__(self, body, *, raise_exc: Exception | None = None):
        self.body = body
        self.raise_exc = raise_exc
        self.requests: list = []

    def __call__(self, request, timeout=None):  # noqa: D401 - urlopen stand-in
        self.requests.append(request)
        if self.raise_exc is not None:
            raise self.raise_exc
        payload = self.body if isinstance(self.body, str) else json.dumps(self.body)
        return _FakeResponse(payload)


class _FakeResponse:
    def __init__(self, text: str):
        self._text = text

    def read(self):
        return self._text.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def reader(monkeypatch):
    def _make(body, raise_exc=None):
        fake = _FakeHTTP(body, raise_exc=raise_exc)
        monkeypatch.setattr(
            "azazel_edge.engagement_advisory_client.urllib.request.urlopen", fake
        )
        return EngagementAdvisoryReader("http://knowledge.invalid", timeout_seconds=1.0), fake

    return _make


# -- the read itself ---------------------------------------------------------


def test_edge_reads_an_advisory_knowledge_produced(reader):
    read, _ = reader(_context_response())

    result = read.get_advisory({"actor_key": "ip:198.51.100.7"})

    assert result.reason == "ok"
    assert result.available is True
    assert result.knowledge_answered is True
    assert result.advisory["advisor"] == "azazel-knowledge"
    assert result.advisory["posture_suggestion"]["objective"] == "collect"
    assert result.repeatability_score == 4


def test_the_advisory_arrives_as_the_canonical_shape(reader):
    """Round trip: what Edge returns re-validates as the same contract."""
    from azazel_fabric.engagement_contracts import EngagementAdvisory

    read, _ = reader(_context_response())
    result = read.get_advisory({})

    restored = EngagementAdvisory.model_validate(result.advisory)
    assert restored.authority == "advisory_only"
    assert restored.executable is False


def test_the_request_body_is_what_the_caller_supplied(reader):
    read, fake = reader(_context_response())

    read.get_advisory({"actor_key": "ja3:abc", "trace_id": "t-1"})

    sent = json.loads(fake.requests[0].data.decode("utf-8"))
    assert sent == {"actor_key": "ja3:abc", "trace_id": "t-1"}, (
        "the client must relay the caller's question unchanged -- what Edge "
        "asks Knowledge about is the caller's decision, not this module's"
    )


# -- three outcomes, not two -------------------------------------------------


def test_knowledge_having_nothing_is_not_a_failure(reader):
    """`no_advisory` says Knowledge looked. `unreachable` says it is not there.

    Knowledge returns null rather than an advisory whose every field reads
    unknown -- "no evidence, no advice" is its own rule. Collapsing that into
    the same bucket as an outage throws away the difference between a node
    that answered and a node that is absent.
    """

    read, _ = reader(_context_response(advisory=None))

    result = read.get_advisory({})

    assert result.reason == "no_advisory"
    assert result.available is False
    assert result.advisory is None
    assert result.knowledge_answered is True, (
        "Knowledge answered; it simply had nothing to advise"
    )


def test_an_outage_is_distinguishable_from_having_nothing(reader):
    read, _ = reader(None, raise_exc=OSError("connection refused"))

    result = read.get_advisory({})

    assert result.reason == "unreachable"
    assert result.knowledge_answered is False


def test_a_repeatability_score_survives_an_empty_advisory(reader):
    """Knowledge-local context is carried even when there is no advisory."""
    read, _ = reader(_context_response(advisory=None, repeatability=9))

    assert read.get_advisory({}).repeatability_score == 9


# -- fail-closed verification ------------------------------------------------


def test_an_advisory_claiming_authority_is_rejected(reader):
    read, _ = reader(_context_response(advisory=_advisory_payload(authority="authoritative")))

    result = read.get_advisory({})

    assert result.reason == "hostile_response"
    assert result.advisory is None


def test_an_advisory_claiming_to_be_executable_is_rejected(reader):
    read, _ = reader(_context_response(advisory=_advisory_payload(executable=True)))

    assert read.get_advisory({}).reason == "hostile_response"


@pytest.mark.parametrize(
    "directive",
    ["shell_command", "nft_rule", "execute_now", "bypass_arbiter", "must_execute"],
)
def test_a_directive_smuggled_into_free_form_keys_is_rejected(reader, directive):
    """`prior_outcomes` has free-form keys -- a level below `extra="forbid"`."""
    hostile = _advisory_payload()
    hostile["prior_outcomes"] = {"decoy": {directive: "x"}}
    read, _ = reader(_context_response(advisory=hostile))

    result = read.get_advisory({})

    assert result.reason == "hostile_response", (
        f"{directive!r} reached Edge nested inside prior_outcomes. The model's "
        "extra=forbid does not look there; the recursive walk is what does."
    )


def test_an_unknown_field_is_rejected(reader):
    read, _ = reader(_context_response(advisory=_advisory_payload(surprise="x")))

    assert read.get_advisory({}).reason == "hostile_response"


def test_a_non_canonical_posture_activity_is_rejected(reader):
    """Knowledge never widens the Engage vocabulary, and Edge never accepts a widening."""
    hostile = _advisory_payload()
    hostile["posture_suggestion"]["supported_activities"] = ["deploy_ransomware"]
    read, _ = reader(_context_response(advisory=hostile))

    assert read.get_advisory({}).reason == "hostile_response"


def test_a_body_that_is_not_json_is_malformed_not_hostile(reader):
    read, _ = reader("<html>502</html>")

    assert read.get_advisory({}).reason == "malformed_response"


def test_a_response_without_the_advisory_key_is_malformed(reader):
    read, _ = reader({"recommendation": {"action": "observe"}})

    result = read.get_advisory({})

    assert result.reason == "malformed_response", (
        "a missing key and an explicit null mean different things: the second "
        "is Knowledge saying it has nothing, the first is not Knowledge's shape"
    )


def test_an_advisory_that_is_not_an_object_is_malformed(reader):
    read, _ = reader(_context_response(advisory=["not", "an", "object"]))

    assert read.get_advisory({}).reason == "malformed_response"


def test_a_non_integer_repeatability_is_dropped_rather_than_passed_on(reader):
    read, _ = reader(_context_response(repeatability="lots"))

    result = read.get_advisory({})

    assert result.reason == "ok"
    assert result.repeatability_score is None, (
        "passing a non-number on as a score would invent a value nobody sent"
    )


# -- fail-open availability --------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        OSError("refused"),
        TimeoutError("slow"),
        ValueError("bad url"),
    ],
)
def test_no_transport_failure_ever_escapes(reader, failure):
    read, _ = reader(None, raise_exc=failure)

    result = read.get_advisory({})

    assert isinstance(result, EngagementAdvisoryResult)
    assert result.available is False


def test_an_unconfigured_source_answers_without_a_reader():
    source = OptionalEngagementAdvisorySource()

    result = source.consult({})

    assert source.configured is False
    assert result.reason == "unconfigured"
    assert result.available is False


def test_a_configured_source_delegates(reader):
    read, _ = reader(_context_response())

    source = OptionalEngagementAdvisorySource(read)

    assert source.configured is True
    assert source.consult({}).reason == "ok"


def test_the_contract_still_pins_advisory_only():
    """What makes the client's redundant checks honest.

    `_verify_response` re-checks `authority` and `executable` after the model
    has already enforced them through `Literal` types -- so no payload can
    reach those lines, and no test can exercise them. They are a backstop for
    the contract being loosened. This is what notices if that happens: the
    day a second value is admitted, this fails, and those lines stop being
    redundant.
    """

    import typing

    from azazel_fabric.engagement_contracts import EngagementAdvisory

    authority = EngagementAdvisory.model_fields["authority"].annotation
    executable = EngagementAdvisory.model_fields["executable"].annotation

    assert typing.get_args(authority) == ("advisory_only",), (
        "EngagementAdvisory.authority admits more than one value. The client's "
        "explicit authority check is now load-bearing rather than redundant -- "
        "verify it still rejects what the contract began permitting."
    )
    assert typing.get_args(executable) == (False,)
    assert EngagementAdvisory.model_config.get("extra") == "forbid"


def test_an_unexpected_error_inside_verification_still_fails_open(reader, monkeypatch):
    """The belt-and-suspenders clause, exercised rather than assumed.

    The three named error types are converted on the way out of `_post`. This
    covers what the final `except Exception` is actually for: something going
    wrong during verification that nobody anticipated. It must still degrade
    to "no advisory" rather than raising into a caller's decision path.
    """

    read, _ = reader(_context_response())

    def _boom(self, payload):
        raise KeyError("something nobody planned for")

    monkeypatch.setattr(
        "azazel_edge.engagement_advisory_client.EngagementAdvisoryReader._verify_response",
        _boom,
    )

    result = read.get_advisory({})

    assert result.available is False
    assert result.reason == "unreachable"
    assert "KeyError" in (result.detail or "")


# -- the authority boundary, asserted structurally ---------------------------


def test_the_client_reaches_no_decision_path():
    """The invariant is an absence, so it is checked as one.

    Knowledge advises; Edge's deterministic arbiter decides. This module may
    return an advisory to an operator surface or an audit record, and it may
    not import, call, or hand anything to the arbiter -- an import is where
    that would start.
    """

    import ast

    source = (
        Path(__file__).resolve().parents[1]
        / "py"
        / "azazel_edge"
        / "engagement_advisory_client.py"
    )
    tree = ast.parse(source.read_text(encoding="utf-8"))

    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    forbidden = [
        name
        for name in imported
        if any(
            part in name
            for part in ("arbiter", "decision_layers", "control_plane", "evaluators")
        )
    ]

    assert forbidden == [], (
        f"the engagement advisory client imports {forbidden}. Knowledge "
        "advises; Edge's arbiter decides. A read path that can reach the "
        "arbiter is a read path that can steer it."
    )


def test_the_arbiter_does_not_know_this_module_exists():
    """The other direction, which is the one that would actually bite.

    The client not importing the arbiter proves nothing if the arbiter
    imports the client.
    """

    import ast

    arbiter_dir = Path(__file__).resolve().parents[1] / "py" / "azazel_edge" / "arbiter"
    offenders = []
    for path in sorted(arbiter_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if "engagement_advisory" in name or "knowledge" in name.lower():
                    offenders.append(f"{path.name}: {name}")

    assert offenders == [], (
        f"the arbiter imports an advisory source: {offenders}. Edge's decision "
        "must be identical whether Knowledge answered, had nothing, or is gone."
    )
