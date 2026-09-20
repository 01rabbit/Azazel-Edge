"""Edge <- Azazel-Knowledge (AZ-04) engagement advisory: the read side.

Knowledge produces a Fabric ``EngagementAdvisory`` on ``POST /v1/context``.
Until this module, nobody read one: Edge and Knowledge both *wrote* the
Engage-aligned types and neither parsed what the other wrote, which means the
contract had been serialized but never exchanged. A contract that has only
ever been written is not known to interoperate -- the first read is where a
disagreement shows (Azazel-Fabric#23, the R1c evidence gate).

This is the reading half. It mirrors
:mod:`azazel_edge.deception_effectiveness_client` deliberately, including its
two failure disciplines, because the authority boundary is the same one:

* **Response verification is fail-CLOSED.** The advisory block is the
  canonical Fabric ``EngagementAdvisory`` or it is rejected outright --
  whatever the HTTP status said. ``authority`` must be ``advisory_only`` and
  ``executable`` must be ``False``, and the model's ``extra="forbid"`` means a
  suggestion cannot arrive carrying a command it was never allowed to hold.
* **Edge-operation availability is fail-OPEN.** Knowledge is optional. A
  timeout, an outage, a malformed body, or a fail-closed rejection all degrade
  to "no advisory" and never raise into a caller, never block, and never
  change what Edge's deterministic arbiter decides.

**Three outcomes, not two.** Knowledge deliberately returns
``engagement_advisory: null`` rather than an advisory whose every field reads
``unknown``: "no evidence, no advice" is its own rule, and it means Knowledge
*looked* and had nothing. Folding that into the same bucket as "Knowledge is
unreachable" would discard the difference between a node that answered and a
node that is not there -- and an operator reading Edge's context needs to tell
those apart. So ``no_advisory`` is its own reason, and it is not a failure.

**What this module does not do.** It returns data. It selects no action,
writes into no decision path, and grants no authority. ``posture_suggestion``
is a suggestion in the ordinary English sense: Edge's deterministic arbiter
decides, and it decides identically whether this module returned an advisory,
returned ``no_advisory``, or was never called. That absence is asserted
structurally in ``tests/test_engagement_advisory_client.py`` rather than
promised here.

The request body is supplied by the caller. *What* Edge asks Knowledge about
-- which entities, which event -- is a product decision that belongs with the
caller; this module's job is transport and verification.

stdlib-only (``urllib``), matching the sibling client. No secret is
hardcoded: auth comes from :class:`KnowledgeAuthConfig`.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from azazel_edge.deception_effectiveness_client import (
    AdvisoryMalformedResponseError,
    AdvisoryTransportError,
    AdvisoryVerificationError,
    KnowledgeAuthConfig,
)

try:
    from azazel_fabric.engagement_contracts import (
        EngagementAdvisory,
        assert_engagement_advisory_only,
    )
except ImportError:  # Fabric remains an optional Edge integration dependency.
    EngagementAdvisory = None  # type: ignore[assignment,misc]
    assert_engagement_advisory_only = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

DEFAULT_CONTEXT_PATH = "/v1/context"

#: The key Knowledge carries the advisory under, beside its own context.
ADVISORY_KEY = "engagement_advisory"

#: Knowledge-local context that the Fabric contract deliberately does not
#: model -- Knowledge keeps it *beside* the advisory rather than widening a
#: shared contract to fit a product-local field. Carried through here for the
#: same reason, and kept out of the verified advisory for the same reason.
REPEATABILITY_KEY = "engagement_repeatability_score"


def fabric_engagement_available() -> bool:
    """True when the canonical Fabric engagement contracts are importable."""

    return EngagementAdvisory is not None and assert_engagement_advisory_only is not None


@dataclass(frozen=True)
class EngagementAdvisoryResult:
    """Outcome of one engagement-advisory read.

    ``reason`` is one of:

    ``ok``
        Knowledge returned an advisory and it verified. ``advisory`` is set.
    ``no_advisory``
        Knowledge answered and had nothing to advise. **Not a failure** --
        Knowledge's own rule is that an advisory needs evidence, so this says
        it looked. ``advisory`` is ``None``.
    ``unconfigured`` / ``unreachable`` / ``malformed_response`` / ``hostile_response``
        Something went wrong; treat all of these as "no advisory available".

    ``repeatability_score`` is Knowledge-local context that sits beside the
    advisory rather than inside it. It is carried verbatim and is **not** part
    of what verification covers -- a caller that treats it as contract-backed
    is treating a product-local number as a shared one.
    """

    available: bool
    advisory: dict[str, Any] | None
    reason: str
    detail: str | None = None
    repeatability_score: int | None = None

    @property
    def knowledge_answered(self) -> bool:
        """True when Knowledge responded, whether or not it had advice.

        The distinction an operator needs: `ok` and `no_advisory` both mean
        the node is there and was consulted.
        """

        return self.reason in {"ok", "no_advisory"}


class EngagementAdvisoryReader:
    """Reads and verifies one Knowledge ``EngagementAdvisory`` at a time.

    Two layers, as in the sibling client:

    * :meth:`fetch_advisory` is fail-closed -- it raises the moment the
      response is not exactly the canonical, non-executable advisory shape.
    * :meth:`get_advisory` is the fail-open surface every caller should use;
      it catches everything and always returns an
      :class:`EngagementAdvisoryResult`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        auth: KnowledgeAuthConfig | None = None,
        context_path: str = DEFAULT_CONTEXT_PATH,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = auth or KnowledgeAuthConfig()
        self.context_path = context_path
        self.timeout_seconds = float(timeout_seconds)

    # -- fail-closed verification ------------------------------------------

    def fetch_advisory(self, request_body: Mapping[str, Any]) -> dict[str, Any] | None:
        """POST a context request and verify the advisory it carries.

        Returns the verified advisory, or ``None`` when Knowledge answered
        that it has none. Raises on any transport or trust failure. Prefer
        :meth:`get_advisory` unless the caller specifically wants the
        fail-closed exception.
        """

        if not isinstance(request_body, Mapping):
            raise ValueError("request_body must be a mapping")
        if not fabric_engagement_available():
            raise AdvisoryTransportError(
                "canonical Fabric engagement contracts are unavailable"
            )

        payload = self._post(request_body)
        return self._verify_response(payload)[0]

    def _post(self, request_body: Mapping[str, Any]) -> Any:
        headers = {"Content-Type": "application/json", **self.auth.to_headers()}
        try:
            encoded = json.dumps(dict(request_body)).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"request_body is not JSON-serializable: {exc}") from exc

        http_request = urllib.request.Request(
            f"{self.base_url}{self.context_path}",
            data=encoded,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self.timeout_seconds) as raw:
                body = raw.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise AdvisoryTransportError(f"context request failed: HTTP {exc.code}") from exc
        except (OSError, ValueError) as exc:
            raise AdvisoryTransportError(f"context transport failed: {exc}") from exc

        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise AdvisoryMalformedResponseError(
                "context response is not valid JSON"
            ) from exc

    def _verify_response(self, payload: Any) -> tuple[dict[str, Any] | None, int | None]:
        """Extract and verify the advisory block. Returns (advisory, repeatability)."""

        if not isinstance(payload, dict):
            raise AdvisoryMalformedResponseError("context response is not a JSON object")

        repeatability = payload.get(REPEATABILITY_KEY)
        if repeatability is not None and not isinstance(repeatability, int):
            # Product-local context, so a wrong type is not hostile -- but it
            # is not a number either, and passing it on as one would invent a
            # value nobody sent.
            repeatability = None

        if ADVISORY_KEY not in payload:
            raise AdvisoryMalformedResponseError(
                f"context response carries no {ADVISORY_KEY!r} key"
            )
        block = payload[ADVISORY_KEY]
        if block is None:
            # Knowledge looked and had nothing. Its own rule, not a failure.
            return None, repeatability
        if not isinstance(block, dict):
            raise AdvisoryMalformedResponseError(
                f"{ADVISORY_KEY!r} is not a JSON object"
            )

        # Structural authority check first: a directive-shaped key anywhere in
        # the block is hostile outright, at any nesting depth. `prior_outcomes`
        # has free-form keys, so a directive can hide a level below where the
        # model's own field validation looks -- this is not redundant with
        # `extra="forbid"`.
        assert assert_engagement_advisory_only is not None
        try:
            assert_engagement_advisory_only(block)
        except ValueError as exc:
            raise AdvisoryVerificationError(
                f"engagement advisory carries a directive: {exc}"
            ) from exc

        assert EngagementAdvisory is not None
        try:
            advisory = EngagementAdvisory.model_validate(block)
        except Exception as exc:
            raise AdvisoryVerificationError(
                "engagement advisory failed contract validation: "
                f"{exc.__class__.__name__}: {exc}"
            ) from exc

        # Advisory-only is not negotiable.
        #
        # These two checks are unreachable today and deliberately kept: the
        # model's `Literal` types reject a wrong `authority` or `executable`
        # before control arrives here, so no payload can exercise them. That
        # makes them a backstop for one specific future -- the contract being
        # loosened to admit a second value -- and a backstop nobody can test
        # is worth keeping only if something notices when it becomes
        # load-bearing. `test_the_contract_still_pins_advisory_only` pins the
        # Literals, so a loosening fails there rather than silently promoting
        # these lines from redundant to the only thing standing.
        if advisory.authority != "advisory_only":
            raise AdvisoryVerificationError(
                "engagement advisory claims non-advisory authority"
            )
        if advisory.executable is not False:
            raise AdvisoryVerificationError("engagement advisory claims to be executable")

        return advisory.model_dump(mode="json"), repeatability

    # -- fail-open surface --------------------------------------------------

    def get_advisory(self, request_body: Mapping[str, Any]) -> EngagementAdvisoryResult:
        """Fail-open read: always returns, never raises.

        Edge's deterministic decision must proceed identically whether this
        returns ``ok``, ``no_advisory``, or any failure reason.
        """

        if not fabric_engagement_available():
            return EngagementAdvisoryResult(
                available=False,
                advisory=None,
                reason="unconfigured",
                detail="canonical Fabric engagement contracts are unavailable",
            )

        try:
            payload = self._post(request_body)
            advisory, repeatability = self._verify_response(payload)
        except AdvisoryVerificationError as exc:
            logger.warning("engagement advisory rejected (fail-closed verify): %s", exc)
            return EngagementAdvisoryResult(
                available=False, advisory=None, reason="hostile_response", detail=str(exc)
            )
        except AdvisoryMalformedResponseError as exc:
            logger.info("engagement advisory response malformed: %s", exc)
            return EngagementAdvisoryResult(
                available=False, advisory=None, reason="malformed_response", detail=str(exc)
            )
        except AdvisoryTransportError as exc:
            logger.info("Knowledge context unreachable: %s", exc)
            return EngagementAdvisoryResult(
                available=False, advisory=None, reason="unreachable", detail=str(exc)
            )
        except Exception as exc:  # belt-and-suspenders: nothing escapes
            logger.warning("engagement advisory read failed unexpectedly: %s", exc)
            return EngagementAdvisoryResult(
                available=False,
                advisory=None,
                reason="unreachable",
                detail=f"{exc.__class__.__name__}: {exc}",
            )

        if advisory is None:
            return EngagementAdvisoryResult(
                available=False,
                advisory=None,
                reason="no_advisory",
                detail="Knowledge answered with no engagement advisory",
                repeatability_score=repeatability,
            )
        return EngagementAdvisoryResult(
            available=True,
            advisory=advisory,
            reason="ok",
            repeatability_score=repeatability,
        )


class OptionalEngagementAdvisorySource:
    """Wraps an optional reader so a caller need not branch on configuration.

    Deliberately *not* a decision input: it returns context for an operator
    surface or an audit record. Edge's arbiter is unaffected by this class
    existing in the call graph.
    """

    def __init__(self, reader: EngagementAdvisoryReader | None = None) -> None:
        self._reader = reader

    @property
    def configured(self) -> bool:
        return self._reader is not None

    def consult(self, request_body: Mapping[str, Any]) -> EngagementAdvisoryResult:
        if self._reader is None:
            return EngagementAdvisoryResult(
                available=False,
                advisory=None,
                reason="unconfigured",
                detail="no Knowledge engagement advisory reader configured",
            )
        return self._reader.get_advisory(request_body)


__all__ = [
    "ADVISORY_KEY",
    "DEFAULT_CONTEXT_PATH",
    "REPEATABILITY_KEY",
    "EngagementAdvisoryReader",
    "EngagementAdvisoryResult",
    "OptionalEngagementAdvisorySource",
    "fabric_engagement_available",
]
