"""Edge -> Azazel-Knowledge (AZ-04) advisory-only effectiveness path.

This is the Edge side of the Deception -> Edge -> Knowledge interlock: AZ-06
emits fact-only :class:`azazel_fabric.deception_contracts.InteractionObservation`
records while an engagement is live; Edge relays batches of them to Knowledge
for analysis and may, purely for operator/arbiter context, read back a
Knowledge :class:`~azazel_fabric.deception_contracts.EffectivenessAdvisory`.

Two very different failure disciplines apply here, deliberately:

* **Response verification is fail-CLOSED.** An advisory response is the
  canonical Fabric ``EffectivenessAdvisory`` shape or it is rejected outright.
  Extra fields, a wrong ``authority``, or ``executable`` anything but
  ``False`` are treated as hostile, whatever the HTTP status code says
  (mirrors :mod:`azazel_edge.deception_shadow_client`).
* **Edge-operation availability is fail-OPEN.** Knowledge is optional and
  advisory-only (AZ-04 doctrine: "Edge is the sole authority; Knowledge is
  advisory-only"). Any transport failure, timeout, malformed body, or
  fail-closed rejection degrades to "no advisory available" -- it never
  raises out of :meth:`EffectivenessAdvisoryReader.get_advisory`, never
  blocks, and never changes Edge's deterministic decision. The returned
  advisory (when present) is context only: nothing in this module writes it
  into a decision path, selects an action, or grants authority.

Security framing for the ingest side: an ``InteractionObservation`` batch is
attacker-authored content (lure IDs, metadata strings, evidence refs) wrapped
in a Fabric envelope. :class:`KnowledgeIngestClient` is a *relay* of that
content -- it JSON-serializes and POSTs the dicts it is given and never
evaluates, formats, executes, or otherwise interprets any field value. The
only structural check it performs is the authority-boundary invariant Fabric
itself defines (:func:`assert_no_runtime_directives`): reject forwarding a
payload that smuggles an executable/runtime-directive key, which is a check
on *key names*, not on attacker-controlled string content.

stdlib-only (``urllib``), matching :mod:`azazel_edge.deception_shadow_client`.
No secret is ever hardcoded here: auth is supplied by the caller via
:class:`KnowledgeAuthConfig`, optionally sourced from the environment with
:meth:`KnowledgeAuthConfig.from_env`.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

try:
    from azazel_fabric.deception_contracts import (
        EffectivenessAdvisory,
        assert_no_runtime_directives,
    )
except ImportError:  # Fabric remains an optional Edge integration dependency.
    EffectivenessAdvisory = None  # type: ignore[assignment,misc]
    assert_no_runtime_directives = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

DEFAULT_INGEST_PATH = "/v1/deception-observations"
DEFAULT_ADVISORY_PATH_TEMPLATE = "/v1/deception-advisories/{environment_id}"
INGEST_BATCH_SCHEMA = "deception-observation-batch/v0.1"

# HTTP statuses treated as ordinary, expected backpressure: the batch was
# understood but Knowledge chose not to accept it right now. Never raised.
_ACCEPTED_STATUSES = frozenset({200, 202})
_BACKPRESSURE_STATUSES = frozenset({413, 429, 503})


def fabric_available() -> bool:
    return EffectivenessAdvisory is not None and assert_no_runtime_directives is not None


class AdvisoryTransportError(RuntimeError):
    """An advisory request could not be completed (network/HTTP failure).

    Distinct from :class:`AdvisoryVerificationError` so the fail-open layer
    can tell "Knowledge was unreachable" apart from "Knowledge answered but
    the answer was hostile" -- both degrade to "advisory unavailable" for the
    caller, but the reason recorded differs.
    """


class AdvisoryMalformedResponseError(RuntimeError):
    """An advisory response body was not valid JSON / not a JSON object."""


class AdvisoryVerificationError(RuntimeError):
    """A Knowledge advisory response failed authority verification.

    Raised only by the low-level verification step, for a syntactically fine
    response whose *content* is not the canonical, non-executable advisory
    shape (wrong authority, executable not False, or any extra/directive/
    verdict field). Fail-open callers must catch this (see
    :meth:`EffectivenessAdvisoryReader.get_advisory`) rather than let it
    escape to the deterministic decision path.
    """


@dataclass(frozen=True)
class KnowledgeAuthConfig:
    """Configurable auth for the Knowledge AZ-04 HTTP API.

    Never hardcode a token: construct this from operator configuration or
    :meth:`from_env`. ``header_name``/``scheme`` are configurable because the
    ingest scope's exact header convention is a Knowledge-side deployment
    choice, not something this client should assume.
    """

    token: str | None = None
    header_name: str = "Authorization"
    scheme: str | None = "Bearer"

    def to_headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        value = f"{self.scheme} {self.token}" if self.scheme else self.token
        return {self.header_name: value}

    @classmethod
    def from_env(cls, prefix: str = "AZ_KNOWLEDGE_") -> "KnowledgeAuthConfig":
        """Build auth config from environment variables, never a literal.

        Reads ``{prefix}TOKEN`` (required for a non-empty config),
        ``{prefix}AUTH_HEADER`` (default ``Authorization``), and
        ``{prefix}AUTH_SCHEME`` (default ``Bearer``; set to the empty string
        to send the token value with no scheme prefix).
        """

        token = os.environ.get(f"{prefix}TOKEN") or None
        header_name = os.environ.get(f"{prefix}AUTH_HEADER") or "Authorization"
        scheme_raw = os.environ.get(f"{prefix}AUTH_SCHEME")
        scheme = "Bearer" if scheme_raw is None else (scheme_raw or None)
        return cls(token=token, header_name=header_name, scheme=scheme)


@dataclass(frozen=True)
class IngestResult:
    """Outcome of one best-effort observation-batch relay attempt.

    ``status`` is one of: ``accepted``, ``backpressure``, ``rejected``,
    ``unreachable``, ``invalid_batch``. None of these are exceptions -- the
    ingest path is fire-and-forget by design (AZ-06 observation emission must
    never block on Knowledge's availability).
    """

    status: str
    submitted_count: int
    http_status: int | None = None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "accepted"


@dataclass(frozen=True)
class AdvisoryReadResult:
    """Outcome of one advisory read: either a verified advisory or a reason.

    ``reason`` is one of: ``ok``, ``unconfigured``, ``unreachable``,
    ``malformed_response``, ``hostile_response``. Only ``ok`` carries a
    non-``None`` ``advisory``. This is the fail-open surface: callers should
    treat every non-``ok`` reason identically -- "no advisory available" --
    and continue with Edge's deterministic decision unchanged.
    """

    available: bool
    advisory: dict[str, Any] | None
    reason: str
    detail: str | None = None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class KnowledgeIngestClient:
    """Best-effort relay of AZ-06 ``InteractionObservation`` batches to AZ-04.

    This client does not interpret observation content. Every field in a
    submitted observation (lure IDs, metadata, evidence refs, ...) may be
    attacker-influenced; it is JSON-encoded and forwarded verbatim, never
    evaluated, executed, or used to make a local decision. The only rejection
    this client performs before sending is Fabric's runtime-directive
    authority check on key names (:func:`assert_no_runtime_directives`), not
    an interpretation of any string value.
    """

    def __init__(
        self,
        base_url: str,
        *,
        edge_node_id: str,
        auth: KnowledgeAuthConfig | None = None,
        ingest_path: str = DEFAULT_INGEST_PATH,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not edge_node_id:
            raise ValueError("edge_node_id is required")
        self.base_url = base_url.rstrip("/")
        self.edge_node_id = edge_node_id
        self.auth = auth or KnowledgeAuthConfig()
        self.ingest_path = ingest_path
        self.timeout_seconds = float(timeout_seconds)

    def submit_observations(self, observations: list[dict[str, Any]]) -> IngestResult:
        """POST one batch. Never raises: every failure mode returns a status.

        Fire-and-forget: an unreachable, slow, or backpressuring Knowledge
        must not affect AZ-06's ability to keep emitting observations, so
        this method reports rather than raises in every case.
        """

        if not isinstance(observations, list) or not observations:
            return IngestResult(
                status="invalid_batch",
                submitted_count=0,
                detail="observations must be a non-empty list",
            )
        if not all(isinstance(item, dict) for item in observations):
            return IngestResult(
                status="invalid_batch",
                submitted_count=0,
                detail="every observation must be a dict",
            )

        # Structural authority check only: reject a batch that smuggles a
        # runtime/execution key. This inspects key names, never the
        # attacker-authored string values the keys hold.
        if assert_no_runtime_directives is not None:
            try:
                assert_no_runtime_directives(observations)
            except ValueError as exc:
                return IngestResult(
                    status="invalid_batch",
                    submitted_count=0,
                    detail=f"authority invariant violated: {exc}",
                )

        envelope = {
            "schema_version": INGEST_BATCH_SCHEMA,
            "source_edge_node_id": self.edge_node_id,
            "submitted_at": _utcnow_iso(),
            "observations": observations,
        }
        headers = {"Content-Type": "application/json"}
        headers.update(self.auth.to_headers())
        http_request = urllib.request.Request(
            f"{self.base_url}{self.ingest_path}",
            data=json.dumps(envelope).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(http_request, timeout=self.timeout_seconds) as raw:
                status_code = raw.getcode()
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            body = exc.read()
            detail = body.decode("utf-8", errors="replace")[:500] if body else None
            if status_code in _BACKPRESSURE_STATUSES:
                logger.info(
                    "Knowledge ingest backpressure (status=%s): %s", status_code, detail
                )
                return IngestResult(
                    status="backpressure",
                    submitted_count=len(observations),
                    http_status=status_code,
                    detail=detail,
                )
            logger.warning(
                "Knowledge ingest rejected batch (status=%s): %s", status_code, detail
            )
            return IngestResult(
                status="rejected",
                submitted_count=len(observations),
                http_status=status_code,
                detail=detail,
            )
        except (OSError, ValueError) as exc:
            logger.info("Knowledge ingest unreachable: %s", exc)
            return IngestResult(
                status="unreachable",
                submitted_count=len(observations),
                detail=f"{exc.__class__.__name__}: {exc}",
            )

        if status_code in _ACCEPTED_STATUSES:
            return IngestResult(
                status="accepted",
                submitted_count=len(observations),
                http_status=status_code,
            )
        logger.info("Knowledge ingest returned unexpected status=%s", status_code)
        return IngestResult(
            status="backpressure" if status_code in _BACKPRESSURE_STATUSES else "rejected",
            submitted_count=len(observations),
            http_status=status_code,
        )


class EffectivenessAdvisoryReader:
    """Reads and verifies one Knowledge ``EffectivenessAdvisory`` at a time.

    Two layers, on purpose:

    * :meth:`fetch_advisory` is the fail-closed layer -- it raises
      :class:`AdvisoryVerificationError` (or lets a transport error escape)
      the moment the response is not exactly the canonical, non-executable
      advisory shape.
    * :meth:`get_advisory` is the fail-open layer every caller should
      actually use -- it calls :meth:`fetch_advisory`, catches *everything*,
      and always returns an :class:`AdvisoryReadResult`. A Knowledge outage,
      timeout, malformed body, or fail-closed rejection all degrade to the
      same "advisory unavailable" outcome; none of them can block or steer
      Edge's deterministic decision.
    """

    def __init__(
        self,
        base_url: str,
        *,
        auth: KnowledgeAuthConfig | None = None,
        advisory_path_template: str = DEFAULT_ADVISORY_PATH_TEMPLATE,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = auth or KnowledgeAuthConfig()
        self.advisory_path_template = advisory_path_template
        self.timeout_seconds = float(timeout_seconds)

    # -- fail-closed verification ---------------------------------------

    def fetch_advisory(self, environment_id: str) -> dict[str, Any]:
        """GET and verify one advisory. Raises on any transport or trust failure.

        Prefer :meth:`get_advisory` unless the caller specifically wants the
        fail-closed exception (e.g. a diagnostic tool).
        """

        if not environment_id:
            raise ValueError("environment_id is required")
        if not fabric_available():
            raise AdvisoryTransportError(
                "canonical Fabric deception contracts are unavailable"
            )

        path = self.advisory_path_template.format(environment_id=environment_id)
        headers = dict(self.auth.to_headers())
        http_request = urllib.request.Request(
            f"{self.base_url}{path}", headers=headers, method="GET"
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self.timeout_seconds) as raw:
                body = raw.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise AdvisoryTransportError(
                f"advisory request failed: HTTP {exc.code}"
            ) from exc
        except (OSError, ValueError) as exc:
            raise AdvisoryTransportError(f"advisory transport failed: {exc}") from exc

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise AdvisoryMalformedResponseError(
                "advisory response is not valid JSON"
            ) from exc

        return self._verify_response(payload)

    def _verify_response(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise AdvisoryMalformedResponseError("advisory response is not a JSON object")

        # Structural authority check first: any runtime/execution-directive
        # key anywhere in the payload is treated as hostile outright.
        assert assert_no_runtime_directives is not None
        try:
            assert_no_runtime_directives(payload)
        except ValueError as exc:
            raise AdvisoryVerificationError(
                f"advisory response carries a runtime directive: {exc}"
            ) from exc

        # The canonical Fabric model is the source of truth for the wire
        # shape: extra="forbid" rejects unknown fields (an executable,
        # directive, or verdict field included), and the Literal types pin
        # authority=="advisory_only" / executable==False structurally.
        assert EffectivenessAdvisory is not None
        try:
            advisory = EffectivenessAdvisory.model_validate(payload)
        except Exception as exc:
            raise AdvisoryVerificationError(
                f"advisory response failed contract validation: {exc.__class__.__name__}: {exc}"
            ) from exc

        # Advisory-only is not negotiable: explicit, redundant checks even
        # though the model above already enforces them -- a response
        # claiming otherwise is hostile, whatever else it got right.
        if advisory.authority != "advisory_only":
            raise AdvisoryVerificationError("advisory response claims non-advisory authority")
        if advisory.executable is not False:
            raise AdvisoryVerificationError("advisory response claims to be executable")

        return advisory.model_dump(mode="json")

    # -- fail-open surface -------------------------------------------------

    def get_advisory(self, environment_id: str) -> AdvisoryReadResult:
        """Fail-open read: always returns, never raises.

        Every failure mode -- Knowledge absent, slow, unreachable, returning
        malformed JSON, or returning a response that fails authority
        verification -- degrades to ``available=False`` with a descriptive
        ``reason``. Edge's deterministic decision must proceed identically
        whether this returns ``ok`` or anything else.
        """

        try:
            advisory = self.fetch_advisory(environment_id)
        except AdvisoryVerificationError as exc:
            # Response arrived but failed authority verification -- treated
            # as hostile, and still degrades to "no advisory" rather than
            # raising into the caller's decision path.
            logger.warning("Knowledge advisory rejected (fail-closed verify): %s", exc)
            return AdvisoryReadResult(
                available=False, advisory=None, reason="hostile_response", detail=str(exc)
            )
        except AdvisoryMalformedResponseError as exc:
            logger.info("Knowledge advisory response malformed: %s", exc)
            return AdvisoryReadResult(
                available=False, advisory=None, reason="malformed_response", detail=str(exc)
            )
        except AdvisoryTransportError as exc:
            logger.info("Knowledge advisory unreachable: %s", exc)
            return AdvisoryReadResult(
                available=False, advisory=None, reason="unreachable", detail=str(exc)
            )
        except Exception as exc:  # belt-and-suspenders: never let anything escape
            logger.warning("Knowledge advisory read failed unexpectedly: %s", exc)
            return AdvisoryReadResult(
                available=False,
                advisory=None,
                reason="unreachable",
                detail=f"{exc.__class__.__name__}: {exc}",
            )
        return AdvisoryReadResult(available=True, advisory=advisory, reason="ok")


class OptionalEffectivenessAdvisorySource:
    """Pluggable, optional advisory context for the operator/arbiter.

    Wrap an :class:`EffectivenessAdvisoryReader` (or ``None``, meaning
    Knowledge is not configured for this deployment) and hand the result to
    :meth:`consult`. This class is deliberately *not* a decision input: it
    has no method that returns an action, a score adjustment, or anything
    that could be mistaken for authority. Callers get context to display or
    log, nothing more -- wiring it into an actual selection/authorization
    path is an explicit, separate choice this module does not make.

    When ``reader`` is ``None`` (Knowledge unconfigured/absent), every call
    to :meth:`consult` returns immediately with ``reason="unconfigured"`` and
    makes no network call, so baseline Edge behavior is byte-for-byte
    unaffected by this class simply existing in the call graph.
    """

    def __init__(self, reader: EffectivenessAdvisoryReader | None = None) -> None:
        self._reader = reader

    @property
    def configured(self) -> bool:
        return self._reader is not None

    def consult(self, environment_id: str) -> AdvisoryReadResult:
        """Return advisory context for ``environment_id``, or "unconfigured".

        Never raises, never blocks the caller beyond the reader's own
        timeout, and never returns anything Edge should treat as a directive
        -- it is read-only context for a human operator or an Action
        Arbiter's situational display, not an input to ``ActionArbiter``
        policy evaluation.
        """

        if self._reader is None:
            return AdvisoryReadResult(
                available=False, advisory=None, reason="unconfigured"
            )
        return self._reader.get_advisory(environment_id)
