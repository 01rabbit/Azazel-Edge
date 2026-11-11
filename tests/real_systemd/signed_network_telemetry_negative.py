"""Pure SYNTHETIC invalid-authentication fixture; never a producer/execution fact.

No IO, private-key access, source signing, role authority or admission. A future
reviewed Root controller may inject this only into its separate owned negative
scope. The standard wire has no fixture field; the immutable wrapper labels it.
"""

from dataclasses import dataclass, field
import re
import uuid

from azazel_edge.outcome.input_auth import TrustPolicy, SOURCE_SCHEMA
from azazel_edge.outcome.journal import OutcomeJournalError, ZERO_HASH, _json

EXPECTED_REFUSAL = "authentication signature invalid"
# Well-formed 64-byte hexadecimal signature, but S is noncanonical (>= group order).
# No private key or real signer is used; this cannot be a valid Ed25519 signature.
INVALID_SIGNATURE = "ff" * 64


@dataclass(frozen=True)
class SyntheticPrepare:
    wire: bytes = field(repr=False)
    fixture_kind: str = field(init=False, default="SYNTHETIC_INVALID_SIGNATURE_PREPARE")
    expected_refusal: str = field(init=False, default=EXPECTED_REFUSAL)


def synthetic_prepare_frame(policy, *, kernel_boot_id, session_ref):
    """One context-correct prepare envelope, deliberately unauthenticatable.

    Uses only a current public v3 policy, actual raw boot UUID and caller's fresh
    lowercase native session ID. It creates no lifecycle/sequence acceptance.
    """
    if type(policy) is not TrustPolicy:
        raise OutcomeJournalError("explicit public TrustPolicy required")
    data = policy.data
    if (
        data["schema_version"] != "outcome-input-trust/v3"
        or [data[k] for k in ("producer_uid", "observer_uid", "witness_uid")]
        != [61001, 61002, 0]
        or type(kernel_boot_id) is not str
        or str(uuid.UUID(kernel_boot_id)) != kernel_boot_id
        or type(session_ref) is not str
        or re.fullmatch("[0-9a-f]{32}", session_ref) is None
    ):
        raise OutcomeJournalError("fixed synthetic public context required")
    origin = dict(
        schema_version="outcome-registered-origin/v2",
        registration_sha256=data["origin_registration_sha256"],
        mode="live-core",
        session_ref=session_ref,
        seq=0,
        kind="session_prepare",
    )
    event = dict(
        pipeline="rust_live_origin_v1",
        source="capture_producer",
        capture_lifecycle=dict(state="prepare"),
        capture_origin=origin,
    )
    wire = dict(
        schema_version=SOURCE_SCHEMA,
        **{k: data[k] for k in ("scope_ref", "producer_ref", "stream_ref")},
        boot_ref=kernel_boot_id.replace("-", ""),
        seq=1,
        prev=ZERO_HASH,
        event=event,
        signature=INVALID_SIGNATURE,
    )
    return SyntheticPrepare(_json(wire) + b"\n")
