"""Current public Root configuration continuity ONLY, not source admission.

Only two fixed public files are read. Paths in their public context are metadata,
never selectors for additional reads. The unchanged observer API remains the
actual cryptographic/configuration-validity gate after GO.
"""

import hashlib
import os

from signed_network_plan import g, need, strict
from azazel_edge.outcome.input_auth import TrustPolicy, read_regular

FLAG = "EDGE_SIGNED_NETWORK_TELEMETRY"


def public_auth_binding():
    """Sample protected public config; never open a key, source or endpoint.

    Returned hashes describe observed bytes, not JSON authentication, an atomic
    pair snapshot, observer-label binding or authority to proceed. In particular
    the configured enrollment digest is retained separately from origin raw SHA.
    """
    g.guard()
    need(
        os.geteuid() == 0 and os.environ.get(FLAG) == "1",
        "explicit Root v2 binding required",
    )
    trust_raw, _ = read_regular(g.BUNDLE / "trust.json", owner=0, max_bytes=8192)
    origin_raw, _ = read_regular(g.BUNDLE / "origin.json", owner=0, max_bytes=16384)
    trust = TrustPolicy(
        strict(trust_raw)
    )  # Pure public-schema parser, no role endpoint.
    data = trust.data
    origin = strict(origin_raw)
    need(
        data["schema_version"] == "outcome-input-trust/v3"
        and [data[k] for k in ("producer_uid", "observer_uid", "witness_uid")]
        == [61001, 61002, 0],
        "fixed public trust role context required",
    )
    need(
        type(origin) is dict
        and origin.get("schema_version") == "outcome-live-origin-registration/v4"
        and origin.get("mode") == "live-core"
        and all(
            origin.get(k) == data[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        ),
        "public origin context differs",
    )
    return dict(
        scope="public_root_config_continuity_only",
        trust_file_sha256=hashlib.sha256(trust_raw).hexdigest(),
        origin_file_sha256=hashlib.sha256(origin_raw).hexdigest(),
        trust_sha256=trust.digest,
        trust_schema=data["schema_version"],
        origin_schema=origin["schema_version"],
        origin_mode=origin["mode"],
        **{
            k: data[k]
            for k in (
                "scope_ref",
                "source_path",
                "journal_directory",
                "origin_registration_sha256",
                "producer_uid",
                "observer_uid",
                "witness_uid",
            )
        },
    )
