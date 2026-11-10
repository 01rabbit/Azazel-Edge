"""Registered-key policy is pinned in authenticated source and journal context."""

import pytest

pytest.importorskip("cryptography")
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
from auth_input_helpers import make_policy
from test_outcome_input_auth import signed
from test_outcome_telemetry_g3 import rust_event


def enrolled(tmp_path):
    p, key, *_ = make_policy(tmp_path)
    return (
        TrustPolicy(
            {
                **dict(p.data),
                "schema_version": "outcome-input-trust/v2",
                "origin_registration_sha256": "1" * 64,
            }
        ),
        key,
    )


def readonly_event():
    event = rust_event(ts="2026-01-01T00:00:00Z", trace="origin")
    event.update(source="suricata_eve", pipeline="rust_event_engine_v1")
    event["enforcement"].update(
        mode="dry_run",
        result="dry_run",
        executed_count=0,
        failed_count=0,
        command_plan=[],
        rollback_plan=[],
        errors=[],
        metadata={"capture_only": True},
    )
    event["enforcement_status"] = dict(
        enforce_enabled=False,
        dry_run=True,
        high_impact_auto=False,
        enforce_level="advisory",
        allowed_actions=[],
    )
    return event


def marker(offset=100):
    return dict(
        schema_version="outcome-registered-origin/v1",
        registration_sha256="1" * 64,
        mode="readonly-core",
        raw_cursor=dict(offset=offset, prefix_sha256="2" * 64),
    )


@pytest.mark.parametrize(
    "fault",
    ["missing", "registration", "mode", "extra", "cursor", "hash", "bool", "overflow"],
)
def test_valid_signature_cannot_bypass_origin_registration(tmp_path, fault):
    p, key = enrolled(tmp_path)
    event = readonly_event()
    m = marker()
    if fault == "registration":
        m["registration_sha256"] = "3" * 64
    if fault == "mode":
        m["mode"] = "enforced"
    if fault == "extra":
        m["other"] = 0
    if fault == "cursor":
        m["raw_cursor"]["offset"] = 0
    if fault == "hash":
        m["raw_cursor"]["prefix_sha256"] = "no"
    if fault == "bool":
        m["raw_cursor"]["offset"] = True
    if fault == "overflow":
        m["raw_cursor"]["offset"] = p.data["input_max_bytes"] + 1
    if fault != "missing":
        event["capture_origin"] = m
    with pytest.raises(OSError):
        SourceVerifier(p).verify(signed(p, key, event=event))


def test_registered_raw_position_and_trust_binding(tmp_path):
    p, key = enrolled(tmp_path)
    v = SourceVerifier(p)
    event = readonly_event()
    event["capture_origin"] = marker()
    first = signed(p, key, event=event)
    v.verify(first)
    for offset in (99, 100):
        event["capture_origin"] = marker(offset)
        with pytest.raises(OSError):
            v.verify(first + signed(p, key, seq=2, prev=v.head, event=event))
    event["capture_origin"] = marker(101)
    v.verify(first + signed(p, key, seq=2, prev=v.head, event=event))
    altered = dict(p.data)
    altered["origin_registration_sha256"] = "4" * 64
    assert TrustPolicy(altered).binding() != p.binding()
    with pytest.raises(OSError):
        TrustPolicy(
            {k: x for k, x in dict(p.data).items() if k != "origin_registration_sha256"}
        )
    with pytest.raises(OSError):
        TrustPolicy({**dict(p.data), "schema_version": "outcome-input-trust/v1"})


@pytest.mark.parametrize(
    "output",
    [
        "print('{}')",
        "print('x'*65537)",
        "print('null');raise SystemExit(1)",
        "print('{}');print('{}')",
        "print('{')",
        "import time;time.sleep(10)",
    ],
)
def test_private_pipe_faults_are_bounded_and_child_reaped(output):
    import subprocess
    import sys
    from unittest.mock import patch
    from azazel_edge.outcome.input_origin import RegisteredOrigin

    origin = RegisteredOrigin.__new__(RegisteredOrigin)
    origin.fd = 123  # Replaced only in this injected child transport.
    real = subprocess.Popen
    children = []

    def injected(argv, **kwargs):
        assert argv == ["/proc/self/fd/123", "--capture-origin-once"]
        assert kwargs["env"] == {"PATH": "/nonexistent"}
        kwargs.pop("pass_fds")
        child = real([sys.executable, "-c", output], **kwargs)
        children.append(child)
        return child

    with patch(
        "azazel_edge.outcome.input_origin.subprocess.Popen", side_effect=injected
    ):
        with pytest.raises((OSError, subprocess.SubprocessError)):
            origin.transform(b'{"event_type":"alert"}\n')
    assert children and children[0].poll() is not None


@pytest.mark.parametrize("fault", ["applied", "plan", "enabled", "count", "shape"])
def test_signed_readonly_origin_cannot_claim_execution(tmp_path, fault):
    p, key = enrolled(tmp_path)
    event = readonly_event()
    event["capture_origin"] = marker()
    if fault == "applied":
        event["enforcement"]["result"] = "applied"
    elif fault == "plan":
        event["enforcement"]["command_plan"] = ["tc fake"]
    elif fault == "enabled":
        event["enforcement_status"]["enforce_enabled"] = True
    elif fault == "count":
        event["enforcement"]["executed_count"] = False
    else:
        event["enforcement"] = []
    with pytest.raises(OSError):
        SourceVerifier(p).verify(signed(p, key, event=event))
