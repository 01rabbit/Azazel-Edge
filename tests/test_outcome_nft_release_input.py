"""Real nft flow-limit release identity must not be forced into legacy tc."""

from dataclasses import replace
import pytest
from test_outcome_release_g1b import release_event, owned_event
from azazel_edge.outcome import (
    from_rust_release_event,
    from_rust_event,
    reconcile_release_evidence,
)
from azazel_edge.outcome.release_evidence import _release_ownership
from azazel_edge.outcome.input_resume import decode_input
from azazel_edge.outcome.journal import _json


def event(status="released", verified=True):
    value = release_event("throttle", status=status, verified=verified)
    value["release"].update(
        resource_key="nft:inet:azazel_edge:throttle:198.18.0.3>198.18.0.1:tcp:22",
        tc_handle="",
    )
    return value


@pytest.mark.parametrize(
    "flow",
    [
        "198.18.0.3>198.18.0.1:tcp:22",
        "198.18.0.3>198.18.0.1:udp:53",
        "198.18.0.3>198.18.0.1:icmp:0",
        "2001:db8::1>2001:db8::2:tcp:22",
        "2001:db8::1>2001:db8::2:ipv6-icmp:0",
    ],
)
def test_nft_release_decodes_without_a_fabricated_tc_handle(flow):
    value = event()
    value["release"]["resource_key"] = "nft:inet:azazel_edge:throttle:" + flow
    record = from_rust_release_event(value)
    assert record.tc_handle == ""
    assert _release_ownership(record) == {
        "kind": "nft_comment",
        "value": record.owner_token,
    }
    assert decode_input(_json(value)) == value


@pytest.mark.parametrize(
    "flow",
    [
        "198.18.0.3",
        "198.18.0.3>:tcp:22",
        "198.18.0.3>198.18.0.1:tcp:0",
        "198.18.0.3>198.18.0.1:tcp:022",
        "198.18.0.3>198.18.0.1:udp:65536",
        "198.18.0.3>198.18.0.1:icmp:22",
        "198.18.0.3>198.18.0.1:ipv6-icmp:0",
        "198.18.0.3>2001:db8::1:tcp:22",
        "2001:db8::1%eth0>2001:db8::2:tcp:22",
        "2001:db8::1>2001:db8::2:icmp:0",
        "198.18.0.3>198.18.0.1:sctp:22",
    ],
)
def test_malformed_or_widened_flow_never_advances_input(flow):
    value = event()
    value["release"]["resource_key"] = "nft:inet:azazel_edge:throttle:" + flow
    with pytest.raises(ValueError):
        from_rust_release_event(value)
    with pytest.raises(OSError, match="position not advanced"):
        decode_input(_json(value))


@pytest.mark.parametrize(
    "fault", ["wrong_chain", "tc_handle", "owner", "unverified", "missing_resource"]
)
def test_provider_confusion_owner_mismatch_and_unverified_release_refuse(fault):
    value = event()
    if fault == "wrong_chain":
        value["release"]["resource_key"] = value["release"]["resource_key"].replace(
            ":throttle:", ":input:"
        )
    if fault == "tc_handle":
        value["release"]["tc_handle"] = "1a:"
    if fault == "owner":
        value["release"]["owner_token"] = "azazel-edge:release-other"
    if fault == "unverified":
        value["release"]["postcondition"]["verified"] = False
    if fault == "missing_resource":
        value["release"]["resource_key"] = "test-resource"
    with pytest.raises(ValueError):
        from_rust_release_event(value)


def test_retry_is_not_release_and_unobserved_mechanism_is_not_promoted():
    native = owned_event("throttle")
    metadata = native["enforcement"]["metadata"]
    metadata.update(
        release_resource_key=event()["release"]["resource_key"], release_tc_handle=""
    )
    token = metadata["release_owner_token"]
    native["enforcement"]["command_plan"] = [
        f"nft insert rule inet azazel_edge throttle ip saddr 198.18.0.3 ip daddr 198.18.0.1 tcp dport 22 limit rate over 16 kbytes/second burst 16 kbytes drop comment {token}"
    ]
    bundle = from_rust_event(native)
    for value in [event(), event("retry_pending", False)]:
        execution, mechanism = reconcile_release_evidence(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            release=from_rust_release_event(value),
        )
        assert execution == bundle.execution and mechanism == bundle.mechanism
    with pytest.raises(ValueError, match="resource key"):
        bad = replace(
            from_rust_release_event(event()),
            resource_key="nft:inet:azazel_edge:throttle:198.18.0.4>198.18.0.1:tcp:22",
        )
        reconcile_release_evidence(
            execution=bundle.execution, mechanism=bundle.mechanism, release=bad
        )
