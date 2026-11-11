"""Strict native nft scope/read-only evidence; no host commands or activation."""

import copy
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shlex
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from azazel_edge.outcome import (
    from_rust_event,
    verify_mechanism_postcondition,
    ReadOnlyCommandResult,
)
from azazel_edge.outcome import nft_flow_evidence as flow
from azazel_edge.outcome.ownership import expected_ownership
from azazel_edge.outcome.postcondition import (
    SubprocessReadOnlyRunner,
    ReadOnlyCommandRejected,
)


def event(protocol="tcp", ipv6=False, quote="bare"):
    src, dst = ("2001:db8::2", "2001:db8::3") if ipv6 else ("10.91.1.2", "10.91.3.2")
    proto = {"icmp6": "ipv6-icmp", "icmpv6": "ipv6-icmp"}.get(protocol, protocol)
    family = "ip6" if ipv6 else "ip"
    port = 18080 if proto in ("tcp", "udp") else 0
    trace = "trace-0x2817f5fb332b839"
    resource = f"nft:inet:azazel_edge:throttle:{src}>{dst}:{proto}:{port}"
    # Default task is retained from the actual v3 native execution, not inferred
    # from a matching readback marker. Other variants exercise native grammar.
    task = (
        "release-321a3b3e005366df"
        if protocol == "tcp" and not ipv6
        else flow._task(trace, resource)
    )
    owner = "azazel-edge:" + task
    token = owner if quote == "bare" else json.dumps(owner)
    if quote == "nested":
        token = shlex.quote(token)
    selector = f"{proto} dport {port}" if port else f"meta l4proto {proto}"
    command = f"nft insert rule inet azazel_edge throttle {family} saddr {src} {family} daddr {dst} {selector} limit rate over 16 kbytes/second burst 16 kbytes drop comment {token}"
    return dict(
        pipeline="rust_event_engine_v1",
        source="suricata_eve",
        normalized=dict(
            ts="2026-11-11T09:00:00+00:00",
            src_ip=src,
            dst_ip=dst,
            protocol=protocol.upper(),
            target_port=port,
            sid=393001,
        ),
        defense=dict(action="throttle", target=src, policy_reason="test"),
        enforcement=dict(
            mode="enforced",
            result="applied",
            trace_id=trace,
            selected_action="throttle",
            target=src,
            policy_reason="test",
            command_plan=[command],
            rollback_plan=[
                f"nft delete rule inet azazel_edge throttle handle '<owned:{owner}>'"
            ],
            executed_count=1,
            failed_count=0,
            errors=[],
            metadata=dict(
                release_task_id=task,
                release_owner_token=owner,
                release_resource_key=resource,
                release_due_epoch=1794387630.0,
                release_tc_handle="",
                release_ledger_state="active",
            ),
        ),
    )


def payload(scope):
    family = scope["family"]
    proto = scope["protocol"]
    matches = [
        {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": family, "field": field}},
                "right": scope[key],
            }
        }
        for field, key in (("saddr", "source_ip"), ("daddr", "destination_ip"))
    ]
    selector = (
        {"payload": {"protocol": proto, "field": "dport"}}
        if proto in ("tcp", "udp")
        else {"meta": {"key": "l4proto"}}
    )
    matches.append(
        {
            "match": {
                "op": "==",
                "left": selector,
                "right": scope["destination_port"]
                if proto in ("tcp", "udp")
                else proto,
            }
        }
    )
    rule = dict(
        family="inet",
        table="azazel_edge",
        chain="throttle",
        handle=5,
        comment=scope["owner_token"],
        expr=matches
        + [
            {
                "limit": dict(
                    rate=16,
                    rate_unit="kbytes",
                    burst=16,
                    burst_unit="kbytes",
                    per="second",
                    inv=True,
                )
            },
            {"drop": None},
        ],
    )
    chain = dict(
        family="inet",
        table="azazel_edge",
        name="throttle",
        handle=3,
        type="filter",
        hook="prerouting",
        prio=-150,
        policy="accept",
    )
    return {
        "nftables": [
            {"metainfo": {"version": "synthetic"}},
            {"chain": chain},
            {"rule": rule},
        ]
    }


class Runner:
    def __init__(self, data=None, *, code=0, error=None, raw=None):
        self.data = data
        self.code = code
        self.error = error
        self.raw = raw
        self.calls = []

    def run(self, argv, *, timeout_seconds):
        self.calls.append(tuple(argv))
        if self.error:
            raise self.error
        return ReadOnlyCommandResult(
            argv=tuple(argv),
            returncode=self.code,
            stdout=self.raw if self.raw is not None else json.dumps(self.data),
            stderr="",
        )


def verify(bundle, runner):
    return verify_mechanism_postcondition(
        execution=bundle.execution,
        mechanism=bundle.mechanism,
        runner=runner,
        observed_at="2026-11-11T09:00:01+00:00",
    )


@pytest.mark.parametrize(
    "protocol,ipv6",
    [
        ("tcp", False),
        ("udp", False),
        ("icmp", False),
        ("tcp", True),
        ("udp", True),
        ("ipv6-icmp", True),
        ("icmp6", True),
        ("icmpv6", True),
    ],
)
@pytest.mark.parametrize("quote", ["bare", "quoted", "nested"])
def test_exact_owned_native_flow_is_truthfully_scoped_and_observed(
    protocol, ipv6, quote
):
    b = from_rust_event(event(protocol, ipv6, quote))
    before = asdict(b.execution)
    assert b.mechanism.status.value == "unverified"
    assert b.mechanism.scope["scope_kind"] == flow.SCOPE_KIND
    assert "interface" not in b.mechanism.scope
    runner = Runner(payload(b.mechanism.scope))
    observed = verify(b, runner)
    assert observed.status.value == "observed"
    assert runner.calls == [flow.QUERY] and asdict(b.execution) == before
    assert expected_ownership(b.execution) == {
        "kind": "nft_comment",
        "value": b.mechanism.scope["owner_token"],
    }


@pytest.mark.parametrize(
    "fault",
    [
        "extra_command",
        "nonstring",
        "bad_owner",
        "bad_task",
        "bad_resource",
        "bad_rollback",
        "missing_metadata",
        "missing_port",
        "wrong_normalized_proto",
        "family",
        "rate_zero",
        "extra_selector",
        "shell",
        "boolean_count",
    ],
)
def test_unverifiable_native_plan_never_becomes_root_scope_or_queries(fault):
    e = event()
    a = e["enforcement"]
    m = a["metadata"]
    if fault == "extra_command":
        a["command_plan"].append(
            "tc qdisc replace dev br0 root tbf rate 256kbit burst 32kbit latency 1000ms"
        )
    elif fault == "nonstring":
        a["command_plan"].append(1)
    elif fault == "bad_owner":
        m["release_owner_token"] = "azazel-edge:release-" + "f" * 16
    elif fault == "bad_task":
        m["release_task_id"] = "release-" + "f" * 16
    elif fault == "bad_resource":
        m["release_resource_key"] += ":other"
    elif fault == "bad_rollback":
        a["rollback_plan"][0] = a["rollback_plan"][0].replace("throttle", "input")
    elif fault == "missing_metadata":
        a["metadata"] = {}
    elif fault == "missing_port":
        e["normalized"]["target_port"] = 0
    elif fault == "wrong_normalized_proto":
        e["normalized"]["protocol"] = "UDP"
    elif fault == "family":
        a["command_plan"][0] = a["command_plan"][0].replace(" ip ", " ip6 ")
    elif fault == "rate_zero":
        a["command_plan"][0] = a["command_plan"][0].replace("over 16", "over 0")
    elif fault == "extra_selector":
        a["command_plan"][0] = a["command_plan"][0].replace(
            " limit", " tcp dport 22 limit"
        )
    elif fault == "shell":
        a["command_plan"][0] += "; true"
    else:
        a["executed_count"] = True
    b = from_rust_event(e)
    runner = Runner(error=AssertionError("unverifiable plan queried"))
    assert b.mechanism.scope["scope_kind"] == flow.UNKNOWN_SCOPE
    assert verify(b, runner).status.value == "unverified" and not runner.calls


@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "destination",
        "port",
        "rate",
        "burst",
        "under",
        "time",
        "foreign_owner",
    ],
)
def test_complete_but_different_postcondition_is_not_observed(fault):
    b = from_rust_event(event())
    data = payload(b.mechanism.scope)
    rule = data["nftables"][2]["rule"]
    expr = rule["expr"]
    if fault == "source":
        expr[0]["match"]["right"] = "10.91.1.99"
    elif fault == "destination":
        expr[1]["match"]["right"] = "10.91.3.99"
    elif fault == "port":
        expr[2]["match"]["right"] = 22
    elif fault == "rate":
        expr[3]["limit"]["rate"] = 32
    elif fault == "burst":
        expr[3]["limit"]["burst"] = 32
    elif fault == "under":
        expr[3]["limit"]["inv"] = False
    elif fault == "time":
        expr[3]["limit"]["per"] = "minute"
    else:
        rule["comment"] = "azazel-edge:release-" + "f" * 16
    assert verify(b, Runner(data)).status.value == "not_observed"


@pytest.mark.parametrize(
    "fault",
    [
        "missing_chain",
        "wrong_hook",
        "wrong_priority",
        "wrong_policy",
        "wrong_chain_type",
        "missing_chain_handle",
        "wrong_family",
        "duplicate_chain",
        "duplicate_owner",
        "duplicate_handle",
        "no_handle",
        "extra_match",
        "extra_verdict",
        "order",
        "unknown_unit",
        "bad_type",
        "wrong_proto",
        "conflicting_match",
        "unknown_entry",
        "unknown_owned_key",
        "non_equality",
    ],
)
def test_ambiguous_or_unknown_readback_remains_unverified(fault):
    b = from_rust_event(event())
    data = payload(b.mechanism.scope)
    chain = data["nftables"][1]["chain"]
    rule = data["nftables"][2]["rule"]
    expr = rule["expr"]
    if fault == "missing_chain":
        data["nftables"].pop(1)
    elif fault == "wrong_hook":
        chain["hook"] = "input"
    elif fault == "wrong_priority":
        chain["prio"] = -100
    elif fault == "wrong_policy":
        chain["policy"] = "drop"
    elif fault == "missing_chain_handle":
        del chain["handle"]
    elif fault == "wrong_chain_type":
        chain["type"] = "nat"
    elif fault == "wrong_family":
        chain["family"] = "ip"
    elif fault == "duplicate_chain":
        data["nftables"].append({"chain": copy.deepcopy(chain)})
    elif fault == "duplicate_owner":
        other = copy.deepcopy(rule)
        other["handle"] = 7
        data["nftables"].append({"rule": other})
    elif fault == "duplicate_handle":
        other = copy.deepcopy(rule)
        other["comment"] = "foreign"
        data["nftables"].append({"rule": other})
    elif fault == "no_handle":
        del rule["handle"]
    elif fault == "extra_match":
        expr.insert(1, copy.deepcopy(expr[0]))
    elif fault == "extra_verdict":
        expr.append({"accept": None})
    elif fault == "order":
        expr[2], expr[3] = expr[3], expr[2]
    elif fault == "unknown_unit":
        expr[3]["limit"]["rate_unit"] = "packets"
    elif fault == "bad_type":
        expr[3]["limit"]["rate"] = True
    elif fault == "wrong_proto":
        expr[2]["match"]["left"]["payload"]["protocol"] = "udp"
    elif fault == "conflicting_match":
        expr.append(copy.deepcopy(expr[2]))
    elif fault == "unknown_entry":
        data["nftables"].append({"unknown": {}})
    elif fault == "unknown_owned_key":
        rule["unexpected"] = 1
    else:
        expr[0]["match"]["op"] = "!="
    assert verify(b, Runner(data)).status.value == "unverified"


@pytest.mark.parametrize(
    "fault", ["scope", "release_ref", "target", "metadata", "plan", "provider_count"]
)
def test_execution_and_mechanism_binding_is_checked_before_query(fault):
    b = from_rust_event(event())
    if fault == "scope":
        b = replace(
            b,
            mechanism=replace(
                b.mechanism, scope={**b.mechanism.scope, "source_ip": "10.91.1.99"}
            ),
        )
    elif fault == "release_ref":
        b = replace(b, execution=replace(b.execution, release_ref="different"))
    elif fault == "target":
        b = replace(
            b,
            execution=replace(
                b.execution,
                requested_parameters={
                    **b.execution.requested_parameters,
                    "target": "10.91.1.99",
                },
            ),
        )
    elif fault == "metadata":
        parameters = copy.deepcopy(b.execution.applied_parameters)
        parameters["metadata"]["release_owner_token"] = "wrong"
        b = replace(b, execution=replace(b.execution, applied_parameters=parameters))
    elif fault == "plan":
        parameters = copy.deepcopy(b.execution.requested_parameters)
        parameters["command_plan"][0] += " counter"
        b = replace(b, execution=replace(b.execution, requested_parameters=parameters))
    else:
        parameters = {**b.execution.applied_parameters, "executed_count": 2}
        b = replace(b, execution=replace(b.execution, applied_parameters=parameters))
    runner = Runner(error=AssertionError("binding failed before readback"))
    assert verify(b, runner).status.value == "unverified" and not runner.calls


@pytest.mark.parametrize(
    "raw",
    [
        "{}",
        "{",
        '{"nftables":[],"nftables":[]}',
        '{"nftables":[],"x":NaN}',
        '{"nftables":[],"x":1e999}',
    ],
)
def test_malformed_or_duplicate_json_remains_unverified(raw):
    assert (
        verify(from_rust_event(event()), Runner(raw=raw)).status.value == "unverified"
    )


def test_permission_failure_and_command_exit_never_promote():
    b = from_rust_event(event())
    assert verify(b, Runner({}, code=1)).status.value == "unverified"
    assert (
        verify(b, Runner(error=PermissionError("no NET_ADMIN"))).status.value
        == "unverified"
    )
    assert verify(b, Runner({"nftables": []})).status.value == "unverified"


def test_new_query_allowlist_is_exact_and_still_read_only():
    with (
        patch(
            "azazel_edge.outcome.postcondition.shutil.which",
            return_value="/usr/sbin/nft",
        ),
        patch(
            "azazel_edge.outcome.postcondition.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="{}", stderr=""),
        ) as run,
    ):
        SubprocessReadOnlyRunner().run(flow.QUERY, timeout_seconds=1)
        assert run.call_args.kwargs["shell"] is False
        assert run.call_args.kwargs["env"]["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
    for args in [
        ("nft", "-j", "list", "chain", "inet", "other", "throttle"),
        ("nft", "-j", "list", "chain", "inet", "azazel_edge", "arbitrary"),
        ("nft", "delete", "table", "inet", "azazel_edge"),
    ]:
        with pytest.raises(ReadOnlyCommandRejected):
            SubprocessReadOnlyRunner().run(args, timeout_seconds=1)


def test_recorded_actual_v3_rule_without_header_cannot_be_promoted():
    directory = os.environ.get("EDGE_NFT_FLOW_RECORDED_DIR")
    if not directory:
        pytest.skip("optional retained actual v3 native event/rule, no runtime")
    folder = Path(directory)
    events = [
        json.loads(line)
        for line in (folder / "events-1.jsonl").read_text().splitlines()
    ]
    e = next(e for e in events if e.get("pipeline") == "rust_event_engine_v1")
    b = from_rust_event(e)
    assert b.mechanism.scope["scope_kind"] == flow.SCOPE_KIND
    assert b.mechanism.scope["release_task_id"] == "release-321a3b3e005366df"
    actual = json.loads((folder / "independent_rule_readback.json").read_text())
    assert (
        verify(b, Runner({"nftables": [{"rule": actual}]})).status.value == "unverified"
    )


def test_scoped_ipv6_literals_not_supported_by_native_are_unverifiable():
    value = event("tcp", True)
    value["enforcement"]["command_plan"][0] = value["enforcement"]["command_plan"][
        0
    ].replace("2001:db8::2", "2001:db8::2%es")
    bundle = from_rust_event(value)
    assert bundle.mechanism.scope["scope_kind"] == flow.UNKNOWN_SCOPE
    runner = Runner(error=AssertionError("invalid scope queried"))
    assert verify(bundle, runner).status.value == "unverified" and not runner.calls


def test_wrong_query_receipt_never_promotes_matching_payload():
    b = from_rust_event(event())

    class WrongReceipt:
        def run(self, argv, *, timeout_seconds):
            return ReadOnlyCommandResult(
                argv=("nft", "-j", "list", "chain", "inet", "azazel_edge", "input"),
                returncode=0,
                stdout=json.dumps(payload(b.mechanism.scope)),
                stderr="",
            )

    assert verify(b, WrongReceipt()).status.value == "unverified"


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "dry_run"},
        {"result": "partial_failure"},
        {"executed_count": True},
        {"failed_count": False},
    ],
)
def test_manually_conflicting_applied_provider_receipt_is_not_probed(change):
    b = from_rust_event(event())
    b = replace(
        b,
        execution=replace(
            b.execution, applied_parameters={**b.execution.applied_parameters, **change}
        ),
    )
    runner = Runner(error=AssertionError("conflicting provider receipt queried"))
    assert verify(b, runner).status.value == "unverified" and not runner.calls
