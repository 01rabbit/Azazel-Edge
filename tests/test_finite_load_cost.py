"""Synthetic custody and public TEST keys; never real Linux load evidence."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from azazel_edge.benchmark import finite_load_cost as cost
from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
from azazel_edge.outcome.journal import _json
from test_finite_ingress import fixture as old_fixture, change_source
from test_native_close_receipts import obj, rewrite, stream, wire
from safety_observation_data import digest

ROOT = Path(__file__).parent / "real_systemd"


def fixture():
    a, c, root, ic = old_fixture()
    raw, manifest = cost.materialize_corpus()
    case = "load-off"
    registration = json.loads(a["registration.json"])
    registration["environment"]["AZAZEL_LIVE_ORIGIN_LOAD_COST"] = "v1"
    policy = TrustPolicy(
        {
            **json.loads(a["trust.json"]),
            "origin_registration_sha256": digest(_json(registration)),
        }
    )
    c.update(
        case_id=case,
        protocol_sha256=cost.PROTOCOL_SHA256,
        trust_sha256=policy.digest,
        registration_sha256=policy.data["origin_registration_sha256"],
    )
    c["root_custody"]["relative_name"] = (
        "close-custody/" + case + "-" + "a" * 32 + ".raw"
    )
    a.update(
        {
            "protocol.json": (ROOT / "finite-load-cost-protocol-v1.json").read_bytes(),
            "registration.json": _json(registration),
            "trust.json": _json(dict(policy.data)),
            "code-pins.json": wire(
                {
                    k: c[k]
                    for k in ("source_revision", "protocol_sha256", "core_image_sha256")
                }
            ),
        }
    )
    root.update(
        schema_version="outcome-live-close-custody/v3",
        registration_sha256=c["registration_sha256"],
        trust_sha256=policy.digest,
    )

    def empty_cost(names):
        return dict(
            schema_version="azazel-edge/phase-cost/v1",
            complete=True,
            invalid_reason=None,
            phases={
                n: dict(
                    count=1, wall_ns=5, process_cpu_ns=2, thread_cpu_ns=1, max_wall_ns=5
                )
                for n in names
            },
        )

    native = json.loads(a["native-close.raw"])
    native.update(
        schema_version="outcome-native-close-receipt/v3",
        cost=empty_cost(("poll_total", "committed_hash", "admitted_callback")),
    )
    native["ingress"].update(
        committed_end_offset=len(raw),
        last_observed_length=len(raw),
        committed_bytes=len(raw),
        committed_sha256=digest(raw),
    )
    native["ingress"]["counts"].update(
        examined=27007,
        admitted=27007,
        alerts_admitted=3,
        normalized_decisions=3,
        blank=0,
        admitted_without_source=27004,
    )
    a["native-close.raw"] = wire(native)
    root["native_stream"] = stream(a["native-close.raw"])
    receiver = json.loads(a["receiver-close.raw"][15:])
    receiver.update(
        schema_version="outcome-live-receiver-close-receipt/v2",
        registration_sha256=c["registration_sha256"],
        trust_sha256=policy.digest,
        cost=empty_cost(
            (
                "receive_wait",
                "frame_validation",
                "source_append",
                "source_sign",
                "source_verify",
                "source_fsync",
            )
        ),
    )
    a["receiver-close.raw"] = b'{"ready":true}\n' + wire(receiver)
    root["receiver_stream"] = stream(a["receiver-close.raw"])

    def events(rows):
        decisions = [
            e for e in rows if e["capture_origin"]["kind"] == "decision_execution"
        ]
        rows.remove(decisions[-1])
        for seq, e in enumerate(rows):
            e["capture_origin"]["seq"] = seq
            e["capture_origin"]["registration_sha256"] = c["registration_sha256"]
            if e["capture_origin"]["kind"] == "session_end":
                for k in ("admitted", "enqueued", "produced", "written"):
                    e["capture_lifecycle"]["counts"][k] = 3
        for e, m in zip(decisions[:3], manifest["markers"]):
            e["normalized"]["sid"] = m["sid"]
            e["ingress_origin"] = dict(
                schema_version="azazel-edge/ingress-origin/v1",
                range_ref=c["session_ref"],
                device=8,
                inode=777,
                start_offset=m["start_offset"],
                end_offset=m["end_offset"],
                raw_sha256=m["raw_sha256"],
            )

    change_source(a, c, root, events)
    rewrite(a, c, root)
    initial, final = obj(777, 0, b"", 0o644), obj(777, 0, raw, 0o644)
    for name, body, meta in (
        ("eve-start.raw", b"", initial),
        ("eve-after-writer.raw", raw, final),
        ("eve-held-final.raw", raw, final),
        ("eve-path-final.raw", raw, final),
    ):
        a[name] = body
        ic["snapshots"][name] = dict(
            before=deepcopy(meta),
            after=deepcopy(meta),
            sha256=digest(body),
            size=len(body),
            fd=5,
            flags=0,
        )
    ic.update(case_id=case, protocol_sha256=cost.PROTOCOL_SHA256)
    ic["held_fd"]["object"] = initial
    ic["writer"][0].update(
        before=initial,
        after=final,
        offset_after=len(raw),
        requested_bytes=len(raw),
        written_bytes=len(raw),
        write_calls=27007,
    )
    tip = SourceVerifier(policy).verify(a["source-before.raw"])
    ic["markers"] = [
        dict(
            kind="source",
            sid=90232003,
            occurrence=1,
            observed_ns=140,
            session_ref=c["session_ref"],
            range_ref=c["session_ref"],
            source_checkpoint=tip,
            ingress_origin=dict(
                schema_version="azazel-edge/ingress-origin/v1",
                range_ref=c["session_ref"],
                device=8,
                inode=777,
                **{
                    k: manifest["markers"][-1][k]
                    for k in ("start_offset", "end_offset", "raw_sha256")
                },
            ),
            normalized_log_checkpoint=None,
        )
    ]
    ic["finished_ns"] = c["finished_ns"] = 10_000_000_000
    ic["held_fd"]["closed_ns"] = 10_000_000_001
    ic["writer"][0].update(
        started_ns=110, finished_ns=9_001_333_443, joined_ns=9_001_333_444
    )
    a["ingress-controller.json"] = wire(ic)
    rewrite(a, c, root)
    a.update({k: None for k in cost.EXTRA_FILES})
    a["corpus-manifest.json"] = wire(manifest)
    a["load-controller.json"] = wire(
        dict(
            schema_version="edge-finite-load-controller/v1",
            case_id=case,
            protocol_sha256=cost.PROTOCOL_SHA256,
            corpus_sha256=manifest["sha256"],
            session_ref=c["session_ref"],
            started_ns=100,
            finished_ns=10_000_000_000,
            controller_identity=dict(
                pid=20,
                start_ticks=120,
                native_tid=20,
                boot_id=c["boot_id"],
                clock_ticks_per_second=100,
                clock_domain=dict(
                    time_namespace_device=1,
                    time_namespace_inode=2,
                    timens_offsets=[],
                    established=True,
                ),
                clock_resolutions={},
            ),
            controller_anchors=dict(
                before=dict(
                    monotonic_before_ns=90, epoch_ns=1000000, monotonic_after_ns=99
                ),
                after=dict(
                    monotonic_before_ns=10_000_000_001,
                    epoch_ns=10_001_000_000,
                    monotonic_after_ns=10_000_000_002,
                ),
            ),
            resources=dict.fromkeys(
                (
                    "native_before",
                    "native_after",
                    "receiver_before",
                    "receiver_after",
                    "observer_before",
                    "observer_after",
                )
            ),
            observer=None,
            errors=[],
            audits=[],
            writer=dict(
                pid=20,
                tid=21,
                fd=6,
                flags=0o2001,
                before=initial,
                after=final,
                started_ns=110,
                first_write_before_ns=110,
                marker_one_before_ns=3_000_000_110,
                final_nonalert_after_ns=9_001_333_443,
                finished_ns=9_001_333_443,
                joined_ns=9_001_333_444,
                written_bytes=len(raw),
                nonalert_records=27004,
                per_class=manifest["per_class"],
                write_calls=27007,
                fsync_completed=True,
                joined=True,
                sha256=manifest["sha256"],
                error=None,
            ),
        )
    )
    return a, c, root, ic


def evaluate(a):
    return cost.evaluate_finite_load_cost_case(
        a,
        expected={k: digest(v) if isinstance(v, bytes) else None for k, v in a.items()},
    )


def test_corpus_protocol_and_exact_ranges():
    raw, m = cost.materialize_corpus()
    assert (
        digest((ROOT / "finite-load-cost-protocol-v1.json").read_bytes())
        == cost.PROTOCOL_SHA256
    )
    assert m["bytes"] == len(raw) < 16 * 1024 * 1024
    assert m["lf_records"] == raw.count(b"\n") == 27007
    assert m["per_class"] == dict.fromkeys(cost.CLASSES, 6751)
    for marker in m["markers"]:
        span = raw[marker["start_offset"] : marker["end_offset"]]
        assert digest(span) == marker["raw_sha256"]
        assert json.loads(span)["alert"]["signature_id"] == marker["sid"]
    assert cost.materialize_corpus() == (raw, m)


def test_synthetic_bound_input_load_and_scoped_costs_keep_authority_closed():
    a, _, _, _ = fixture()
    r = evaluate(a)
    assert r["finite"]["whole_input_complete"] is True, (
        r["finite"]["reasons"],
        r["finite"]["close"]["reasons"],
    )
    assert r["load"]["status"] == r["intake"]["status"] == "qualified", r["reasons"]
    assert r["intake"]["examined_nonalert"] == 27004
    assert r["observer"] is None and r["status"] == "withheld"
    assert not any(r["authority_flags"].values())


@pytest.mark.parametrize(
    "key",
    [
        "eve-after-writer.raw",
        "native-close.raw",
        "root-custody.raw",
        "receiver-close.raw",
        "source-after.raw",
        "load-controller.json",
        "corpus-manifest.json",
    ],
)
def test_missing_original_is_not_pass_or_zero(key):
    a, _, _, _ = fixture()
    a[key] = None
    r = evaluate(a)
    assert r["status"] == "withheld"
    assert r["load"] is None or r["intake"] is None


@pytest.mark.parametrize("duration", [2_900_000_000, 20_000_000_000])
def test_actual_slow_or_short_load_fails(duration):
    a, cc, rr, ic = fixture()
    c = json.loads(a["load-controller.json"])
    c["writer"].update(
        final_nonalert_after_ns=duration, finished_ns=duration, joined_ns=duration
    )
    if duration < 3_000_000_000:
        c["writer"]["marker_one_before_ns"] = 1_000_000_000
    for key in ("finished_ns", "joined_ns"):
        ic["writer"][0][key] = c["writer"][key]
    if duration > 10_000_000_000:
        ic["finished_ns"] = cc["finished_ns"] = c["finished_ns"] = duration + 100
        ic["held_fd"]["closed_ns"] = duration + 101
        c["controller_anchors"]["after"] = dict(
            monotonic_before_ns=duration + 101,
            epoch_ns=duration + 1000000,
            monotonic_after_ns=duration + 102,
        )
    a["ingress-controller.json"] = wire(ic)
    rewrite(a, cc, rr)
    a["load-controller.json"] = wire(c)
    assert evaluate(a)["load"]["status"] == "failed"


def test_extra_envelope_and_stored_evaluation_do_not_authorize():
    a, _, _, _ = fixture()
    a["evaluation.json"] = wire(dict(status="PASS", clock="qualified"))
    r = evaluate(a)
    assert r["status"] == "withheld" and r["observer"] is None
    a["extra"] = b""
    assert evaluate(a)["finite"] is None


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_field",
        "different_fd",
        "different_pid",
        "anchor_after_start",
        "wrong_corpus",
        "missing_final_counter",
    ],
)
def test_unbound_or_incomplete_timings_cannot_qualify(mutation):
    a, _, _, _ = fixture()
    c = json.loads(a["load-controller.json"])
    if mutation == "extra_field":
        c["untrusted"] = "PASS"
    elif mutation == "different_fd":
        c["writer"]["fd"] += 1
    elif mutation == "different_pid":
        c["writer"]["pid"] += 1
    elif mutation == "anchor_after_start":
        c["controller_anchors"]["before"]["monotonic_after_ns"] = c["started_ns"] + 1
    elif mutation == "wrong_corpus":
        c["corpus_sha256"] = "f" * 64
    else:
        a["native-close.raw"] = None
    a["load-controller.json"] = wire(c)
    r = evaluate(a)
    assert r["status"] == "withheld"
    assert (r["load"] or {}).get(
        "status"
    ) != "qualified" or mutation == "missing_final_counter"
    if mutation == "missing_final_counter":
        assert r["intake"] is None
        assert r["finite"]["source_decisions"] == 3


def test_forged_pin_is_rejected_without_destroying_authenticated_source():
    a, _, _, _ = fixture()
    pins = {k: digest(v) if isinstance(v, bytes) else None for k, v in a.items()}
    a["eve-after-writer.raw"] += b"\n"
    r = cost.evaluate_finite_load_cost_case(a, expected=pins)
    assert r["load"] is None
    assert r["finite"]["source_decisions"] == 3
    assert r["pins"]["eve-after-writer.raw"] is False


@pytest.mark.parametrize(
    "cases", [None, [], [None, {}, {}], ["load-off", "load-on", "load-faulted"]]
)
def test_malformed_comparison_is_withheld(cases):
    r = cost.evaluate_finite_load_cost_comparison(cases)
    assert r["status"] == "withheld" and r["reasons"]


def test_descriptive_differences_preserve_unknown_phases_and_broad_blockers():
    a, _, _, _ = fixture()
    baseline = evaluate(a)
    cases = [deepcopy(baseline) for _ in cost.ARMS]
    for arm, c in zip(cost.ARMS, cases):
        c["case_id"] = arm
    cases[1]["native_cost"]["phases"]["poll_total"]["wall_ns"] += 10
    cases[2]["receiver_cost"]["phases"]["source_sign"] = None
    r = cost.evaluate_finite_load_cost_comparison(cases)
    assert r["status"] == "withheld" and not any(r["authority_flags"].values())
    assert r["differences"][0]["status"] == "descriptive_measured_difference"
    assert r["differences"][0]["native_cost"]["poll_total"]["wall_ns"] == 10
    assert r["differences"][1]["receiver_cost"]["source_sign"] is None
    cases[1]["native_cost"]["complete"] = False
    cases[1]["native_cost"]["invalid_reason"] = "clock_error"
    assert (
        cost.evaluate_finite_load_cost_comparison(cases)["differences"][0][
            "native_cost"
        ]
        is None
    )


def test_measured_partial_prefix_below_floor_is_adverse_not_missing_zero():
    a, c, root, ic = fixture()
    raw, manifest = cost.materialize_corpus()
    end = manifest["markers"][0]["end_offset"]
    native = json.loads(a["native-close.raw"])
    native["ingress"].update(
        committed_end_offset=end,
        committed_bytes=end,
        committed_sha256=digest(raw[:end]),
        last_stop="WorkTime",
    )
    native["ingress"]["counts"].update(
        examined=9001,
        admitted=9001,
        alerts_admitted=1,
        normalized_decisions=1,
        admitted_without_source=9000,
    )
    a["native-close.raw"] = wire(native)
    root["native_stream"] = stream(a["native-close.raw"])

    def partial(rows):
        decisions = [
            e for e in rows if e["capture_origin"]["kind"] == "decision_execution"
        ]
        for e in decisions[1:]:
            rows.remove(e)
        for seq, e in enumerate(rows):
            e["capture_origin"]["seq"] = seq
            if e["capture_origin"]["kind"] == "session_end":
                for key in ("admitted", "enqueued", "produced", "written"):
                    e["capture_lifecycle"]["counts"][key] = 1

    change_source(a, c, root, partial)
    ic["markers"] = []
    a["ingress-controller.json"] = wire(ic)
    r = evaluate(a)
    assert r["load"]["status"] == "qualified", r["reasons"]
    assert r["intake"]["status"] == "failed", (
        r["reasons"],
        r["finite"]["close"]["reasons"],
    )
    assert r["intake"]["examined_nonalert"] == 9000
    assert r["finite"]["whole_input_complete"] is False
    assert r["finite"]["source_decisions"] == 1
    assert r["status"] == "withheld"


@pytest.mark.parametrize("bad", [[], {}, None, "f" * 64])
def test_malformed_nested_corpus_pin_withholds_comparison(bad):
    a, _, _, _ = fixture()
    r = evaluate(a)
    cases = [deepcopy(r) for _ in cost.ARMS]
    for case, arm in zip(cases, cost.ARMS):
        case["case_id"] = arm
    cases[0]["corpus"]["sha256"] = bad
    result = cost.evaluate_finite_load_cost_comparison(cases)
    assert "same_actual_corpus_not_established" in result["reasons"]
    assert all(d["status"] == "withheld" for d in result["differences"])


def test_missing_end_does_not_destroy_verified_input_or_authorize_completion():
    a, _, _, _ = fixture()
    a["source-after.raw"] = a["source-before.raw"]
    r = evaluate(a)
    assert r["finite"]["close"]["selected_end_present"] is False
    assert r["finite"]["source_decisions"] == 3
    assert r["finite"]["whole_input_complete"] is not True
    assert r["status"] == "withheld"


def test_wrong_range_session_does_not_join_originals():
    a, _, _, ic = fixture()
    ic["session_ref"] = "f" * 32
    a["ingress-controller.json"] = wire(ic)
    r = evaluate(a)
    assert r["load"] is None and r["intake"] is None
    assert r["finite"]["whole_input_complete"] is not True


@pytest.mark.parametrize("fault", ["missing_cpu", "overflow", "absent_phase"])
def test_new_receipt_cost_failure_keeps_source_without_inventing_measurement(fault):
    a, c, root, _ = fixture()
    native = json.loads(a["native-close.raw"])
    if fault == "missing_cpu":
        native["cost"]["phases"]["poll_total"]["process_cpu_ns"] = None
    elif fault == "overflow":
        native["cost"].update(complete=False, invalid_reason="counter_overflow")
    else:
        native["cost"]["phases"]["poll_total"] = None
    a["native-close.raw"] = wire(native)
    root["native_stream"] = stream(a["native-close.raw"])
    rewrite(a, c, root)
    r = evaluate(a)
    assert r["finite"]["source_decisions"] == 3 and r["status"] == "withheld"
    if fault == "missing_cpu":
        assert r["native_cost"] is None
    elif fault == "overflow":
        assert r["native_cost"]["complete"] is False
    else:
        assert r["native_cost"]["phases"]["poll_total"] is None
