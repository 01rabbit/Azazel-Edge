"""Synthetic receipts and TEST-key crypto, not Linux observation evidence."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from azazel_edge.benchmark import finite_ingress as annex
from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
from azazel_edge.outcome.journal import _json
from safety_observation_data import digest
from source_witness_data import anchor_checkpoint
from test_native_close_receipts import fixture as close_fixture, obj, reader_binding, rewrite, stream, wire
from test_native_source_accounting import anchors, source_bytes


def fixture():
    artifacts, c, root, oldpolicy = close_fixture()
    case = "ingress-mixed"
    protocol = (Path(__file__).parent / "real_systemd/finite-ingress-source-protocol-v1.json").read_bytes()
    pdoc = json.loads(protocol)
    raw = b""
    origins = []
    for item in pdoc["cases"][0]["recipe"]:
        if item["kind"] == "alert":
            value = deepcopy(pdoc["alert_template"])
            value["alert"]["signature_id"] = item["sid"]
            line = wire(value)
            origins.append(dict(schema_version="azazel-edge/ingress-origin/v1",
                range_ref=c["session_ref"], device=8, inode=777,
                start_offset=len(raw), end_offset=len(raw) + len(line), raw_sha256=digest(line)))
        elif item["kind"] == "json":
            line = wire(item["value"])
        else:
            line = item["value"].encode()
        raw += line
    registration = json.loads(artifacts["registration.json"])
    registration["environment"]["AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING"] = "v1"
    policy = TrustPolicy({**dict(oldpolicy.data), "origin_registration_sha256": digest(_json(registration))})
    events = [json.loads(line)["event"] for line in artifacts["source-after.raw"].splitlines()]
    i = 0
    for event in events:
        event["capture_origin"]["registration_sha256"] = policy.data["origin_registration_sha256"]
        if event["capture_origin"]["kind"] == "decision_execution":
            event["normalized"]["sid"] = annex.CASES[case][1][i]
            event["ingress_origin"] = origins[i]
            i += 1
    after = source_bytes(policy, events)
    before = b"".join(after.splitlines(keepends=True)[:-1])
    bt, at = SourceVerifier(policy).verify(before), SourceVerifier(policy).verify(after)
    ab, aa = anchors(policy, bt), anchors(policy, at)
    c.update(case_id=case, protocol_sha256=annex.PROTOCOL_SHA256,
             trust_sha256=policy.digest, registration_sha256=policy.data["origin_registration_sha256"])
    c["root_custody"]["relative_name"] = "close-custody/" + case + "-" + "a" * 32 + ".raw"
    for name, br, ar in (("source", before, after), ("anchors", ab, aa)):
        artifacts[name + "-before.raw"], artifacts[name + "-after.raw"] = br, ar
        for when, body in (("before", br), ("after", ar)):
            entry = c["stores"][name][when]
            entry.update(bytes=len(body), sha256=digest(body))
            entry["object"]["size"] = len(body)
        c["stores"][name].update(before_checkpoint=bt if name == "source" else anchor_checkpoint(ab),
                                  after_checkpoint=at if name == "source" else anchor_checkpoint(aa))
    reader = c["reader"]
    sobj = obj(200, 61001, after, 0o644)
    reader.update(source_before=sobj, source_after=deepcopy(sobj), bytes_read=len(after), sha256=digest(after))
    counts = dict(polls=2, examined=9, admitted=8, alerts_admitted=4,
        shed_by_type=dict.fromkeys(("flow", "dns", "stats", "other", "unparseable"), 0),
        shed_rate=0, shed_backlog=0, oversized_started=0, oversized_possible_alerts=0,
        file_replacements=0, truncation_resets=0, unread_bytes_lost_observed=0,
        normalized_decisions=4, blank=1, admitted_without_source=4)
    ingress = dict(schema_version="azazel-edge/finite-ingress/v1", range_ref=c["session_ref"],
        measurement_valid=True, invalid_reason=None, input_identity=dict(device=8, inode=777),
        start_offset=0, committed_end_offset=len(raw), last_observed_length=len(raw),
        committed_bytes=len(raw), committed_sha256=digest(raw), last_stop="CaughtUp",
        unfinished_tail=None, oversized_in_progress=False, counts=counts)
    native = json.loads(artifacts["native-close.raw"])
    native.update(schema_version="outcome-native-close-receipt/v2", ingress=ingress)
    receiver = json.loads(artifacts["receiver-close.raw"][15:])
    receiver.update(registration_sha256=c["registration_sha256"], trust_sha256=policy.digest, source_checkpoint=at)
    artifacts.update({"protocol.json": protocol, "registration.json": _json(registration), "trust.json": _json(dict(policy.data)),
        "native-close.raw": wire(native), "receiver-close.raw": b'{"ready":true}\n' + wire(receiver),
        "readback-source.raw": after, "reader-binding.json": wire(reader_binding(reader, case)),
        "witness-boundary.json": wire(dict(source_checkpoint=at, anchor_checkpoint=anchor_checkpoint(aa))),
        "code-pins.json": wire({k: c[k] for k in ("source_revision", "protocol_sha256", "core_image_sha256")})})
    root.update(schema_version="outcome-live-close-custody/v2", registration_sha256=c["registration_sha256"], trust_sha256=policy.digest,
                native_stream=stream(artifacts["native-close.raw"]), receiver_stream=stream(artifacts["receiver-close.raw"]))
    rewrite(artifacts, c, root)
    artifacts.update({name: None for name in annex.FILES - artifacts.keys()})
    initial, final = obj(777, 0, b"", 0o644), obj(777, 0, raw, 0o644)
    snapshots = dict.fromkeys(annex.RAW_FILES)
    for name, body, meta in (("eve-start.raw", b"", initial), ("eve-after-writer.raw", raw, final),
                              ("eve-held-final.raw", raw, final), ("eve-path-final.raw", raw, final)):
        artifacts[name] = body
        snapshots[name] = dict(before=deepcopy(meta), after=deepcopy(meta), sha256=digest(body), size=len(body), fd=5, flags=0)
    writer = dict(stage="initial", pid=20, tid=21, fd=6, flags=0o2001, before=initial, after=final,
        started_ns=110, finished_ns=120, offset_before=0, offset_after=len(raw), requested_bytes=len(raw),
        written_bytes=len(raw), write_calls=1, fsync_completed=True, joined=True, joined_ns=130,
        pause=None, resume=None, error=None)
    ctrl = dict(schema_version="edge-finite-ingress-controller/v1", case_id=case, protocol_sha256=annex.PROTOCOL_SHA256,
        session_ref=c["session_ref"], range_ref=c["session_ref"], started_ns=90, finished_ns=200,
        held_fd=dict(fd=5, object=initial, opened_ns=100, closed_ns=201), snapshots=snapshots,
        writer=[writer], mutation=None, markers=[dict(kind="source", sid=90231004, occurrence=1,
            observed_ns=140, session_ref=c["session_ref"], range_ref=c["session_ref"],
            source_checkpoint=bt, ingress_origin=origins[-1], normalized_log_checkpoint=None)], errors=[])
    artifacts["ingress-controller.json"] = wire(ctrl)
    return artifacts, c, root, ctrl


def evaluate(artifacts, expected=None):
    pins = {k: digest(v) if type(v) is bytes else None for k, v in artifacts.items()}
    return annex.evaluate_finite_ingress(artifacts, expected=pins if expected is None else expected)


def change_native(a, c, root, mutate):
    native = json.loads(a["native-close.raw"])
    mutate(native["ingress"])
    a["native-close.raw"] = wire(native)
    root["native_stream"] = stream(a["native-close.raw"])
    rewrite(a, c, root)


def change_source(a, c, root, mutate):
    policy = TrustPolicy(json.loads(a["trust.json"]))
    events = [json.loads(line)["event"] for line in a["source-after.raw"].splitlines()]
    mutate(events)
    after = source_bytes(policy, events)
    before = b"".join(after.splitlines(keepends=True)[:-1])
    bt, at = SourceVerifier(policy).verify(before), SourceVerifier(policy).verify(after)
    ab, aa = anchors(policy, bt), anchors(policy, at)
    for name, br, ar in (("source", before, after), ("anchors", ab, aa)):
        a[name + "-before.raw"], a[name + "-after.raw"] = br, ar
        for when, body in (("before", br), ("after", ar)):
            item = c["stores"][name][when]
            item.update(bytes=len(body), sha256=digest(body))
            item["object"]["size"] = len(body)
        c["stores"][name].update(before_checkpoint=bt if name == "source" else anchor_checkpoint(ab),
                                  after_checkpoint=at if name == "source" else anchor_checkpoint(aa))
    sobj = obj(200, 61001, after, 0o644)
    c["reader"].update(source_before=sobj, source_after=deepcopy(sobj), bytes_read=len(after), sha256=digest(after))
    a.update({"readback-source.raw": after, "reader-binding.json": wire(reader_binding(c["reader"], c["case_id"])),
              "witness-boundary.json": wire(dict(source_checkpoint=at, anchor_checkpoint=anchor_checkpoint(aa)))})
    receiver = json.loads(a["receiver-close.raw"][15:])
    receiver["source_checkpoint"] = at
    a["receiver-close.raw"] = b'{"ready":true}\n' + wire(receiver)
    root["receiver_stream"] = stream(a["receiver-close.raw"])
    rewrite(a, c, root)


def test_synthetic_complete_bindings_preserve_originals_and_old_evaluation():
    a, _, _, _ = fixture()
    saved = deepcopy(a)
    r = evaluate(a)
    assert r["status"] == "bound_complete_input", (r["reasons"], r["close"]["reasons"])
    assert r["whole_input_complete"] is r["committed_range_verified"] is True
    assert r["source_decisions"] == r["matched_decision_spans"] == 4
    assert r["ingress"]["counts"]["admitted_without_source"] == 4
    assert r["unconfirmed_decision_outputs"] == 0 and not any(r["authority_flags"].values())
    assert a == saved and evaluate(a) == r
    old = {k: a[k] for k in annex.close.FILES}
    result = annex.close.evaluate_native_close_receipts(old, expected={k: digest(v) if type(v) is bytes else None for k, v in old.items()})
    assert result["status"] == "unknown"
    assert result["schema_version"] == "edge-native-close-analysis/v1"


@pytest.mark.parametrize("key", sorted(annex.FILES - {"evaluation.json", "failure.json", "eve-before-mutation.raw", "normalized-log-before.raw", "normalized-log-final.raw", "launcher-journal.raw"}))
def test_missing_leg_never_upgrades_and_keeps_independently_authenticated_source(key):
    a, _, _, _ = fixture()
    a[key] = None
    r = evaluate(a)
    assert r["status"] != "bound_complete_input"
    if key not in {"protocol.json", "trust.json", "registration.json", "close-controller.json", "code-pins.json", "source-after.raw"}:
        assert r["source_decisions"] == 4


@pytest.mark.parametrize("mutate", [
    lambda i: i.update(range_ref="0" * 32),
    lambda i: i.update(committed_end_offset=i["committed_end_offset"] + 1),
    lambda i: i.update(committed_sha256="0" * 64),
    lambda i: i["counts"].update(examined=0),
    lambda i: i["counts"].update(blank=True),
    lambda i: i["counts"].update(normalized_decisions=3),
    lambda i: i["counts"].update(file_replacements=1),
    lambda i: i.update(unfinished_tail=dict(start_offset=True, observed_bytes=1, raw_sha256="0" * 64)),
])
def test_bad_native_measurement_does_not_erase_signed_prefix(mutate):
    a, c, root, _ = fixture()
    change_native(a, c, root, mutate)
    r = evaluate(a)
    assert r["status"] != "bound_complete_input"
    assert r["source_decisions"] == 4


def test_independent_tail_retains_consumed_prefix_and_does_not_backfill_native_tail():
    a, _, _, ctrl = fixture()
    suffix = b'{"unfinished":'
    for name in ("eve-after-writer.raw", "eve-held-final.raw", "eve-path-final.raw"):
        a[name] += suffix
        meta = ctrl["snapshots"][name]
        meta.update(size=len(a[name]), sha256=digest(a[name]))
        meta["before"]["size"] = meta["after"]["size"] = len(a[name])
    ctrl["writer"][0].update(requested_bytes=len(a["eve-held-final.raw"]), written_bytes=len(a["eve-held-final.raw"]), offset_after=len(a["eve-held-final.raw"]))
    a["ingress-controller.json"] = wire(ctrl)
    r = evaluate(a)
    assert r["status"] == "bound_consumed_prefix", r["reasons"]
    assert r["whole_input_complete"] is False
    assert r["raw_population"]["tail_bytes"] == r["raw_population"]["unread_bytes"] == len(suffix)
    assert r["ingress"]["unfinished_tail"] is None


def test_missing_native_keeps_actual_raw_population_without_final_count_zero():
    a, c, root, _ = fixture()
    a["native-close.raw"] = b""
    root["native_stream"] = stream(b"")
    rewrite(a, c, root)
    r = evaluate(a)
    assert r["raw_population"]["complete_lf_records"] == 9
    assert r["ingress"] is r["unconfirmed_decision_outputs"] is None
    assert r["source_decisions"] == 4


@pytest.mark.parametrize("fault", ["extra", "bool_fd", "write_open", "metadata", "held_closed_early", "changed_raw"])
def test_custody_and_pin_negative_cases(fault):
    a, _, _, ctrl = fixture()
    if fault == "extra":
        ctrl["extra"] = 1
    elif fault == "bool_fd":
        ctrl["snapshots"]["eve-held-final.raw"]["fd"] = True
    elif fault == "write_open":
        ctrl["snapshots"]["eve-held-final.raw"]["flags"] = 1
    elif fault == "metadata":
        ctrl["snapshots"]["eve-held-final.raw"]["after"]["ctime_ns"] += 1
    elif fault == "held_closed_early":
        ctrl["held_fd"]["closed_ns"] = 100
    else:
        a["eve-held-final.raw"] = b"x" + a["eve-held-final.raw"][1:]
    a["ingress-controller.json"] = wire(ctrl)
    r = evaluate(a)
    assert r["status"] != "bound_complete_input"
    assert r["source_decisions"] == 4


@pytest.mark.parametrize("fault", ["middle", "multiline", "overlap", "different_input_object", "sid_mismatch"])
def test_authentic_test_key_source_cannot_bind_wrong_input_span(fault):
    a, c, root, _ = fixture()
    def mutate(events):
        decisions = [e for e in events if e["capture_origin"]["kind"] == "decision_execution"]
        e = decisions[0]
        origin = e["ingress_origin"]
        if fault == "middle":
            origin["start_offset"] += 1
            origin["raw_sha256"] = digest(a["eve-held-final.raw"][origin["start_offset"]:origin["end_offset"]])
        elif fault == "multiline":
            origin["end_offset"] = decisions[1]["ingress_origin"]["end_offset"]
            origin["raw_sha256"] = digest(a["eve-held-final.raw"][:origin["end_offset"]])
        elif fault == "overlap":
            decisions[1]["ingress_origin"] = deepcopy(origin)
            decisions[1]["normalized"]["sid"] = decisions[0]["normalized"]["sid"]
        elif fault == "different_input_object":
            origin["inode"] += 1
        else:
            e["normalized"]["sid"] += 100
    change_source(a, c, root, mutate)
    r = evaluate(a)
    assert r["close"]["source_authenticated"] is True
    assert r["source_decisions"] == 4
    assert r["legs"]["spans"] is False
    assert r["unconfirmed_decision_outputs"] is None
    assert r["status"] != "bound_complete_input"


def test_conserved_native_blank_admitted_split_requires_independent_raw_agreement():
    a, c, root, _ = fixture()
    def mutate(i):
        i["counts"].update(blank=0, admitted=9, admitted_without_source=5)
    change_native(a, c, root, mutate)
    r = evaluate(a)
    assert r["ingress"] is not None
    assert r["legs"]["committed"] is False
    assert r["status"] != "bound_complete_input"


@pytest.mark.parametrize("fault", ["no_marker", "wrong_checkpoint", "wrong_occurrence", "unfinished_writer", "wrong_recipe", "unknown_control_field"])
def test_case_control_failures_do_not_qualify_complete_input(fault):
    a, _, _, ctrl = fixture()
    if fault == "no_marker":
        ctrl["markers"] = []
    elif fault == "wrong_checkpoint":
        ctrl["markers"][0]["source_checkpoint"]["sha256"] = "0" * 64
    elif fault == "wrong_occurrence":
        ctrl["markers"][0]["occurrence"] = 2
    elif fault == "unfinished_writer":
        ctrl["writer"][0]["joined"] = False
    elif fault == "wrong_recipe":
        a["eve-after-writer.raw"] = b"x" + a["eve-after-writer.raw"][1:]
    else:
        ctrl["writer"][0]["ignored_extra"] = 1
    a["ingress-controller.json"] = wire(ctrl)
    r = evaluate(a)
    assert r["source_decisions"] == 4
    assert r["status"] != "bound_complete_input"


def test_sticky_first_invalidation_reason_can_precede_later_counter_failure():
    a, c, root, _ = fixture()
    change_native(a, c, root, lambda i: i.update(measurement_valid=False, invalid_reason="identity_changed", committed_sha256=None, counts=None))
    r = evaluate(a)
    assert r["ingress"]["invalid_reason"] == "identity_changed"
    assert r["ingress"]["counts"] is r["unconfirmed_decision_outputs"] is None


def test_release_is_signed_activity_but_not_an_ingress_decision_or_exclusion():
    a, c, root, ctrl = fixture()
    def mutate(events):
        decision = next(e for e in events if e["capture_origin"]["kind"] == "decision_execution")
        release = dict(capture_origin={**decision["capture_origin"], "kind": "release"},
            release={}, enforcement_status=deepcopy(decision["enforcement_status"]),
            source="release_ledger", pipeline="rust_release_engine_v1")
        events.insert(-1, release)
        sequence = 0
        for event in events:
            if event["capture_origin"]["kind"] != "session_prepare":
                sequence += 1
                event["capture_origin"]["seq"] = sequence
        counts = events[-1]["capture_lifecycle"]["counts"]
        for name in ("produced", "admitted", "enqueued", "written"):
            counts[name] += 1
    change_source(a, c, root, mutate)
    # Preserve the actual pre-release progress marker at its original checkpoint.
    r = evaluate(a)
    assert r["close"]["legs"]["selected_session"] is True, r["close"]["reasons"]
    assert r["source_decisions"] == r["matched_decision_spans"] == 4
    assert r["source_releases"] == 1
    assert r["unconfirmed_decision_outputs"] == 0
    assert r["ingress"]["counts"]["admitted_without_source"] == 4


def test_independent_oversize_classifier_matches_actual_lf_boundary():
    limit = 1024 * 1024
    at_limit = b" " * limit + b"\n"
    over_limit = b" " * (limit + 1) + b"\n"
    assert annex._raw_classes(at_limit)["oversized_started"] == 0
    assert annex._raw_classes(over_limit)["oversized_started"] == 1


def test_missing_witness_is_unknown_whole_completion_without_observed_incompleteness():
    a, _, _, _ = fixture()
    a["witness-boundary.json"] = None
    r = evaluate(a)
    assert r["status"] == "bound_consumed_prefix"
    assert r["whole_input_complete"] is None


def test_typed_failed_collection_retains_independent_facts_but_never_qualifies():
    a, c, root, _ = fixture()
    c.update(outcome="failure", error=dict(type="AssertionError", message="final manager unavailable"))
    a["failure.json"] = wire(c["error"])
    rewrite(a, c, root)
    r = evaluate(a)
    assert r["close"]["collection_completed"] is False
    assert r["source_decisions"] == r["matched_decision_spans"] == 4
    assert r["raw_population"]["complete_lf_records"] == 9
    assert r["status"] != "bound_complete_input" and r["whole_input_complete"] is None
    assert r["close"]["status"] == "unknown"
    original = deepcopy(a)
    assert evaluate(a) == r and a == original


def test_failed_collection_requires_matching_pinned_failure_object():
    a, c, root, _ = fixture()
    c.update(outcome="failure", error=dict(type="AssertionError", message="actual"))
    a["failure.json"] = wire(dict(type="AssertionError", message="different"))
    rewrite(a, c, root)
    r = evaluate(a)
    assert r["close"]["legs"]["context"] is False
    assert r["status"] == "unknown"


def test_v1_failure_analysis_stays_fail_closed_after_v2_addition():
    a, c, root, _ = close_fixture()
    c.update(outcome="failure", error=dict(type="AssertionError", message="failure"))
    a["failure.json"] = wire(c["error"])
    rewrite(a, c, root)
    pins = {k: digest(v) if type(v) is bytes else None for k, v in a.items()}
    r = annex.close.evaluate_native_close_receipts(a, expected=pins)
    assert r["status"] == "unknown" and "collection_completed" not in r
