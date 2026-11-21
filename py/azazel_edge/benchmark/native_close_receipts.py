"""Pure close-receipt facts under explicit trusted CI custody, never admission."""

import base64
import json
from pathlib import PurePosixPath
import re
import stat

from ..outcome.input_auth import SourceVerifier, TrustPolicy
from ..outcome.input_live import ENV_KEYS, REQUIRED_ENV
from .native_source_accounting import (
    ACTOR, ERRORS, _actor, _decode, _fields, _hash, _need, _object, _sha,
    _tip, _uint,
)
from .source_witness import _source_tips, _verify_anchors

PROTOCOL_SHA256 = "27b5674e1d2b7704bbb4e788ab5581fde2d7ee2f968c17d6519793217fb5639b"
FILES = frozenset("protocol.json trust.json registration.json close-controller.json root-custody.raw root-custody-object.json actor-fd-custody.json native-close.raw receiver-close.raw launcher-systemd.json unit-exec-start.raw launcher-journal.raw source-before.raw source-after.raw anchors-before.raw anchors-after.raw journal-before.raw journal-after.raw readback-source.raw reader-binding.json witness-boundary.json code-pins.json failure.json evaluation.json".split())
CONTROL = set("schema_version case_id protocol_sha256 source_revision core_image_sha256 trust_sha256 registration_sha256 boot_id source_boot_ref session_ref previous_session_ref attempt_ref action custody_mode started_ns finished_ns actors invocation root_custody fd_custody stores reader outcome error".split())
INVOCATION = set("unit invocation_id exec_main_pid exec_main_start_monotonic_us exec_main_exit_monotonic_us active_state result exec_main_code exec_main_status exec_start_sha256 exec_start standard_output standard_error".split())
OBJECT = set("device inode owner_uid mode nlink size mtime_ns ctime_ns".split())
FD = set("fd device inode owner_uid mode nlink flags".split())
IDENTITY = ("device", "inode", "owner_uid", "mode", "nlink")
CUSTODY = set("schema_version registration_sha256 trust_sha256 session_ref boot_ref launcher_pid core_pid receiver_pid core_returncode receiver_returncode receiver_wait_timed_out forwarded_signal native_stream receiver_stream root_stdout".split())
MANAGED = set("schema_version stage attempted_session_ref prior_session_ref source_checkpoint registration_sha256 trust_sha256 launcher_pid boot_ref invocation_id core_spawn_attempted receiver_spawn_attempted root_stdout".split())
NATIVE = {"schema_version", "session_ref", "native_pid", "local_worker_ack_observed"}
RECEIVER = set("schema_version session_ref receiver_pid launcher_pid registration_sha256 trust_sha256 source_checkpoint clean_eof_observed terminal_append_fsync_completed source_writer_close_completed".split())
CASES = {
    "normal-four": ("normal_stop", [90121001, 90121002, 90121003, 90121004]),
    "restart-one": ("normal_stop", [90121006]),
    "witness-stopped-close": ("stop_witness_then_normal_stop", [90122001]),
    "interrupted-prefix": ("native_sigkill", [90121007]),
    "receiver-killed-prefix": ("receiver_sigkill_then_normal_stop", [90122002]),
    "interrupted-restart-refused": ("connected_restart_attempt", []),
    "receiver-restart-refused": ("connected_restart_attempt", []),
}
AUTHORITY = dict.fromkeys("safety_acceptance comparison performance production deployment resume applied_provider_claim".split(), False)
BIG = 8 * 1024 * 1024


def _limit(name):
    if name.startswith(("source-", "anchors-", "journal-")) or name == "readback-source.raw":
        return BIG
    return {"trust.json": 32768, "registration.json": 32768,
            "root-custody.raw": 32768, "native-close.raw": 1024,
            "receiver-close.raw": 4096, "launcher-journal.raw": 65536}.get(name, 128 * 1024)


def _object_shape(value):
    _fields(value, OBJECT)
    _need(all(_uint(v) for v in value.values()), "object_types")


def _same_object(a, b):
    _object_shape(a)
    _object_shape(b)
    return all(a[k] == b[k] for k in IDENTITY)


def evaluate_native_close_receipts(artifacts, *, expected):
    """Retain independent authenticated facts when another leg is unavailable."""
    result = dict(
        schema_version="edge-native-close-analysis/v1", case_id=None, status="unknown",
        raw_sha256={}, pins={}, legs={}, reasons=[],
        native_local_worker_ack_observed=None, receiver_close_report=None,
        source_authenticated=None, source_tip=None, authenticated_prefix_tip=None,
        selected_end_present=None, source_readback_verified=None,
        witness_checkpoint=None, witness_covers_selected_end=None,
        native_returncode=None, receiver_returncode=None, launcher_exit=None,
        managed_refusal_verified=None, stores_unchanged=None, authority_flags=AUTHORITY.copy(),
    )
    if type(artifacts) is not dict or set(artifacts) != FILES or type(expected) is not dict or set(expected) != FILES:
        result["reasons"].append("exact_artifact_pin_envelope")
        return result
    all_supplied_pins_valid = True
    for name in sorted(FILES):
        raw, pin = artifacts[name], expected[name]
        digest = _sha(raw) if type(raw) is bytes and len(raw) <= _limit(name) else None
        result["raw_sha256"][name] = digest
        result["pins"][name] = bool(_hash(pin) and digest == pin)
        if not (raw is None and pin is None) and not result["pins"][name]:
            all_supplied_pins_valid = False
            result["reasons"].append(name + ":invalid_supplied_pin")
        if name == "evaluation.json":
            result["raw_sha256"][name] = result["pins"][name] = None
    legs = result["legs"]

    def check(name, call):
        try:
            value = call()
            legs[name] = True
            return value
        except ERRORS as error:
            legs[name] = False
            result["reasons"].append(name + ":" + str(error))
            return None

    def raw(name):
        _need(result["pins"][name], name + ":missing_or_invalid_pin")
        return artifacts[name]

    def data(name):
        return _decode(raw(name), _limit(name), lf=name not in ("trust.json", "registration.json"))

    def trust():
        policy = TrustPolicy(data("trust.json"))
        p = policy.data
        _need(p["schema_version"] == "outcome-input-trust/v4"
              and p["producer_uid"] == 61001 and p["observer_uid"] == 61002
              and p["witness_uid"] == 0, "fixed_v4_CI_roles")
        return policy

    policy = check("trust", trust)
    if policy is None:
        return result

    def source(name):
        value = raw(name)
        _need(value.count(b"\n") <= 4096, "Source_row_bound")
        verifier = SourceVerifier(policy)
        tip = verifier.verify(value)
        return verifier, tip, value

    before = check("source_before", lambda: source("source-before.raw"))
    after = check("source_after", lambda: source("source-after.raw"))
    if before is not None:
        result["authenticated_prefix_tip"] = before[1]
    if after is not None:
        result.update(source_authenticated=True, source_tip=after[1])

    def context():
        protocol = data("protocol.json")
        _need(_sha(raw("protocol.json")) == PROTOCOL_SHA256
              and protocol["schema_version"] == "edge-native-close-receipts-protocol/v1", "fixed_protocol")
        c = data("close-controller.json")
        _fields(c, CONTROL)
        _need(c["schema_version"] == "edge-native-close-controller/v1"
              and c["case_id"] in CASES and c["protocol_sha256"] == PROTOCOL_SHA256
              and c["action"] == CASES[c["case_id"]][0]
              and c["outcome"] == "collected" and c["error"] is None, "fixed_collected_case")
        _need(artifacts["failure.json"] is None, "retained_collection_failure")
        _need(_hash(c["attempt_ref"], 32) and _hash(c["source_revision"], 40)
              and _hash(c["session_ref"], 32)
              and _uint(c["started_ns"]) and _uint(c["finished_ns"])
              and c["started_ns"] <= c["finished_ns"], "controller_context_types")
        _need(type(c["boot_id"]) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", c["boot_id"])
              and c["source_boot_ref"] == c["boot_id"].replace("-", ""), "boot_binding")
        _need(c["trust_sha256"] == result["raw_sha256"]["trust.json"] == policy.digest
              and c["registration_sha256"] == result["raw_sha256"]["registration.json"], "context_original_pins")
        pins = data("code-pins.json")
        _fields(pins, {"source_revision", "protocol_sha256", "core_image_sha256"})
        _need(all(pins[k] == c[k] for k in pins), "tested_code_pins")
        return c

    control = check("context", context)
    if control is None:
        return result
    case = control["case_id"]
    result["case_id"] = case
    refusal = case.endswith("restart-refused")

    def registration():
        r = data("registration.json")
        _fields(r, set("schema_version mode scope_ref producer_ref stream_ref producer_public_key binary_path binary_sha256 launcher_uid environment ai_socket_uid capture_apparmor_profile native_apparmor_profile".split()))
        _need(r["schema_version"] == "outcome-live-origin-registration/v4" and r["mode"] == "live-core"
              and type(r["launcher_uid"]) is int and r["launcher_uid"] == 0
              and r["native_apparmor_profile"] == "edge400-native" and r["capture_apparmor_profile"] == "edge400-capture"
              and r["binary_sha256"] == control["core_image_sha256"]
              and _hash(r["binary_sha256"]) and _sha(raw("registration.json")) == policy.data["origin_registration_sha256"], "v4_registration")
        _need(all(r[k] == policy.data[k] for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")), "registration_scope_key")
        env = r["environment"]
        _need(type(env) is dict and {"AZAZEL_" + k for k in REQUIRED_ENV} <= set(env)
              and all(type(k) is str and k.startswith("AZAZEL_") and k[7:] in ENV_KEYS
                      and type(v) is str and len(v) <= 1024 and "\x00" not in v for k, v in env.items())
              and env.get("AZAZEL_LIVE_ORIGIN_ACCOUNTING") == env.get("AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS") == "v1"
              and env.get("AZAZEL_EVENT_STDOUT") == "off" and env.get("AZAZEL_EVE_FROM_START") == "0", "registered_receipts_profile")
        _need(type(r["binary_path"]) is str and r["binary_path"].startswith("/")
              and len(r["binary_path"]) <= 1024 and "\x00" not in r["binary_path"]
              and all(part not in ("", ".", "..") for part in r["binary_path"].split("/")[1:])
              and _uint(r["ai_socket_uid"], 2**31) and r["ai_socket_uid"] not in (61001, 61002), "registered_image_path_and_ai_uid")
        paths = ("EVE_PATH", "NORMALIZED_EVENT_LOG", "DEFENSE_RELEASE_LEDGER", "REDIRECT_POLICY_PATH", "PROTECTED_FLOWS_PATH", "UNDELIVERED_SPOOL", "AI_SOCKET")
        for key in paths:
            if "AZAZEL_" + key in env:
                path = PurePosixPath(env["AZAZEL_" + key])
                _need(path.is_absolute() and ".." not in path.parts, "registered_absolute_paths")
        forbidden = {policy.data["source_path"], str(PurePosixPath(policy.data["journal_directory"]) / "observations.journal"),
                     str(PurePosixPath(policy.data["anchor_directory"]) / "anchors.journal"), policy.data["socket_path"]}
        _need(not any(v in forbidden for k, v in env.items() if k.endswith(("PATH", "LOG", "LEDGER", "SOCKET", "SPOOL"))), "core_path_aliases_evidence")
        return r

    registered = check("registration", registration)

    def stores():
        values = control["stores"]
        _fields(values, {"source", "anchors", "journal"})
        unchanged = True
        for name, value in values.items():
            fields = {"before", "after"} | ({"before_checkpoint", "after_checkpoint"} if name != "journal" else set())
            _fields(value, fields)
            for when in ("before", "after"):
                item = value[when]
                _fields(item, {"object", "bytes", "sha256"})
                _object_shape(item["object"])
                body = raw(name + "-" + when + ".raw")
                _need(type(item["bytes"]) is int and item["bytes"] == item["object"]["size"] == len(body)
                      and item["sha256"] == _sha(body), "original_store_snapshot")
                _need(stat.S_ISREG(item["object"]["mode"]) and item["object"]["nlink"] == 1
                      and item["object"]["owner_uid"] == {"source": 61001, "anchors": 0, "journal": 61002}[name], "store_object_owner")
                if name == "source":
                    _need(stat.S_IMODE(item["object"]["mode"]) == 0o644, "original_Source_mode")
                else:
                    _need(stat.S_IMODE(item["object"]["mode"]) == 0o600, "original_private_store_mode")
            unchanged &= value["before"] == value["after"] and raw(name + "-before.raw") == raw(name + "-after.raw")
        result["stores_unchanged"] = bool(unchanged)
        _need(before is not None and after is not None
              and values["source"]["before_checkpoint"] == before[1]
              and values["source"]["after_checkpoint"] == after[1], "Source_snapshot_tips")
        _need(after[2].startswith(before[2]), "retained_Source_prefix")
        for when, source_value in (("before", before), ("after", after)):
            checkpoint = values["anchors"][when + "_checkpoint"]
            _tip(checkpoint, anchor=True)
            anchor_raw = raw("anchors-" + when + ".raw")
            _need(anchor_raw and anchor_raw.count(b"\n") <= 4096, "anchor_snapshot_rows")
            state = json.loads(anchor_raw.splitlines()[-1])["state"]
            source_tip = {k: state["source_" + k] for k in ("seq", "head", "size", "sha256")}
            _tip(source_tip)
            _need(_verify_anchors(policy, anchor_raw, _source_tips(source_value[2]), source_tip) == checkpoint, "anchor_snapshot_checkpoint")
        return values

    observed_stores = check("store_snapshots", stores)

    def session():
        _need(after is not None, "authenticated_selected_Source")
        rows, offset, end_offset = [], 0, None
        for line in after[2].splitlines(keepends=True):
            offset += len(line)
            wire = json.loads(line)
            origin = wire["event"]["capture_origin"]
            if origin["session_ref"] == control["session_ref"]:
                _need(wire["boot_ref"] == control["source_boot_ref"], "selected_boot")
                rows.append(wire["event"])
                if origin["kind"] == "session_end":
                    end_offset = offset
        _need(sum(e["capture_origin"]["kind"] == "session_start" for e in rows) == 1, "selected_native_start")
        result["selected_end_present"] = end_offset is not None
        starts = [e for e in rows if e["capture_origin"]["kind"] == "session_start"]
        ends = [e for e in rows if e["capture_origin"]["kind"] == "session_end"]
        _need(starts[0]["capture_lifecycle"].get("schema_version") == "outcome-live-origin-lifecycle/v2"
              and starts[0]["capture_lifecycle"].get("accounting_profile") == "v1", "counted_native_profile_required")
        activity = [e for e in rows if e["capture_origin"]["kind"] in ("decision_execution", "release")]
        actual_sids = [e["normalized"]["sid"] for e in activity if "normalized" in e]
        wanted = ([90121007] if case == "interrupted-restart-refused" else [90122002]) if refusal else CASES[case][1]
        _need(actual_sids == wanted and all(type(v) is int for v in actual_sids)
              and len(activity) == len(actual_sids), "actual_challenge_activity")
        if ends:
            _need(len(ends) == 1 and ends[0]["capture_lifecycle"].get("schema_version") == "outcome-live-origin-lifecycle/v2"
                  and ends[0]["capture_lifecycle"].get("accounting_profile") == "v1", "counted_End_required")
            counts = ends[0]["capture_lifecycle"]["counts"]
            _fields(counts, set("produced admitted enqueued written dropped inflight".split()))
            _need(all(_uint(v, 2**63) for v in counts.values())
                  and all(counts[k] == len(activity) for k in ("produced", "admitted", "enqueued", "written"))
                  and counts["dropped"] == counts["inflight"] == 0, "authentic_counter_agreement")
        for event in activity:
            enforcement, posture = event["enforcement"], event["enforcement_status"]
            _need(enforcement["mode"] in ("disabled", "dry_run", "policy_gated")
                  and enforcement["result"] == ("no_disruptive_action" if enforcement["mode"] == "disabled" else "planned_not_applied")
                  and type(enforcement["executed_count"]) is int and enforcement["executed_count"] == 0
                  and posture["enforce_enabled"] is False and posture["dry_run"] is True
                  and posture["high_impact_auto"] is False, "unchanged_no_action_posture")
        return end_offset

    end_offset = check("selected_session", session)

    def manager():
        value = control["invocation"]
        _fields(value, INVOCATION)
        _need(data("launcher-systemd.json") == value, "original_manager_copy")
        _need(value["unit"] == "azazel-edge-core.service" and _hash(value["invocation_id"], 32)
              and _uint(value["exec_main_pid"]) and value["exec_main_pid"] > 1
              and _uint(value["exec_main_start_monotonic_us"]) and _uint(value["exec_main_exit_monotonic_us"])
              and 0 < value["exec_main_start_monotonic_us"] <= value["exec_main_exit_monotonic_us"], "actual_exited_invocation")
        _need(value["active_state"] in ("inactive", "failed") and type(value["exec_main_code"]) is int
              and type(value["exec_main_status"]) is int and type(value["result"]) is str, "actual_manager_exit")
        commands = data("unit-exec-start.raw")
        _need(commands == value["exec_start"] and _sha(raw("unit-exec-start.raw")) == value["exec_start_sha256"], "typed_ExecStart_pin")
        _need(type(commands) is list and len(commands) == 1 and type(commands[0]) is list
              and len(commands[0]) >= 2, "typed_ExecStart_shape")
        command, argv = commands[0][:2]
        _need(command == "/opt/edge400-runtime/bin/python" and argv == [command, "-I", "-m", "azazel_edge.outcome.service_entry", "--bundle", "/var/lib/edge400-systemd-lab/bundle", "--boot-ref", control["source_boot_ref"]], "fixed_protected_ExecStart")
        _fields(value["standard_output"], {"mode", "path"})
        _need(value["standard_output"]["mode"] == "append" and value["standard_error"] == "journal", "separate_Root_output")
        result["launcher_exit"] = {k: value[k] for k in ("exec_main_code", "exec_main_status", "result")}
        return value

    invocation = check("manager", manager)

    def root_output():
        _need(invocation is not None, "manager_custody_required")
        value = control["root_custody"]
        _fields(value, {"relative_name", "prepared", "launcher_fd1", "after", "bytes", "sha256"})
        _need(data("root-custody-object.json") == value, "original_Root_object_copy")
        _need(type(value["relative_name"]) is str and re.fullmatch(r"close-custody/" + re.escape(case) + r"-[0-9a-f]{32}\.raw", value["relative_name"]), "fresh_Root_sink_name")
        for item in (value["prepared"], value["after"]):
            _object_shape(item)
            _need(stat.S_ISREG(item["mode"]) and stat.S_IMODE(item["mode"]) == 0o600
                  and item["owner_uid"] == 0 and item["nlink"] == 1, "protected_Root_sink")
        _need(_same_object(value["prepared"], value["after"]) and value["prepared"]["size"] == 0, "original_empty_Root_sink")
        output = raw("root-custody.raw")
        _need(type(value["bytes"]) is int and value["bytes"] == value["after"]["size"] == len(output)
              and value["sha256"] == _sha(output), "complete_Root_readback")
        configured_path = invocation["standard_output"]["path"]
        _need(configured_path is None or configured_path == "/var/lib/edge400-systemd-lab/" + value["relative_name"], "typed_Root_sink_path")
        lines = output.splitlines(keepends=True)
        if refusal:
            _need(len(lines) == 1, "one_Root_refusal_not_journal_marker")
        else:
            _need(len(lines) == 2 and lines[0] == b'{"core_started":true}\n', "exact_Root_stream")
        _need(len(lines[-1]) <= 16384, "Root_report_bound")
        report = _decode(lines[-1], 16384, lf=True)
        _fields(report, MANAGED if refusal else CUSTODY)
        _need(type(report["launcher_pid"]) is int and report["launcher_pid"] == invocation["exec_main_pid"]
              and report["boot_ref"] == control["source_boot_ref"]
              and report["registration_sha256"] == control["registration_sha256"]
              and report["trust_sha256"] == control["trust_sha256"]
              and _same_object(report["root_stdout"], value["prepared"]), "exclusive_Root_report_binding")
        if not refusal:
            _need(report["schema_version"] == "outcome-live-close-custody/v1" and report["session_ref"] == control["session_ref"]
                  and _uint(report["core_pid"]) and _uint(report["receiver_pid"]), "Root_live_custody")
        return report

    parent = check("root_output", root_output)

    def live_custody():
        _need(not refusal and registered is not None and parent is not None, "live_parent_required")
        _fields(control["actors"], {"launcher", "native", "receiver"})
        a = control["actors"]
        native = a["native"]
        _fields(native, ACTOR | {"image"})
        _actor(a["launcher"], uid=0, mask=0x10C4)
        _actor({k: native[k] for k in ACTOR}, uid=0, profile="edge400-native", mask=0x10C4)
        _actor(a["receiver"], uid=61001, profile="edge400-capture", mask=0x10C4)
        _need(a["receiver"]["cap_eff"] == a["receiver"]["cap_prm"] == a["receiver"]["cap_amb"] == 0, "receiver_zero_caps")
        _need(native["ppid"] == a["receiver"]["ppid"] == a["launcher"]["pid"]
              and len({v["pid"] for v in a.values()}) == 3
              and a["launcher"]["pid"] == parent["launcher_pid"]
              and native["pid"] == parent["core_pid"] and a["receiver"]["pid"] == parent["receiver_pid"], "actual_parent_children")
        image = native["image"]
        _fields(image, {"sha256", "owner_uid", "mode", "nlink", "seals"})
        _need(all(_uint(image[k]) for k in ("owner_uid", "mode", "nlink", "seals"))
              and image["sha256"] == registered["binary_sha256"] and image["owner_uid"] == image["nlink"] == 0
              and type(image["seals"]) is int and image["seals"] == 15
              and type(image["mode"]) is int and stat.S_ISREG(image["mode"]) and stat.S_IMODE(image["mode"]) == 0o500, "sealed_native")
        fd = control["fd_custody"]
        _fields(fd, {"sampled_ns", "launcher", "native", "receiver"})
        _need(data("actor-fd-custody.json") == fd and _uint(fd["sampled_ns"]), "original_FD_copy")
        root_obj = control["root_custody"]["prepared"]
        stdout = {}
        for role in ("launcher", "native", "receiver"):
            entry = fd[role]
            _fields(entry, {"pid", "start_ticks", "complete", "entries", "errors"})
            _need(entry["pid"] == a[role]["pid"] and entry["start_ticks"] == a[role]["start_ticks"]
                  and entry["complete"] is True and entry["errors"] == []
                  and type(entry["entries"]) is list and len(entry["entries"]) <= 256, "actual_complete_FD_inventory")
            numbers = []
            for item in entry["entries"]:
                _fields(item, FD)
                _need(all(_uint(v) for v in item.values()), "FD_types")
                numbers.append(item["fd"])
                same = all(item[k] == root_obj[k] for k in ("device", "inode"))
                if role != "launcher":
                    _need(not same, "child_has_Root_sink_descriptor")
                if item["fd"] == 1:
                    stdout[role] = item
            _need(numbers == sorted(set(numbers)), "ordered_unique_FDs")
        _need(all(k in stdout for k in a), "actual_stdout_descriptors")
        _need(all(stdout["launcher"][k] == root_obj[k] for k in IDENTITY), "actual_Root_fd1")
        for role in ("native", "receiver"):
            item = stdout[role]
            _need(stat.S_ISFIFO(item["mode"]) and item["flags"] & 3 == 1
                  and item["flags"] & 0o2000000 != 0, "private_CLOEXEC_child_stdout")
        _need(stdout["native"]["flags"] & 0o4000 != 0
              and (stdout["native"]["device"], stdout["native"]["inode"]) != (stdout["receiver"]["device"], stdout["receiver"]["inode"]), "distinct_nonblocking_native_pipe")
        _need(control["custody_mode"] == "live_parent_and_children", "live_custody_mode")
        return a

    actors = check("live_custody", live_custody) if not refusal else None

    def child_stream(role, limit):
        _need(actors is not None, "actual_child_custody_required")
        value = parent[role + "_stream"]
        _fields(value, {"raw_b64", "eof", "over_limit"})
        _need(type(value["raw_b64"]) is str and len(value["raw_b64"]) <= ((limit + 2) // 3) * 4
              and value["eof"] is True and value["over_limit"] is False, "complete_bounded_child_stream")
        payload = base64.b64decode(value["raw_b64"], validate=True)
        filename = "native-close.raw" if role == "native" else "receiver-close.raw"
        _need(payload == raw(filename) and len(payload) <= limit, "original_private_pipe_bytes")
        return payload

    def waits():
        _need(actors is not None and type(parent["receiver_wait_timed_out"]) is bool, "actual_parent_waits")
        child_stream("native", 1024)
        child_stream("receiver", 4096)
        for key in ("core_returncode", "receiver_returncode"):
            _need(type(parent[key]) is int and -(2**31) <= parent[key] < 2**31, "actual_raw_returncode")
        _need(parent["forwarded_signal"] is None or type(parent["forwarded_signal"]) is int and parent["forwarded_signal"] in (2, 15), "forwarded_signal")
        result["native_returncode"] = parent["core_returncode"]
        result["receiver_returncode"] = parent["receiver_returncode"]
    check("child_waits", waits) if not refusal else None

    def native_report():
        body = child_stream("native", 1024)
        value = _decode(body, 1024, lf=True)
        _fields(value, NATIVE)
        _need(value["schema_version"] == "outcome-native-close-receipt/v1"
              and value["session_ref"] == control["session_ref"]
              and type(value["native_pid"]) is int and value["native_pid"] == actors["native"]["pid"]
              and type(value["local_worker_ack_observed"]) is bool, "actual_native_report")
        result["native_local_worker_ack_observed"] = value["local_worker_ack_observed"]
    check("native_report", native_report) if not refusal else None

    def receiver_report():
        body = child_stream("receiver", 4096)
        _need(body.startswith(b'{"ready":true}\n'), "exact_original_ready")
        value = _decode(body[15:], 3072, lf=True)
        _fields(value, RECEIVER)
        flags = ("clean_eof_observed", "terminal_append_fsync_completed", "source_writer_close_completed")
        _tip(value["source_checkpoint"])
        _need(value["schema_version"] == "outcome-live-receiver-close-receipt/v1"
              and value["session_ref"] == control["session_ref"]
              and type(value["receiver_pid"]) is int and value["receiver_pid"] == actors["receiver"]["pid"]
              and type(value["launcher_pid"]) is int and value["launcher_pid"] == actors["launcher"]["pid"]
              and value["registration_sha256"] == control["registration_sha256"]
              and value["trust_sha256"] == policy.digest and all(value[k] is True for k in flags)
              and after is not None and value["source_checkpoint"] == after[1]
              and result["selected_end_present"] is True, "post_close_receiver_report")
        result["receiver_close_report"] = {k: value[k] for k in (*flags, "source_checkpoint")}
    check("receiver_report", receiver_report) if not refusal else None

    def readback():
        _need(after is not None and observed_stores is not None, "original_Source_required")
        value = control["reader"]
        _fields(value, set("actor source_before source_after access_mode started_ns finished_ns bytes_read sha256 complete errors".split()))
        _actor(value["actor"], uid=61002, profile="edge400-observer")
        binding = data("reader-binding.json")
        _fields(binding, set("schema_version unit challenge bootstrap unit_properties actual_actor command_verified status error runner_stderr runner_stdout_base64 runner_stderr_base64 runner_stdout_bytes runner_stderr_bytes runner_stdout_truncated runner_stderr_truncated runner_returncode cleanup".split()))
        _need(binding["schema_version"] == "edge-native-source-reader-binding/v1"
              and binding["status"] == "verified_root_observed_role"
              and binding["error"] is None and binding["command_verified"] is True
              and binding["actual_actor"] == value["actor"]
              and type(binding["challenge"]) is str and _hash(binding["challenge"], 32)
              and binding["unit"] == "edge400-accounting-reader-" + case + "-" + binding["challenge"] + ".service"
              and type(binding["runner_returncode"]) is int and binding["runner_returncode"] == 0, "original_Root_reader_binding")
        bootstrap, properties = binding["bootstrap"], binding["unit_properties"]
        _fields(bootstrap, {"schema_version", "pid", "challenge", "invocation_id", "actor"})
        _fields(properties, {"MainPID", "InvocationID"})
        _fields(bootstrap["actor"], ACTOR)
        _need(bootstrap["schema_version"] == "edge-native-source-reader-bootstrap/v1"
              and bootstrap["challenge"] == binding["challenge"]
              and type(bootstrap["pid"]) is int and bootstrap["pid"] == value["actor"]["pid"]
              and properties["MainPID"] == str(bootstrap["pid"])
              and _hash(properties["InvocationID"], 32)
              and properties["InvocationID"] == bootstrap["invocation_id"]
              and all(bootstrap["actor"][k] == value["actor"][k] for k in ACTOR if k != "start_ticks")
              and bootstrap["actor"]["start_ticks"] in (None, value["actor"]["start_ticks"]), "actual_reader_incarnation")
        identity = {k: observed_stores["source"]["after"]["object"][k] for k in IDENTITY}
        _object(value["source_before"], identity)
        _object(value["source_after"], identity)
        _need(value["source_before"] == value["source_after"] and _uint(value["started_ns"])
              and _uint(value["finished_ns"]) and value["started_ns"] <= value["finished_ns"]
              and type(value["access_mode"]) is int and value["access_mode"] == 0
              and type(value["bytes_read"]) is int and value["bytes_read"] == len(after[2]) == value["source_after"]["size"]
              and value["sha256"] == _sha(after[2]) and value["complete"] is True and value["errors"] == []
              and raw("readback-source.raw") == after[2], "independent_stable_RO_Source")
        result["source_readback_verified"] = True
    check("readback", readback) if not refusal else None

    def witness():
        _need(after is not None, "authenticated_Source_required")
        value = data("witness-boundary.json")
        _fields(value, {"source_checkpoint", "anchor_checkpoint"})
        source_tip, anchor_tip = value["source_checkpoint"], value["anchor_checkpoint"]
        _need(observed_stores is not None and anchor_tip == observed_stores["anchors"]["after_checkpoint"], "witness_snapshot_same_checkpoint")
        _tip(source_tip)
        _tip(anchor_tip, anchor=True)
        anchors = raw("anchors-after.raw")
        _need(anchors.count(b"\n") <= 4096 and anchor_tip["size"] == len(anchors)
              and source_tip["size"] <= len(after[2])
              and SourceVerifier(policy).verify(after[2][:source_tip["size"]]) == source_tip
              and _verify_anchors(policy, anchors, _source_tips(after[2]), source_tip) == anchor_tip, "original_protected_witness")
        result["witness_checkpoint"] = source_tip
        if result["selected_end_present"] is True:
            result["witness_covers_selected_end"] = source_tip["size"] >= end_offset
    check("witness", witness)

    def managed_refusal():
        _need(refusal and registered is not None and parent is not None and invocation is not None
              and observed_stores is not None and after is not None and before is not None, "refusal_originals_required")
        _tip(parent["source_checkpoint"])
        _need(control["custody_mode"] == "managed_prelaunch_refusal"
              and parent["schema_version"] == "outcome-managed-restart-refusal/v1"
              and parent["stage"] == "managed_ready_unclosed_history"
              and parent["attempted_session_ref"] is None
              and parent["prior_session_ref"] == control["session_ref"] == control["previous_session_ref"]
              and parent["source_checkpoint"] == after[1] == before[1]
              and parent["invocation_id"] == invocation["invocation_id"]
              and parent["core_spawn_attempted"] is False and parent["receiver_spawn_attempted"] is False,
              "actual_typed_prelaunch_refusal")
        _need(not after[0].live_state.closed and after[0].live_state.session == control["session_ref"]
              and result["stores_unchanged"] is True
              and invocation["exec_main_code"] == 1 and invocation["exec_main_status"] == 1
              and invocation["active_state"] == "failed" and invocation["result"] == "exit-code", "nonmutating_actual_refusal_exit")
        result["managed_refusal_verified"] = True
    check("managed_refusal", managed_refusal) if refusal else None

    common = ("trust", "source_before", "source_after", "context", "registration", "store_snapshots", "selected_session", "manager", "root_output")
    if all_supplied_pins_valid and all(legs.get(k) is True for k in common):
        if refusal and legs.get("managed_refusal") is True:
            result["status"] = "bound_prelaunch_refusal"
        elif not refusal and all(legs.get(k) is True for k in ("live_custody", "child_waits", "readback", "witness")):
            normal_exit = (result["native_returncode"] == result["receiver_returncode"] == 0
                           and invocation["exec_main_code"] == 1 and invocation["exec_main_status"] == 0
                           and invocation["active_state"] == "inactive" and invocation["result"] == "success"
                           and parent["receiver_wait_timed_out"] is False)
            complete_reports = legs.get("native_report") is True and result["native_local_worker_ack_observed"] is True and legs.get("receiver_report") is True
            if case in ("normal-four", "restart-one") and normal_exit and complete_reports and result["witness_covers_selected_end"] is True:
                result["status"] = "bound_finite_close"
            elif case == "witness-stopped-close" and normal_exit and complete_reports and result["witness_covers_selected_end"] is False:
                result["status"] = "bound_partial_close"
            elif (case == "interrupted-prefix" and result["native_returncode"] == -9
                  and result["selected_end_present"] is False and parent["receiver_wait_timed_out"] is False
                  and invocation["exec_main_code"] == 1 and invocation["exec_main_status"] == 1
                  and invocation["active_state"] == "failed" and invocation["result"] == "exit-code"):
                result["status"] = "bound_partial_close"
            elif (case == "receiver-killed-prefix" and result["receiver_returncode"] == -9
                  and result["selected_end_present"] is False and parent["receiver_wait_timed_out"] is False
                  and invocation["exec_main_code"] == 1 and invocation["exec_main_status"] == 1
                  and invocation["active_state"] == "failed" and invocation["result"] == "exit-code"):
                result["status"] = "bound_partial_close"
    return result
