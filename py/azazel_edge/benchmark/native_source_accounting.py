"""Pure registered native finite-cohort evidence; never whole-system admission."""

import hashlib
import json
import re
import stat
from pathlib import PurePosixPath

from ..outcome.confinement import profile_name
from ..outcome.input_auth import SourceVerifier, TrustPolicy
from ..outcome.input_live import ENV_KEYS, REQUIRED_ENV
from ..outcome.journal import OutcomeJournalError, _json
from .source_witness import _source_tips, _verify_anchors

PROTOCOL_SHA256 = "ddf6d2babb348e2d43307ec4c78cbd5d628778b14a273cb9d7e964f84c4fd445"
MAXIMUM = 8 * 1024 * 1024
ROWS = 4096
ACTOR = set("pid ppid start_ticks uid gid groups apparmor_label cap_eff cap_prm cap_bnd cap_amb no_new_privs".split())
CONTROLLER = set("schema_version case_id protocol_sha256 source_revision core_image_sha256 registration_sha256 trust_sha256 boot_id source_boot_ref session_ref source_identity prefix_checkpoint checkpoint native launcher receiver wait reader challenge_sids observed_sids excluded_sids planned_activity_count witness_boundary outcome local_finish_acknowledged".split())
OBJECT = set("device inode owner_uid mode nlink size mtime_ns ctime_ns".split())
COUNTS = set("produced admitted enqueued written dropped inflight".split())
CASES = {
    "normal-four": ([90121001, 90121002, 90121003, 90121004], [], 4, "clean"),
    "restart-one": ([90121006], [90121005], 1, "clean"),
    "interrupted-prefix": ([90121007], [], 1, "interrupted"),
}
ERRORS = (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, RecursionError, UnicodeError, OutcomeJournalError)


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _fields(value, fields):
    _need(type(value) is dict and set(value) == fields, "field_set")


def _uint(value, bound=2**64):
    return type(value) is int and 0 <= value < bound


def _hash(value, length=64):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _need(key not in value, "duplicate_JSON_key")
        value[key] = item
    return value


def _decode(raw, maximum, *, lf=False):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, "byte_bound")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_JSON")))
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        _need(depth <= 16, "JSON_depth")
        if type(item) is dict:
            stack.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            stack.extend((v, depth + 1) for v in item)
    _need(_json(value) + (b"\n" if lf else b"") == raw, "canonical_original_bytes")
    return value


def _tip(value, *, anchor=False):
    _fields(value, {"counter" if anchor else "seq", "head", "size", "sha256"})
    _need(_uint(value["counter" if anchor else "seq"]) and _uint(value["size"])
          and _hash(value["head"]) and _hash(value["sha256"]), "checkpoint_types")


def _actor(value, *, uid, profile=None, mask=0):
    _fields(value, ACTOR)
    _need(all(_uint(value[k]) for k in ("pid", "ppid", "start_ticks", "uid", "gid", "cap_eff", "cap_prm", "cap_bnd", "cap_amb"))
          and min(value["pid"], value["ppid"], value["start_ticks"]) > 0, "actor_incarnation")
    _need(value["uid"] == value["gid"] == uid and type(value["groups"]) is list
          and len(value["groups"]) <= 32 and len(set(value["groups"])) == len(value["groups"])
          and all(_uint(g) and g == uid for g in value["groups"])
          and value["no_new_privs"] is True and value["cap_amb"] == 0, "actor_identity")
    _need(all(value[k] & ~mask == 0 for k in ("cap_eff", "cap_prm", "cap_bnd")), "actor_capabilities")
    _need(type(value["apparmor_label"]) is str and value["apparmor_label"], "actor_label")
    if profile is not None:
        _need(value["apparmor_label"] == profile + " (enforce)", "actor_enforcing_profile")


def _object(value, identity):
    _fields(value, OBJECT)
    _need(all(_uint(v) for v in value.values()) and stat.S_ISREG(value["mode"])
          and stat.S_IMODE(value["mode"]) == 0o644 and value["nlink"] == 1
          and all(value[k] == v for k, v in identity.items()), "original_Source_object")


def evaluate_native_source_accounting(trust_raw, registration_raw, source_raw,
                                     anchors_raw, controller_raw, *, expected):
    """Verify independent legs; missing finals stay null and prefix facts survive."""
    result = dict(
        schema_version="edge-native-source-accounting-analysis/v1", status="unknown",
        raw_sha256={}, pins={}, legs={}, reasons=[], original_source_tip=None,
        authenticated_prefix_tip=None, original_anchor_tip=None,
        authenticated_full_source=False, authenticated_prefix=False,
        known_activity_count=None, known_sids=[], authenticated_declared_counts=None,
        selected_end_present=False, witnessed_source_checkpoint=None,
        finite_accounting_verified=False, qualified_counts=None,
        local_finish_acknowledged=None, overall_capture_completion_verified=None,
        upstream_ingress_count=None, full_lifetime_loss=None, source_immutable=False,
        safety_count=None, whole_window_coverage=False, comparison_qualified=False,
        performance_acceptance=False, production_activation=False,
        resume_authorized=False, old_evaluation_modified=False,
        authority_flags=dict(safety_acceptance=False, comparison=False, performance=False,
                             production=False, resume=False),
    )
    raw = dict(trust=trust_raw, registration=registration_raw, source=source_raw,
               anchors=anchors_raw, controller=controller_raw)
    limits = dict(trust=32768, registration=32768, source=MAXIMUM,
                  anchors=MAXIMUM, controller=128 * 1024)
    envelope = type(expected) is dict and set(expected) == {k + "_sha256" for k in raw}
    if not envelope:
        result["reasons"].append("expected_pin_envelope")
    for key, value in raw.items():
        digest = _sha(value) if type(value) is bytes and len(value) <= limits[key] else None
        pin = expected.get(key + "_sha256") if type(expected) is dict else None
        result["raw_sha256"][key] = digest
        result["pins"][key] = bool(_hash(pin) and digest == pin)
        if not result["pins"][key]:
            result["reasons"].append(key + ":missing_or_invalid_pin")
    legs = result["legs"]

    def check(name, operation):
        try:
            value = operation()
            legs[name] = True
            return value
        except ERRORS as exc:
            legs[name] = False
            result["reasons"].append(name + ":" + str(exc))
            return None

    def trust():
        _need(result["pins"]["trust"], "trust_pin")
        policy = TrustPolicy(_decode(trust_raw, limits["trust"]))
        _need(policy.data["schema_version"] in ("outcome-input-trust/v3", "outcome-input-trust/v4")
              and policy.data["witness_uid"] == 0 and policy.data["producer_uid"] == 61001
              and policy.data["observer_uid"] == 61002, "live_Root_CI_roles_required")
        return policy

    policy = check("trust", trust)
    if policy is None:
        return result

    def registration():
        _need(result["pins"]["registration"], "registration_pin")
        value = _decode(registration_raw, limits["registration"])
        _fields(value, set("schema_version mode scope_ref producer_ref stream_ref producer_public_key binary_path binary_sha256 launcher_uid environment ai_socket_uid capture_apparmor_profile native_apparmor_profile".split()))
        _need(value["schema_version"] == "outcome-live-origin-registration/v4"
              and value["mode"] == "live-core" and type(value["launcher_uid"]) is int
              and value["launcher_uid"] == 0
              and _sha(registration_raw) == policy.data["origin_registration_sha256"], "registered_v4_binding")
        _need(all(value[k] == policy.data[k] for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")), "registration_scope_key")
        env = value["environment"]
        _need(type(env) is dict
              and {"AZAZEL_" + k for k in REQUIRED_ENV} <= set(env)
              and all(type(k) is str and k.startswith("AZAZEL_") and k[7:] in ENV_KEYS
                      and type(v) is str and len(v) <= 1024 and "\x00" not in v for k, v in env.items())
              and env.get("AZAZEL_LIVE_ORIGIN_ACCOUNTING") == "v1"
              and value["environment"].get("AZAZEL_EVE_FROM_START") == "0"
              and value["environment"].get("AZAZEL_EVENT_STDOUT") == "off", "required_registered_accounting_profile")
        _need(_hash(value["binary_sha256"]) and type(value["binary_path"]) is str
              and value["binary_path"].startswith("/") and len(value["binary_path"]) <= 1024
              and "\x00" not in value["binary_path"]
              and all(part not in ("", ".", "..") for part in value["binary_path"].split("/")[1:])
              and _uint(value["ai_socket_uid"], 2**31)
              and value["ai_socket_uid"] not in (policy.data["producer_uid"], policy.data["observer_uid"])
              and all(type(value[k]) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value[k])
                      for k in ("native_apparmor_profile", "capture_apparmor_profile"))
              and value["native_apparmor_profile"] != value["capture_apparmor_profile"], "registered_image_profiles")
        _need(profile_name(value["native_apparmor_profile"]) == "edge400-native"
              and profile_name(value["capture_apparmor_profile"]) == "edge400-capture", "fixed_CI_profiles")
        for key in ("EVE_PATH", "NORMALIZED_EVENT_LOG", "DEFENSE_RELEASE_LEDGER", "REDIRECT_POLICY_PATH", "PROTECTED_FLOWS_PATH", "UNDELIVERED_SPOOL", "AI_SOCKET"):
            if "AZAZEL_" + key in env:
                path = PurePosixPath(env["AZAZEL_" + key])
                _need(path.is_absolute() and ".." not in path.parts, "physical_registered_core_path")
        forbidden = {policy.data["source_path"], str(PurePosixPath(policy.data["journal_directory"]) / "observations.journal"),
                     str(PurePosixPath(policy.data["anchor_directory"]) / "anchors.journal"), policy.data["socket_path"]}
        _need(not any(v in forbidden for k, v in env.items() if k.endswith(("PATH", "LOG", "LEDGER", "SOCKET", "SPOOL"))), "core_path_aliases_evidence")
        return value

    registered = check("registration", registration)

    def controller():
        _need(result["pins"]["controller"], "controller_pin")
        value = _decode(controller_raw, limits["controller"], lf=True)
        _fields(value, CONTROLLER)
        _need(value["schema_version"] == "edge-native-source-accounting-controller/v1"
              and value["case_id"] in CASES and value["protocol_sha256"] == PROTOCOL_SHA256
              and _hash(value["source_revision"], 40)
              and _hash(value["session_ref"], 32), "fixed_protocol_context")
        sids, excluded, planned, outcome = CASES[value["case_id"]]
        _need(value["challenge_sids"] == sids and value["excluded_sids"] == excluded
              and all(type(x) is int for x in value["challenge_sids"] + value["excluded_sids"])
              and type(value["planned_activity_count"]) is int and value["planned_activity_count"] == planned
              and value["outcome"] == outcome, "fixed_case_controls")
        _need(type(value["boot_id"]) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"])
              and value["source_boot_ref"] == value["boot_id"].replace("-", ""), "managed_boot_reference")
        _need(value["registration_sha256"] == result["raw_sha256"]["registration"]
              and value["trust_sha256"] == result["raw_sha256"]["trust"]
              and value["local_finish_acknowledged"] is None, "controller_registration_or_ack")
        _fields(value["source_identity"], set("device inode owner_uid mode nlink".split()))
        ident = value["source_identity"]
        _need(all(_uint(x) for x in ident.values()) and ident["owner_uid"] == policy.data["producer_uid"]
              and stat.S_ISREG(ident["mode"]) and stat.S_IMODE(ident["mode"]) == 0o644
              and ident["nlink"] == 1, "source_identity")
        return value

    control = check("controller", controller)
    authenticated = None

    def source():
        _need(type(source_raw) is bytes and len(source_raw) <= limits["source"]
              and source_raw.count(b"\n") <= ROWS, "Source_bound")
        verifier = SourceVerifier(policy)
        tip = verifier.verify(source_raw)
        result["original_source_tip"] = tip
        result["authenticated_full_source"] = True
        return source_raw

    authenticated = check("source_chain", source)
    if control is not None and type(source_raw) is bytes and len(source_raw) <= MAXIMUM:
        def prefix():
            tip = control["prefix_checkpoint"]
            _tip(tip)
            _need(tip["size"] <= len(source_raw), "prefix_unavailable")
            data = source_raw[:tip["size"]]
            _need(data.count(b"\n") <= ROWS and SourceVerifier(policy).verify(data) == tip, "prefix_checkpoint")
            result["authenticated_prefix"], result["authenticated_prefix_tip"] = True, tip
            return data
        pref = check("source_prefix", prefix)
        if authenticated is None:
            authenticated = pref
    if authenticated is None or control is None:
        return result

    def selected_session():
        selected, position, end_offset = [], 0, None
        for line in authenticated.splitlines(keepends=True):
            position += len(line)
            wire = json.loads(line)
            origin = wire["event"]["capture_origin"]
            if origin["session_ref"] == control["session_ref"]:
                _need(wire["boot_ref"] == control["source_boot_ref"], "signed_session_boot")
                selected.append(wire["event"])
                if origin["kind"] == "session_end":
                    end_offset = position
        starts = [e for e in selected if e["capture_origin"]["kind"] == "session_start"]
        ends = [e for e in selected if e["capture_origin"]["kind"] == "session_end"]
        _need(len(starts) == 1 and len(ends) <= 1, "selected_session_start")
        if starts[0]["capture_lifecycle"].get("accounting_profile") != "v1":
            result["status"] = "legacy_unmeasured"
            raise ValueError("legacy_unmeasured")
        activities = [e for e in selected if e["capture_origin"]["kind"] in ("decision_execution", "release")]
        sids = [e["normalized"]["sid"] for e in activities if e["capture_origin"]["kind"] == "decision_execution"]
        result["known_activity_count"], result["known_sids"] = len(activities), sids
        if ends:
            result["selected_end_present"] = True
            result["authenticated_declared_counts"] = ends[0]["capture_lifecycle"]["counts"].copy()
        return activities, sids, end_offset

    selected = check("session", selected_session)
    if selected is None:
        return result
    activities, sids, end_offset = selected

    def final_source():
        _need(result["pins"]["source"] and result["authenticated_full_source"], "full_Source_provenance")
        _tip(control["checkpoint"])
        _need(control["checkpoint"] == result["original_source_tip"], "final_Source_checkpoint")
    check("source_checkpoint", final_source)

    def image_and_actors():
        _need(registered is not None, "actual_registration_missing")
        _need(control["core_image_sha256"] == registered["binary_sha256"], "controller_image_hash")
        native = control["native"]
        _fields(native, ACTOR | {"image"})
        _actor({k: native[k] for k in ACTOR}, uid=0, profile=registered["native_apparmor_profile"], mask=0x10C4)
        _actor(control["launcher"], uid=0, mask=0x10C4)
        receiver = control["receiver"]
        _actor(receiver, uid=policy.data["producer_uid"], profile=registered["capture_apparmor_profile"], mask=0x10C4)
        _need(receiver["cap_eff"] == receiver["cap_prm"] == receiver["cap_amb"] == 0, "receiver_zero_caps")
        _need(native["ppid"] == receiver["ppid"] == control["launcher"]["pid"]
              and len({native["pid"], receiver["pid"], control["launcher"]["pid"]}) == 3, "launcher_child_custody")
        image = native["image"]
        _fields(image, set("sha256 owner_uid mode nlink seals".split()))
        _need(image["sha256"] == registered["binary_sha256"]
              and all(_uint(image[k]) for k in ("owner_uid", "mode", "nlink", "seals"))
              and image["owner_uid"] == image["nlink"] == 0 and image["seals"] == 15
              and stat.S_ISREG(image["mode"]) and stat.S_IMODE(image["mode"]) == 0o500, "original_sealed_native_image")
    check("actual_native_connection", image_and_actors)

    def wait():
        value = control["wait"]
        _fields(value, set("unit_state exec_main_code exec_main_status".split()))
        _need(value["unit_state"] == "inactive" and type(value["exec_main_code"]) is int
              and value["exec_main_code"] == 1 and type(value["exec_main_status"]) is int
              and value["exec_main_status"] == 0, "normal_launcher_receiver_wait")
    check("normal_wait", wait)

    def readback():
        value = control["reader"]
        _fields(value, set("actor source_before source_after access_mode started_ns finished_ns bytes_read sha256 complete errors".split()))
        _actor(value["actor"], uid=policy.data["observer_uid"], profile="edge400-observer")
        _object(value["source_before"], control["source_identity"])
        _object(value["source_after"], control["source_identity"])
        _need(value["source_before"] == value["source_after"]
              and _uint(value["started_ns"]) and _uint(value["finished_ns"])
              and value["started_ns"] <= value["finished_ns"]
              and type(value["access_mode"]) is int and value["access_mode"] == 0
              and type(value["bytes_read"]) is int and value["bytes_read"] == len(source_raw) == value["source_before"]["size"]
              and value["sha256"] == _sha(source_raw) and value["complete"] is True
              and value["errors"] == [], "stable_original_RO_read")
    check("independent_readback", readback)

    def witness():
        _need(result["pins"]["anchors"] and type(anchors_raw) is bytes
              and len(anchors_raw) <= MAXIMUM and anchors_raw.count(b"\n") <= ROWS, "anchor_pin_or_bound")
        boundary = control["witness_boundary"]
        _fields(boundary, {"source_checkpoint", "anchor_checkpoint"})
        st, at = boundary["source_checkpoint"], boundary["anchor_checkpoint"]
        _tip(st)
        _tip(at, anchor=True)
        _need(st["size"] <= len(authenticated) and SourceVerifier(policy).verify(authenticated[:st["size"]]) == st, "witness_Source_checkpoint")
        _need(at["size"] <= len(anchors_raw), "anchor_prefix_unavailable")
        anchor = anchors_raw[:at["size"]]
        _need(_verify_anchors(policy, anchor, _source_tips(authenticated), st) == at, "protected_anchor_checkpoint")
        result["original_anchor_tip"], result["witnessed_source_checkpoint"] = at, st
        _need(end_offset is not None and st["size"] >= end_offset, "witness_does_not_cover_selected_End")
    check("end_witnessed", witness)

    def finite():
        counts = result["authenticated_declared_counts"]
        _need(type(counts) is dict and set(counts) == COUNTS
              and all(_uint(x, 2**63) for x in counts.values()), "missing_or_invalid_authentic_terminal")
        _need(all(counts[k] == len(activities) for k in ("produced", "admitted", "enqueued", "written"))
              and counts["dropped"] == counts["inflight"] == 0, "finite_counter_agreement")
        for event in activities:
            enforcement, posture = event["enforcement"], event["enforcement_status"]
            _need(enforcement["mode"] in ("disabled", "dry_run", "policy_gated")
                  and enforcement["result"] == ("no_disruptive_action" if enforcement["mode"] == "disabled" else "planned_not_applied")
                  and type(enforcement["executed_count"]) is int and enforcement["executed_count"] == 0
                  and posture["enforce_enabled"] is False and posture["dry_run"] is True
                  and posture["high_impact_auto"] is False,
                  "no_action_case_provider_controls")
        wanted, excluded, planned, outcome = CASES[control["case_id"]]
        _need(outcome == "clean" and len(activities) == planned and sids == wanted
              and control["observed_sids"] == sids and all(type(s) is int for s in sids)
              and not set(sids) & set(excluded), "actual_case_activity_controls")
    check("finite_counts", finite)
    required = ("trust", "registration", "controller", "source_chain", "source_prefix", "source_checkpoint",
                "session", "actual_native_connection", "normal_wait", "independent_readback", "end_witnessed", "finite_counts")
    if envelope and all(result["pins"].values()) and all(legs.get(k) is True for k in required):
        result.update(status="verified_finite_native_cohort", finite_accounting_verified=True,
                      qualified_counts=result["authenticated_declared_counts"].copy())
    return result
