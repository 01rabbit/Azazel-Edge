"""Hardware-free role wiring/refusal contracts; no VM, UID or service proof."""

import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError
from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
from test_outcome_live_origin import enrolled, frame, signed_frame
from test_outcome_input_auth import signed
from test_signed_network_recording import POLICY

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_observer as observer
import signed_network_recording as recording


def identity():
    return dict(
        uid=61002,
        groups=[61002],
        cap_eff=0,
        cap_prm=0,
        cap_amb=0,
        apparmor="edge400-observer (enforce)",
        no_new_privs=True,
    )


def role_fixture(tmp_path, monkeypatch):
    import role_probe
    from azazel_edge.outcome import confinement

    p, key = enrolled(tmp_path)
    p = TrustPolicy(
        {**dict(p.data), "observer_uid": 61002, "producer_uid": 61001, "witness_uid": 0}
    )
    directory = Path(p.data["journal_directory"])
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(role_probe, "status", identity)
    monkeypatch.setattr(confinement, "enforce_capture", lambda label: None)
    monkeypatch.setattr(observer.TrustPolicy, "from_file", lambda *a, **k: p)
    monkeypatch.setattr(
        observer.g, "boot", lambda: "7be45004-1731-4b7c-8e62-59a5ddf129a4"
    )
    policy = observer.OutcomeTelemetryPolicy.from_mapping(
        POLICY, source_ref=str(observer.POLICY_PATH)
    )
    monkeypatch.setattr(observer, "policy_material", lambda: (POLICY, policy, "a" * 64))
    monkeypatch.setattr(
        observer,
        "LinuxProcTelemetrySource",
        lambda: SimpleNamespace(
            sample=lambda **k: SimpleNamespace(coverage={"proc_net_dev": True})
        ),
    )
    return p, key, directory, policy


def signed_prefix(p, key, kinds=("session_prepare", "session_start")):
    v = SourceVerifier(p)
    raw = b""
    for index, kind in enumerate(kinds, 1):
        event = json.loads(signed_frame(p, key, frame(kind, index - 1), index, v.head))[
            "event"
        ]
        raw += signed(
            p,
            key,
            seq=index,
            prev=v.head,
            event=event,
            boot_ref="7be4500417314b7c8e6259a5ddf129a4",
        )
        v.verify(raw)
    return raw


def test_fixed_worker_authority_and_shared_unit_constants():
    for mode, unit in [
        ("initialize", observer.INITIALIZER_UNIT),
        ("live", observer.OBSERVER_UNIT),
    ]:
        args = observer.role_argv(mode)
        assert "--unit=" + unit in args
        for prop in (
            "User=edge400-observer",
            "Group=edge400-observer",
            "CapabilityBoundingSet=",
            "RestrictAddressFamilies=AF_UNIX",
            "NoNewPrivileges=yes",
            "Restart=no",
            "DefaultDependencies=no",
            "NetworkNamespacePath=/run/netns/edge400-provider-edge",
        ):
            assert prop in args
        assert args[-2:] == ["--worker", mode]
        assert not any("NET_ADMIN" in arg or "AF_INET" in arg for arg in args)
    with pytest.raises(BenefitInputError):
        observer.role_argv("arbitrary")


def test_actual_policy_bytes_keep_real_source_reference(monkeypatch):
    raw = json.dumps(POLICY).encode()
    monkeypatch.setattr(observer, "read_regular", lambda *a, **k: (raw, None))
    value, policy, sha = observer.policy_material()
    assert value == POLICY and sha == hashlib.sha256(raw).hexdigest()
    assert (
        policy.policy_ref
        == observer.OutcomeTelemetryPolicy.from_mapping(
            POLICY, source_ref=str(observer.POLICY_PATH)
        ).policy_ref
    )


def test_empty_init_delegates_real_policy_scope_context_and_authentication(
    tmp_path, monkeypatch, capsys
):
    p, _, _, policy = role_fixture(tmp_path, monkeypatch)
    captured = {}

    class Context:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            captured["closed"] = True

        def input_position(self):
            return dict(offset=0, sha256=hashlib.sha256(b"").hexdigest())

        def status(self):
            return dict(pending=0)

        def retained_outcomes(self):
            return ()

    source = Context()

    def bounded(*args, **kwargs):
        captured["source_args"] = args
        captured["source_kwargs"] = kwargs
        return source

    def journal(*args, **kwargs):
        captured["journal_args"] = args
        captured["journal_kwargs"] = kwargs
        return Context()

    monkeypatch.setattr(
        observer, "InputAuthentication", lambda trust: ("existing-auth", trust)
    )
    monkeypatch.setattr(observer, "BoundedInput", bounded)
    monkeypatch.setattr(observer, "ObservationJournal", journal)
    monkeypatch.setattr(
        observer, "recover_input", lambda j, pol: captured.update(recovered_policy=pol)
    )
    result = observer.worker("initialize")
    assert result["initialized_empty"] is True and captured["closed"]
    assert captured["recovered_policy"] is policy
    assert captured["source_kwargs"]["authentication"] == ("existing-auth", p)
    assert captured["journal_kwargs"]["create"] is True
    assert captured["journal_kwargs"]["scope_ref"] == p.data["scope_ref"]
    assert captured["journal_kwargs"]["policy_ref"] == observer.persistence_context(
        policy, "es", observer.INTERVAL
    )
    assert json.loads(capsys.readouterr().out)["initialized_empty"] is True


@pytest.mark.parametrize("fault", ["uid", "cap", "label", "coverage"])
def test_role_or_procfs_commissioning_gap_refuses_before_scope_init(
    tmp_path, monkeypatch, fault
):
    import role_probe

    role_fixture(tmp_path, monkeypatch)
    actual = identity()
    if fault == "uid":
        actual["uid"] = 0
    elif fault == "cap":
        actual["cap_eff"] = 1
    elif fault == "label":
        actual["apparmor"] = "unconfined"
    else:
        monkeypatch.setattr(
            observer,
            "LinuxProcTelemetrySource",
            lambda: SimpleNamespace(
                sample=lambda **k: SimpleNamespace(coverage={"proc_net_dev": False})
            ),
        )
    monkeypatch.setattr(role_probe, "status", lambda: actual)
    monkeypatch.setattr(
        observer,
        "ObservationJournal",
        lambda *a, **k: pytest.fail("must not initialize"),
    )
    with pytest.raises(BenefitInputError):
        observer.worker("initialize")


def test_live_delegates_unchanged_terminal_api_and_records_failure_incomplete(
    tmp_path, monkeypatch, capsys
):
    p, key, directory, _ = role_fixture(tmp_path, monkeypatch)
    raw = signed_prefix(p, key)
    monkeypatch.setattr(observer, "read_regular", lambda *a, **k: (raw, None))

    class ExistingApiFailure(Exception):
        pass

    def run(**kwargs):
        assert kwargs["terminal_stop_registration"] == observer.g.BUNDLE / "origin.json"
        assert kwargs["initialize_journal"] is False
        assert kwargs["journal_scope"] == p.data["scope_ref"]
        assert kwargs["sample_interval_seconds"] == observer.INTERVAL
        assert kwargs["policy_path"] == observer.POLICY_PATH
        assert kwargs["interface"] == "es"
        assert (
            recording.input_resume.OutcomeTelemetryCollector
            is not recording.OutcomeTelemetryCollector
        )
        raise ExistingApiFailure("retain original journal; do not reopen")

    monkeypatch.setattr(observer, "run_live_resumable", run)
    with pytest.raises(ExistingApiFailure):
        observer.worker("live")
    context = json.loads((directory / "observer-start-context.json").read_bytes())
    assert context["source_start_position"] == dict(
        offset=len(raw), sha256=hashlib.sha256(raw).hexdigest()
    )
    assert "clock_anchor" in context
    with pytest.raises(BenefitInputError, match="unfinished"):
        recording.read_calls(directory / "actual-collector-calls.jsonl")
    assert not (directory / "observer-terminal-result.json").exists()
    assert capsys.readouterr().out == ""


def test_live_used_or_closed_prefix_refuses_before_recording(tmp_path, monkeypatch):
    p, key, directory, _ = role_fixture(tmp_path, monkeypatch)
    raw = signed_prefix(p, key, ("session_prepare", "session_start", "session_end"))
    monkeypatch.setattr(observer, "read_regular", lambda *a, **k: (raw, None))
    monkeypatch.setattr(
        observer,
        "run_live_resumable",
        lambda **k: pytest.fail("used source must not reopen"),
    )
    with pytest.raises(BenefitInputError, match="fresh actual signed start"):
        observer.worker("live")
    assert not (directory / "actual-collector-calls.jsonl").exists()


def effective_fixture():
    value = dict.fromkeys(observer.EFFECTIVE_PROPERTIES, "")
    value.update(
        User="edge400-observer",
        Group="edge400-observer",
        AppArmorProfile="edge400-observer",
        RestrictAddressFamilies="AF_UNIX",
        NoNewPrivileges="yes",
        Restart="no",
        RuntimeMaxUSec="40s",
        TimeoutStopUSec="5s",
        DefaultDependencies="no",
        Slice="system.slice",
        Requires="system.slice",
        After="system.slice",
        NetworkNamespacePath="/run/netns/" + observer.p.EDGE,
    )
    executable = str(observer.g.PYTHON.with_name("edge-observe"))
    argv = " ".join(
        [executable, "-I", str(Path(observer.__file__).resolve()), "--worker", "live"]
    )
    value["ExecStart"] = (
        "{ path="
        + executable
        + " ; argv[]="
        + argv
        + " ; ignore_errors=no ; pid=123 ; code=(null) ; status=0/0 }"
    )
    return value


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("Restart", "always"),
        ("NetworkNamespacePath", "/run/netns/foreign"),
        ("User", "root"),
        ("CapabilityBoundingSet", "cap_net_admin"),
        ("AmbientCapabilities", "cap_net_admin"),
        ("RestrictAddressFamilies", "AF_UNIX AF_INET"),
        ("ExecStartPre", "other-writer"),
        ("ExecStopPost", "other-writer"),
        ("Wants", observer.g.UNIT),
        ("Requires", "system.slice other-observer.service"),
        ("TriggeredBy", "other.timer"),
        ("ExecStart", "{ path=/bin/other }"),
    ],
)
def test_effective_drift_refuses(field, replacement):
    value = effective_fixture()
    observer.validate_effective(value)
    value[field] = replacement
    with pytest.raises(BenefitInputError):
        observer.validate_effective(value)


@pytest.mark.parametrize("fault", [None, "pid_reuse", "namespace", "capbound", "label"])
def test_effective_kernel_identity_and_fixed_namespace(tmp_path, monkeypatch, fault):
    properties = effective_fixture()
    monkeypatch.setattr(
        observer.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            stdout="\n".join(key + "=" + value for key, value in properties.items())
        ),
    )
    raw = "123 (observer) " + " ".join(["S"] + ["0"] * 18 + ["123"] + ["0"] * 5)
    state = dict(
        LoadState="loaded",
        ActiveState="active",
        MainPID="123",
        ControlPID="0",
        ControlGroup="/system.slice/" + observer.OBSERVER_UNIT,
        pid_stat=raw,
    )
    calls = []

    def snapshot(unit):
        calls.append(unit)
        return dict(
            state,
            pid_stat=raw.replace(" 123 ", " 124 ")
            if fault == "pid_reuse" and len(calls) == 2
            else raw,
        )

    monkeypatch.setattr(observer.lab, "unit_snapshot", snapshot)
    status = (
        "Uid:\t61002 61002 61002 61002\nGid:\t61002 61002 61002 61002\nGroups:\t61002\nNoNewPrivs:\t1\n"
        + "".join(
            key
            + ":\t"
            + ("1" if fault == "capbound" and key == "CapBnd" else "0")
            + "\n"
            for key in ("CapEff", "CapPrm", "CapAmb", "CapBnd")
        )
    )

    def kernel(path, maximum):
        if path.endswith("/status"):
            return status
        if path.endswith("/cgroup"):
            return "0::/system.slice/" + observer.OBSERVER_UNIT + "\n"
        return "unconfined" if fault == "label" else "edge400-observer (enforce)"

    monkeypatch.setattr(observer, "_kernel_text", kernel)
    real = os.stat
    monkeypatch.setattr(
        observer.os,
        "stat",
        lambda path, *a, **k: SimpleNamespace(
            st_dev=4, st_ino=100 if fault == "namespace" else 99
        )
        if str(path) == "/proc/123/ns/net"
        else real(path, *a, **k),
    )
    if fault is None:
        assert (
            observer.effective_observer(dict(device=4, inode=99))["state"]["MainPID"]
            == "123"
        )
    else:
        with pytest.raises(BenefitInputError):
            observer.effective_observer(dict(device=4, inode=99))


def test_wrong_signed_boot_is_not_relabelled_or_observed(tmp_path, monkeypatch):
    p, key, directory, _ = role_fixture(tmp_path, monkeypatch)
    verifier = SourceVerifier(p)
    raw = b""
    for i, kind in enumerate(("session_prepare", "session_start"), 1):
        raw += signed_frame(p, key, frame(kind, i - 1), i, verifier.head)
        verifier.verify(raw)
    monkeypatch.setattr(observer, "read_regular", lambda *a, **k: (raw, None))
    with pytest.raises(BenefitInputError, match="signed source boot differs"):
        observer.worker("live")
    assert not (directory / "observer-start-context.json").exists()
    assert not (directory / "actual-collector-calls.jsonl").exists()


def test_actual_end_anchor_follows_natural_api_and_durable_recorder_close(
    tmp_path, monkeypatch
):
    p, key, directory, _ = role_fixture(tmp_path, monkeypatch)
    prefix = signed_prefix(p, key)
    source = signed_prefix(p, key, ("session_prepare", "session_start", "session_end"))
    wire = source[len(prefix) :]
    event = json.loads(wire)["event"]
    origin = event["capture_origin"]
    receipt = observer.TerminalControlStop(
        p.data["origin_registration_sha256"],
        origin["session_ref"],
        origin["seq"],
        dict(offset=len(prefix), sha256=hashlib.sha256(prefix).hexdigest()),
        dict(offset=len(source), sha256=hashlib.sha256(source).hexdigest()),
        wire,
        SourceVerifier.unwrap(wire),
        0,
    )
    calls = []

    def read(path, **kwargs):
        if Path(path).name == "input":
            calls.append("source-read")
            return (prefix if calls.count("source-read") == 1 else source), None
        return b"raw closed journal", None

    monkeypatch.setattr(observer, "read_regular", read)
    monkeypatch.setattr(
        observer,
        "run_live_resumable",
        lambda **k: (calls.append("natural-api-return") or receipt),
    )
    monkeypatch.setattr(
        observer.lab,
        "journal_frames",
        lambda raw: [dict(kind="session_close", seq=7, sha256="a" * 64)],
    )

    class Witness:
        def __init__(self, *a):
            self.state = dict(source_sha256=hashlib.sha256(source).hexdigest())

        def preflight(self, *a):
            calls.append("read-only-witness")

    monkeypatch.setattr(observer, "WitnessClient", Witness)
    real_anchor = observer.record_clock_anchor
    anchors = []

    def anchor():
        if anchors:
            assert "natural-api-return" in calls
            assert (
                recording.read_calls(directory / "actual-collector-calls.jsonl")[
                    "calls"
                ]
                == []
            )
            assert not (directory / "observer-terminal-result.json").exists()
        value = real_anchor()
        anchors.append(value)
        return value

    monkeypatch.setattr(observer, "record_clock_anchor", anchor)
    result = observer.worker("live")
    assert len(anchors) == 2 and result["context"]["clock_anchor"] == anchors[0]
    assert result["end_clock_anchor"] == anchors[1]
    assert anchors[1]["monotonic_before_ns"] >= anchors[0]["monotonic_after_ns"]
    assert (directory / "terminal.wire").read_bytes() == wire
