"""SO-02 (Edge#414): source/interface failure visible on the operator surface.

The lab itself needs root and network namespaces, so it runs in the
service-objective job, not here. These tests pin the table, the refusals, the
measurement loop (against a fake lab), and above all the validator: an end the
sample's own fields do not show is never counted, and a virtual-lab record can
never claim to be hardware evidence.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.service_objectives import __main__ as cli  # noqa: E402
from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import so02_source_failure as so02  # noqa: E402

PROC = rec.SO02_CAPTURE_PROCESS
IFACE = rec.SO02_CAPTURE_INTERFACE
SPEC = rec.OBJECTIVE_SPECS["SO-02"]["source_failure_visible"]


@pytest.fixture
def clean_owner(monkeypatch):
    monkeypatch.setattr(
        rec,
        "owner_block",
        lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True},
    )


@pytest.fixture
def no_gap_table(monkeypatch):
    """The SO-02 row with its gaps closed and only the recomputed prerequisites,
    so the pass/fail mechanics can be exercised. Never the real table."""

    row = dict(SPEC, gaps=(), prerequisites=("every_injection_from_healthy_baseline", "every_lab_source_type_sampled"))
    monkeypatch.setitem(rec.OBJECTIVE_SPECS, "SO-02", {"source_failure_visible": row})


def _sample(i: int, source_type: str, elapsed_ms: float) -> dict:
    entry = rec.SO02_SURFACE[source_type]
    start = 10_000_000_000 + i * 100_000_000_000  # 100 s apart: no overlap
    end = start + int(elapsed_ms * 1e6)
    return {
        "sample_id": f"so02-{source_type}-{i:02d}",
        "start_monotonic_ns": start,
        "end_monotonic_ns": end,
        "elapsed_ms": round((end - start) / 1e6, 3),
        "start_event": "injection",
        "end_event": "surface names source failed",
        "source_type": source_type,
        "source_id": entry["source_id"],
        "injection": "x",
        "surface": "GET /api/state",
        "surface_field": entry["field"],
        "baseline_healthy": True,
        "baseline_poll_started_monotonic_ns": start - 50_000_000,
        "baseline_surface_value": "ON" if source_type == PROC else ["usb0"],
        "end_poll_started_monotonic_ns": start + max(1, int(elapsed_ms * 1e6) // 2),
        "end_surface_value": "OFF" if source_type == PROC else ["br0", "usb0"],
        "polls_after_injection": 3,
        "poll_errors_after_injection": 0,
        "recovered": True,
    }


def _samples(elapsed=lambda i: 500.0):
    return [_sample(i, rec.SO02_LAB_SOURCE_TYPES[i % 2], elapsed(i)) for i in range(20)]


def _record(samples, *, prerequisites=None, gaps=None, config=None) -> dict:
    spec = rec.OBJECTIVE_SPECS["SO-02"]["source_failure_visible"]
    observed = rec.so02_observed_prerequisites(samples)
    if prerequisites is None:
        prerequisites = [rec.prerequisite(p, observed.get(p, True), "") for p in spec["prerequisites"]]
    if gaps is None:
        gaps = [rec.gap(g, "x") for g in spec["gaps"]]
    # The harness ends only observed samples; mirror that.
    samples = [dict(s) for s in samples]
    for s in samples:
        if not rec.so02_failure_observed(s):
            s["end_monotonic_ns"] = None
            s["elapsed_ms"] = None
    part = rec.build_part(
        name="source_failure_visible",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": spec["bound_ms"]},
        required_samples=spec["required_samples"],
        samples=samples,
        prerequisites=prerequisites,
        gaps=gaps,
    )
    return rec.build_record(
        objective_id="SO-02",
        title="t",
        started_monotonic_ns=0,
        started_at=rec.utc_now(),
        product_configuration=config if config is not None else {"product": "azazel-edge", "row_class": "virtual-lab", "hardware_evidence": False},
        clock={"name": "CLOCK_MONOTONIC"},
        sample_rule={"required_samples": spec["required_samples"]},
        parts=[part],
        method="test",
    )


def _forge(record: dict, verdict: str = rec.VERDICT_PASS) -> dict:
    record = copy.deepcopy(record)
    record["owner"] = {"repository": rec.OWNING_REPOSITORY, "commit": "c" * 40, "worktree_clean": True}
    for part in record["parts"]:
        part["verdict"] = verdict
        part["pass_rule"]["evaluated"]["holds"] = verdict == rec.VERDICT_PASS
    record["verdict"] = verdict
    record["evidence_class"] = "gate"
    return record


# ------------------------------------------------------------------ the table


def test_table_is_the_assignment_row():
    assert SPEC["bound_ms"] == 10000.0 == so02.BOUND_MS
    assert SPEC["required_samples"] == 20 == so02.REQUIRED_SAMPLES
    assert SPEC["row_class"] == "virtual-lab"
    assert rec.SO02_PER_SOURCE_TYPE_SAMPLES * len(rec.SO02_LAB_SOURCE_TYPES) == SPEC["required_samples"]
    assert set(SPEC["gaps"]) == {
        "SO02-NOT-NEXUS-INTEGRATED",
        "SO02-SOURCE-TYPES-UNDECLARED",
        "SO02-NO-COMMISSIONED-INTERFACE-IDENTITY",
    }
    assert "SO-02" in cli._harnesses(type("A", (), {"seed": None, "core_bin": ""})())


# ------------------------------------------------------------- the validator


def test_real_table_record_is_valid_and_not_measurable(clean_owner):
    record = _record(_samples())
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert record["evidence_class"] == "diagnostic_only"


def test_forged_pass_on_real_table_is_refused(clean_owner):
    errors = rec.validate_record(_forge(_record(_samples())))
    assert any("record supports 'not_measurable'" in e for e in errors), errors


def test_mechanics_pass_within_bound(clean_owner, no_gap_table):
    record = _record(_samples())
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_PASS


def test_one_sample_over_ten_seconds_is_fail(clean_owner, no_gap_table):
    record = _record(_samples(lambda i: 33_000.0 if i == 1 else 500.0))
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_FAIL
    errors = rec.validate_record(_forge(record))
    assert any("disagrees with the samples" in e or "record supports 'fail'" in e for e in errors), errors


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(end_surface_value="ON"),                         # surface never said failed
        lambda s: s.update(end_surface_value=["usb0"]),                     # (interface sample) source not named
        lambda s: s.update(source_id="eth0"),                                # another source
        lambda s: s.update(surface_field="noc_summary.status"),             # another field
        lambda s: s.update(end_poll_started_monotonic_ns=s["start_monotonic_ns"] - 1),  # poll begun before injection
        lambda s: s.update(baseline_surface_value="OFF"),                   # was already failed
        lambda s: s.update(baseline_surface_value=["br0"]),                 # (interface) was already failed
        lambda s: s.update(baseline_healthy=False),
        lambda s: s.update(baseline_poll_started_monotonic_ns=s["start_monotonic_ns"] + 1),
        lambda s: s.update(source_type="feed_unreachable"),
    ],
)
def test_end_not_shown_by_the_fields_is_refused_and_never_counted(clean_owner, no_gap_table, mutate):
    samples = _samples()
    # Mutate one sample of each type; at least one of them is affected.
    for idx in (0, 1):
        mutate(samples[idx])
    affected = [i for i in (0, 1) if not rec.so02_failure_observed(samples[i])]
    assert affected
    # A record that keeps the end anyway is rejected.
    honest = _record(_samples())
    forged = copy.deepcopy(honest)
    for i in affected:
        forged["parts"][0]["samples"][i] = samples[i]
    errors = rec.validate_record(forged)
    assert any("do not show the surface naming the source failed" in e for e in errors), errors
    # Recorded honestly (no end), the sample is unfinished: never a pass.
    record = _record(samples)
    assert record["verdict"] != rec.VERDICT_PASS
    assert rec.validate_record(_forge(record)) != []


def test_one_type_short_is_not_measurable(clean_owner, no_gap_table):
    samples = [_sample(i, PROC if i < 11 else IFACE, 500.0) for i in range(20)]
    assert rec.so02_observed_prerequisites(samples)["every_lab_source_type_sampled"] is False
    record = _record(samples)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert rec.validate_record(record) == []
    forged = _record(samples, prerequisites=[rec.prerequisite(p, True, "") for p in rec.OBJECTIVE_SPECS["SO-02"]["source_failure_visible"]["prerequisites"]])
    errors = rec.validate_record(_forge(forged))
    assert any("'every_lab_source_type_sampled' declared met" in e for e in errors), errors


def test_shortfall_is_not_measurable(clean_owner, no_gap_table):
    record = _record(_samples()[:19])
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE


@pytest.mark.parametrize(
    "config, needle",
    [
        ({"row_class": "hardware-only", "hardware_evidence": False}, "row_class"),
        ({"row_class": "virtual-lab", "hardware_evidence": True}, "hardware_evidence"),
        ({"row_class": "virtual-lab"}, "hardware_evidence"),
        ({}, "row_class"),
    ],
)
def test_virtual_lab_record_never_claims_hardware(clean_owner, config, needle):
    errors = rec.validate_record(_record(_samples(), config=dict(config, product="azazel-edge")))
    assert any(needle in e for e in errors), errors


def test_omitted_gap_is_refused(clean_owner):
    record = _record(_samples(), gaps=[])
    errors = rec.validate_record(_forge(record))
    assert any("mandatory gap 'SO02-NOT-NEXUS-INTEGRATED' omitted" in e for e in errors), errors


def test_unknown_sample_field_is_refused(clean_owner):
    record = _record(_samples())
    record["parts"][0]["samples"][0]["verdict_override"] = "pass"
    assert any("unknown field" in e for e in rec.validate_record(record))


# --------------------------------------------------------------- the harness


def test_not_root_is_not_measurable_and_builds_nothing(clean_owner, monkeypatch):
    monkeypatch.setattr(so02.os, "geteuid", lambda: 1000)

    def no_lab(*a, **k):
        raise AssertionError("the lab must not be built")

    monkeypatch.setattr(so02, "_Lab", no_lab)
    record = so02.run()
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    part = record["parts"][0]
    assert part["samples"] == []
    prereq = {p["id"]: p for p in part["prerequisites"]}
    assert prereq["lab_built"]["met"] is False and "not root" in prereq["lab_built"]["detail"]
    assert record["product_configuration"]["hardware_evidence"] is False


def test_live_capture_is_never_touched(clean_owner, monkeypatch):
    monkeypatch.setattr(
        so02,
        "preflight",
        lambda: {"problems": [], "live_capture": ["suricata already running (pid [42])"], "suricata_version": "", "gunicorn_version": "", "tools": {"suricata": "/x"}},
    )

    def no_lab(*a, **k):
        raise AssertionError("the lab must not be built while a capture is live")

    monkeypatch.setattr(so02, "_Lab", no_lab)
    record = so02.run()
    assert rec.validate_record(record) == []
    prereq = {p["id"]: p for p in record["parts"][0]["prerequisites"]}
    assert prereq["no_live_capture_touched"]["met"] is False
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE


class _FakePoller:
    """Answers wait_for from a script: per call, the delay after begun_after_ns
    and the row content, or None for "nothing seen"."""

    def __init__(self, script, clock=None):
        self.script = list(script)
        self.calls = []
        self.clock = clock

    def wait_for(self, predicate, *, begun_after_ns, timeout_s):
        self.calls.append(begun_after_ns)
        step = self.script.pop(0)
        if step is None:
            return None, 0, 0
        delay_ns, row = step
        row = dict(row, s=begun_after_ns + delay_ns, e=begun_after_ns + delay_ns + 1_000_000, ok=True)
        assert predicate(row), row
        if self.clock is not None:
            self.clock.now = row["e"] + 1  # the response has arrived
        return row, 2, 0


class _FakeLab:
    def __init__(self):
        self.events = []

    def inject(self, source_type):
        self.events.append(("inject", source_type))

    def recover(self, source_type):
        self.events.append(("recover", source_type))
        return True


HEALTHY = {"suricata": "ON", "uplinks": ["usb0"]}


class _Clock:
    def __init__(self):
        self.now = 5_000_000_000

    def monotonic_ns(self):
        self.now += 1000
        return self.now


@pytest.fixture
def clock(monkeypatch):
    import time as _time
    from types import SimpleNamespace

    c = _Clock()
    monkeypatch.setattr(so02, "time", SimpleNamespace(monotonic_ns=c.monotonic_ns, time=_time.time, monotonic=_time.monotonic, sleep=_time.sleep))
    return c


def test_measure_times_from_injection_to_the_failed_poll(clock):
    lab = _FakeLab()
    poller = _FakePoller(clock=clock, script=
        [
            (1, HEALTHY), (5_000_000, {"suricata": "OFF", "uplinks": ["usb0"]}),
            (1, HEALTHY), (30_000_000_000, {"suricata": "ON", "uplinks": ["br0", "usb0"]}),
        ],
    )
    rows = []
    before = so02.time.monotonic_ns()
    so02._measure(lab, poller, 2, rows)
    assert [r["source_type"] for r in rows] == [PROC, IFACE]
    assert lab.events == [("inject", PROC), ("recover", PROC), ("inject", IFACE), ("recover", IFACE)]
    for r in rows:
        assert rec.so02_failure_observed(r)
        assert r["end_poll_started_monotonic_ns"] >= r["start_monotonic_ns"]
    assert 5 <= rows[0]["elapsed_ms"] < 10
    assert rows[1]["elapsed_ms"] > 30_000
    # The waits are anchored where the definition puts them: each baseline
    # after the previous recovery (never from the beginning of time), each end
    # at the sample's own injection stamp.
    base0, end0, base1, end1 = poller.calls
    assert base0 >= before > 0
    assert end0 == rows[0]["start_monotonic_ns"]
    assert base1 > rows[0]["end_monotonic_ns"] and base1 > end0
    assert end1 == rows[1]["start_monotonic_ns"]
    # The end instant is when the failed poll's response arrived, not when it began.
    for r in rows:
        assert r["end_monotonic_ns"] - r["end_poll_started_monotonic_ns"] == 1_000_000
    assert rec.so02_sequence_problems(rows) == []


def test_measure_never_ends_a_sample_without_a_failed_poll():
    lab = _FakeLab()
    poller = _FakePoller([(1, HEALTHY), None])
    rows = []
    so02._measure(lab, poller, 1, rows)
    assert rows[0]["end_monotonic_ns"] is None and rows[0]["elapsed_ms"] is None
    assert lab.events == [("inject", PROC), ("recover", PROC)]


def test_measure_stops_without_a_healthy_baseline_and_injects_nothing():
    lab = _FakeLab()
    poller = _FakePoller([None])
    rows = []
    so02._measure(lab, poller, 20, rows)
    assert len(rows) == 1 and rows[0]["baseline_healthy"] is False and rows[0]["end_monotonic_ns"] is None
    assert lab.events == []
    assert rec.so02_observed_prerequisites(rows)["every_injection_from_healthy_baseline"] is False


def test_children_get_a_fresh_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_DEV_HEALTHY_BASELINE", "1")
    monkeypatch.setenv("AZAZEL_DEMO_FAST", "1")
    lab = so02._Lab(tmp_path, "/usr/bin/suricata")
    assert "AZAZEL_DEV_HEALTHY_BASELINE" not in lab.env
    assert "AZAZEL_DEMO_FAST" not in lab.env
    assert (tmp_path / "first_minute.yaml").read_text(encoding="utf-8").strip() == "suppress_auto_wifi: false"
    tokens = (tmp_path / "auth_tokens.json").read_text(encoding="utf-8")
    assert '"role": "viewer"' in tokens


@pytest.mark.parametrize(
    "source_type, field, value",
    [
        (PROC, "end_surface_value", "ON"),
        (PROC, "end_surface_value", "UNKNOWN"),
        (PROC, "baseline_surface_value", "OFF"),
        (PROC, "baseline_surface_value", "UNKNOWN"),
        (IFACE, "end_surface_value", ["usb0"]),
        (IFACE, "end_surface_value", None),
        (IFACE, "baseline_surface_value", ["br0", "usb0"]),
        (IFACE, "baseline_surface_value", None),
    ],
)
def test_each_type_is_judged_on_its_own_field(source_type, field, value):
    sample = _sample(0, source_type, 500.0)
    assert rec.so02_failure_observed(sample)
    sample[field] = value
    assert not rec.so02_failure_observed(sample)


def test_forged_end_is_recomputed_as_unfinished(clean_owner, no_gap_table):
    """The end is dropped from the recomputation, not only reported: the
    derived verdict is fail (an unfinished sample is a violation)."""

    record = _forge(_record(_samples()))
    record["parts"][0]["samples"][0]["end_surface_value"] = "ON"
    errors = rec.validate_record(record)
    assert any("record supports 'fail'" in e for e in errors), errors


# --------------------------------------------- forged runs (review of #442)


def test_copied_samples_under_new_ids_are_refused(clean_owner, no_gap_table):
    """Ten honest samples of each type, padded out by copying them under new
    sample ids, overlap their originals in time and are refused."""

    honest = _samples()[:10]
    copies = []
    for k, s in enumerate(honest):
        c = copy.deepcopy(s)
        c["sample_id"] = f"copy-{k}"
        copies.append(c)
    record = _record(honest + copies)
    errors = rec.validate_record(record)
    assert any("injected before the previous sample ended" in e for e in errors), errors


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda s: s.update(end_monotonic_ns=s["start_monotonic_ns"], elapsed_ms=0.0, end_poll_started_monotonic_ns=s["start_monotonic_ns"]), "strictly after"),
        (lambda s: s.update(polls_after_injection=0), "at least one poll"),
        (lambda s: s.update(baseline_poll_started_monotonic_ns=1), "baseline polled before"),
    ],
)
def test_sequence_rules(clean_owner, mutate, needle):
    record = _record(_samples())
    mutate(record["parts"][0]["samples"][3])
    errors = rec.validate_record(record)
    assert any(needle in e for e in errors), errors


def test_out_of_order_samples_are_refused(clean_owner):
    record = _record(_samples())
    ss = record["parts"][0]["samples"]
    ss[4], ss[5] = ss[5], ss[4]
    assert any("out of order" in e for e in rec.validate_record(record))


class _FakeProc:
    def __init__(self, lines):
        self.stdout = iter(lines)

    def poll(self):
        return None


def _line(**row):
    import json as _json

    return _json.dumps(row) + "\n"


def test_real_poller_ignores_polls_begun_before_the_anchor():
    lines = [
        _line(s=100, e=150, ok=True, suricata="OFF"),   # failed, but begun before the injection
        _line(s=199, e=260, ok=True, suricata="OFF"),   # still before
        _line(s=200, e=230, ok=False, err="x"),          # after, error
        _line(s=210, e=240, ok=True, suricata="ON"),
        _line(s=300, e=340, ok=True, suricata="OFF"),   # the end
    ]
    poller = so02._Poller(_FakeProc(lines))
    poller.thread.join(timeout=5)
    row, seen, errors = poller.wait_for(lambda r: r.get("suricata") == "OFF", begun_after_ns=200, timeout_s=1)
    assert row["s"] == 300 and row["e"] == 340
    assert (seen, errors) == (3, 1)
    none, seen, _ = poller.wait_for(lambda r: r.get("suricata") == "OFF", begun_after_ns=301, timeout_s=0.2)
    assert none is None and seen == 0


def _preflight_env(monkeypatch, tmp_path, *, pidfile=False, procs=(), netns=()):
    monkeypatch.setattr(so02.os, "geteuid", lambda: 0)
    monkeypatch.setattr(so02.shutil, "which", lambda name: None if name == "systemctl" else f"/usr/bin/{name}")
    monkeypatch.setattr(so02, "SURICATA_CONFIG", tmp_path / "suricata.yaml")
    (tmp_path / "suricata.yaml").write_text("", encoding="utf-8")
    monkeypatch.setattr(so02, "_run", lambda argv, timeout=0: so02.subprocess.CompletedProcess(argv, 0, "x 1\n", ""))
    pid = tmp_path / "suricata.pid"
    if pidfile:
        pid.write_text("4242", encoding="utf-8")
    monkeypatch.setattr(so02, "SURICATA_PIDFILE", pid)
    proc = tmp_path / "proc"
    proc.mkdir()
    for n, cmd in procs:
        (proc / str(n)).mkdir()
        (proc / str(n) / "cmdline").write_bytes(cmd)
    monkeypatch.setattr(so02, "PROC_ROOT", proc)
    ns = tmp_path / "netns"
    ns.mkdir()
    for name in netns:
        (ns / name).write_text("", encoding="utf-8")
    monkeypatch.setattr(so02, "NETNS_ROOT", ns)


def test_preflight_clean(monkeypatch, tmp_path):
    _preflight_env(monkeypatch, tmp_path, procs=[(1, b"/sbin/init\0")])
    pre = so02.preflight()
    assert pre["problems"] == [] and pre["live_capture"] == []


@pytest.mark.parametrize(
    "kw, needle",
    [
        ({"pidfile": True}, "suricata.pid exists"),
        ({"procs": [(77, b"/usr/bin/suricata\0-i\0eth0\0")]}, "suricata already running (pid [77])"),
        ({"netns": ["so02e-abc123"]}, "left by an earlier run"),
    ],
)
def test_preflight_refuses_a_live_or_leftover_capture(monkeypatch, tmp_path, kw, needle):
    _preflight_env(monkeypatch, tmp_path, **kw)
    pre = so02.preflight()
    assert any(needle in x for x in pre["live_capture"]), pre


def test_preflight_refuses_without_pyyaml(monkeypatch, tmp_path):
    _preflight_env(monkeypatch, tmp_path)
    real = so02._run
    monkeypatch.setattr(
        so02,
        "_run",
        lambda argv, timeout=0: so02.subprocess.CompletedProcess(argv, 1 if argv[-1] == "import yaml" else 0, "x 1\n", ""),
    )
    del real
    assert any("PyYAML" in p for p in so02.preflight()["problems"])


def test_daemon_must_confirm_it_will_not_touch_wifi(monkeypatch, tmp_path):
    lab = so02._Lab(tmp_path, "/usr/bin/suricata")
    for out, ok in (('{"suppress_auto_wifi": true}', False), ("", False), ('{"suppress_auto_wifi": false}', True)):
        monkeypatch.setattr(so02, "_run", lambda argv, timeout=0, out=out: so02.subprocess.CompletedProcess(argv, 0, out + "\n", ""))
        if ok:
            assert "false" in lab.verify_daemon_flags()
        else:
            with pytest.raises(RuntimeError):
                lab.verify_daemon_flags()


def test_pidfile_is_removed_only_if_it_names_our_suricata(monkeypatch, tmp_path):
    pid = tmp_path / "suricata.pid"
    monkeypatch.setattr(so02, "SURICATA_PIDFILE", pid)
    monkeypatch.setattr(so02, "PROC_ROOT", tmp_path)
    lab = so02._Lab(tmp_path / "w", "/usr/bin/suricata")
    lab.started_pids = [111]
    pid.write_text("222", encoding="utf-8")
    assert lab._pidfile_is_ours() is False
    pid.write_text("111", encoding="utf-8")
    assert lab._pidfile_is_ours() is True
    (tmp_path / "111").mkdir()
    (tmp_path / "111" / "cmdline").write_bytes(b"suricata\0")
    assert lab._pidfile_is_ours(dead_only=True) is False


# ------------------------------------------- teardown (re-review of #442)


def test_pids_in_netns_matches_only_the_lab_namespace(monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    netns = tmp_path / "netns"
    netns.mkdir()
    lab_ns = netns / "so02e-abc123"
    lab_ns.write_text("", encoding="utf-8")  # a plain file stands in for the bind mount
    for pid in (101, 202, 303):
        (proc / str(pid) / "ns").mkdir(parents=True)
    import os as _os

    _os.link(lab_ns, proc / "101" / "ns" / "net")  # same (dev, inode): inside the lab
    (proc / "202" / "ns" / "net").write_text("", encoding="utf-8")  # another namespace
    # 303 has no readable ns/net (e.g. a zombie): never matched.
    monkeypatch.setattr(so02, "PROC_ROOT", proc)
    assert so02._pids_in_netns(lab_ns) == [101]
    assert so02._pids_in_netns(netns / "absent") == []


def _teardown_lab(monkeypatch, tmp_path, *, pids_in_ns=(), netns=("so02e-x",)):
    lab = so02._Lab(tmp_path / "w", "/usr/bin/suricata")
    lab.netns_created = list(netns)
    killed, deleted, looked = [], [], []
    monkeypatch.setattr(so02, "_pids_in_netns", lambda path: looked.append(path) or list(pids_in_ns))
    monkeypatch.setattr(so02.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(so02, "_reap", lambda pid, timeout=0: None)
    monkeypatch.setattr(lab, "_ip", lambda *a: deleted.append(a) or so02.subprocess.CompletedProcess(a, 0, "", ""))
    return lab, killed, deleted, looked


def test_teardown_kills_lab_processes_but_never_itself(monkeypatch, tmp_path):
    me = so02.os.getpid()
    lab, killed, deleted, _ = _teardown_lab(monkeypatch, tmp_path, pids_in_ns=(me, 4711))
    monkeypatch.setattr(so02, "SURICATA_PIDFILE", tmp_path / "suricata.pid")
    lab.teardown()
    assert {pid for pid, _ in killed} == {4711}
    assert ("netns", "del", "so02e-x") in deleted


def test_teardown_leaves_a_foreign_pidfile(monkeypatch, tmp_path):
    pidfile = tmp_path / "suricata.pid"
    monkeypatch.setattr(so02, "SURICATA_PIDFILE", pidfile)
    monkeypatch.setattr(so02, "PROC_ROOT", tmp_path / "proc")
    lab, _, _, _ = _teardown_lab(monkeypatch, tmp_path)
    lab.started_pids = [111]
    pidfile.write_text("222", encoding="utf-8")
    lab.teardown()
    assert pidfile.read_text(encoding="utf-8") == "222"
    pidfile.write_text("111", encoding="utf-8")
    lab.netns_created = []
    lab.teardown()
    assert not pidfile.exists()


def test_failed_netns_add_kills_nothing(monkeypatch, tmp_path):
    lab, killed, _, looked = _teardown_lab(monkeypatch, tmp_path, pids_in_ns=(4711,), netns=())
    monkeypatch.setattr(so02, "SURICATA_PIDFILE", tmp_path / "suricata.pid")
    monkeypatch.setattr(lab, "_ip", lambda *a: so02.subprocess.CompletedProcess(a, 1, "", "File exists"))
    with pytest.raises(RuntimeError):
        lab.build()
    assert lab.netns_created == []
    lab.teardown()
    assert looked == [] and killed == []
