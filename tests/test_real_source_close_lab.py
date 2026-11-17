"""Synthetic recipes, original verifier replay and failure-preserving runner guards."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import real_source_close_lab as lab
import run_real_source_close as runner


@pytest.mark.parametrize("case,count,closed", [("clean", 8, True), ("explicit_loss", 7, True), ("abrupt_writer", 4, False)])
def test_prospective_synthetic_recipe_uses_unchanged_v3_source_parser(tmp_path, case, count, closed):
    from auth_input_helpers import make_policy
    from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
    from test_outcome_input_auth import signed
    p, key, *_ = make_policy(tmp_path)
    p = TrustPolicy(dict(p.data, schema_version="outcome-input-trust/v3", origin_registration_sha256="a" * 64))
    rows = lab.recipe(case, session="b" * 32, registration_sha256="a" * 64)
    assert [row["id"] for row in rows] == [f"a{i:02}" for i in range(8)]
    verifier, raw = SourceVerifier(p), b""
    emitted = rows[:4] if case == "abrupt_writer" else [r for r in rows if not (case == "explicit_loss" and r["id"] == "a04")]
    for index, row in enumerate(emitted, 1):
        raw += signed(p, key, seq=index, prev=verifier.head, event=row["event"])
        verifier.verify(raw)
    assert verifier.seq == count and verifier.live_state.closed is closed
    for row in rows[2:7]:
        event = row["event"]
        assert event["enforcement"]["executed_count"] == 0
        assert event["enforcement"]["result"] != "applied"
        assert event["enforcement_status"] == dict(enforce_enabled=False, dry_run=True, high_impact_auto=False)
    if case == "explicit_loss":
        assert rows[4]["native_seq"] is None
        assert [row["native_seq"] for row in emitted] == list(range(7))


def test_new_public_files_are_exclusive_readable_and_private_original_unchanged(tmp_path):
    source = tmp_path / "SYNTHETIC-private-original"
    source.write_bytes(b"SYNTHETIC")
    source.chmod(0o600)
    before = source.stat().st_mode
    target = tmp_path / "public.raw"
    runner.save(target, source.read_bytes())
    assert target.read_bytes() == b"SYNTHETIC" and target.stat().st_mode & 0o777 == 0o644
    assert source.stat().st_mode == before and source.read_bytes() == b"SYNTHETIC"
    with pytest.raises(FileExistsError):
        runner.save(target, b"replace")
    assert target.read_bytes() == b"SYNTHETIC"


def test_output_traversal_refuses_symlink_and_reuse(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "alias"
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises(OSError):
        runner.new_directory(link / "publication")
    assert not (actual / "publication").exists()
    runner.new_directory(actual / "publication")
    assert (actual / "publication").stat().st_mode & 0o777 == 0o755
    with pytest.raises(FileExistsError):
        runner.new_directory(actual / "publication")
    with pytest.raises(ValueError):
        runner.new_directory(Path("relative"))


def synthetic_runner(monkeypatch, tmp_path, *, corrupt_after_analysis=False, analysis_failure=False, launch_failure=False):
    source = tmp_path / "tracked.py"
    source.write_bytes(b"# SYNTHETIC inventory source\n")
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    monkeypatch.setattr(runner, "SOURCES", ("tracked.py",))
    monkeypatch.setattr(runner, "role_boundary", lambda: dict(identity=dict(uid=0), no_new_privileges=1))
    monkeypatch.setenv("EDGE_REAL_SOURCE_CLOSE_SOURCE_HEAD", "a" * 40)
    monkeypatch.setenv("EDGE_REAL_SOURCE_CLOSE_SOURCE_TREE", "b" * 40)
    launched = []

    def launch(directory, case, run_id, inventory):
        launched.append(case)
        if launch_failure:
            runner.save(directory / "source.raw", b"SYNTHETIC-known-prefix\n")
            raise RuntimeError("SYNTHETIC supervisor setup failure")
        for name in tuple(lab.RAW_FILES.values()) + tuple(lab.ARG_FILES.values()) + lab.EXTRAS + runner.OUTER:
            runner.save(directory / name, lab.wire(dict(SYNTHETIC=case)))
        pins = {k + "_sha256": lab.sha((directory / name).read_bytes()) for k, name in {**lab.RAW_FILES, **lab.ARG_FILES}.items()}
        return dict(completion=dict(safe_to_continue=True, expected=pins), returncode=0, timed_out=False,
            capture_errors=[], stdout_decode_error=None, binding_errors=[], streams={})

    def evaluate(raw):
        if analysis_failure:
            raise ValueError("SYNTHETIC analyzer failure")
        pins = {k + "_sha256": lab.sha(raw[name]) for k, name in {**lab.RAW_FILES, **lab.ARG_FILES}.items()}
        if corrupt_after_analysis:
            path = tmp_path / "public" / launched[-1] / "source.raw"
            path.write_bytes(b"SYNTHETIC changed AFTER evaluation\n")
        return pins, {"SYNTHETIC": "analysis"}
    monkeypatch.setattr(runner, "launch", launch)
    monkeypatch.setattr(runner, "evaluate_saved", evaluate)
    monkeypatch.setattr(runner, "disposition", lambda case, analysis: True)
    monkeypatch.setattr(runner, "state_problems", lambda *args: [])
    return launched


def test_runner_synthetic_success_retains_exact_original_refs_and_closed_inventory(monkeypatch, tmp_path):
    launched = synthetic_runner(monkeypatch, tmp_path)
    result = runner.run(tmp_path / "public")
    assert launched == list(lab.CASES) and result["blockers"] == []
    manifest = json.loads((tmp_path / "public/manifest.json").read_bytes())
    assert manifest["missing_or_errors"] == {} and manifest["inventory_errors"] == []
    for case in lab.CASES:
        original = tmp_path / "public" / case / "source.raw"
        assert original.read_bytes() == lab.wire(dict(SYNTHETIC=case))
        row = next(row for row in result["cases"] if row["case_id"] == case)
        assert set(row["artifacts"]) == set(runner.CASE_FILES)
        assert all(desc is not None for desc in row["artifacts"].values())
        for name in runner.CASE_FILES:
            raw = (tmp_path / "public" / case / name).read_bytes()
            cached = row["artifacts"][name]
            expected = dict(bytes=len(raw), sha256=lab.sha(raw))
            assert {key: cached[key] for key in expected} == expected
            assert manifest["files"][case + "/" + name] == expected
        assert manifest["files"][case + "/source.raw"]["sha256"] == lab.sha(original.read_bytes())
    assert not any("private" in key or "key" in key for key in manifest["files"])


def test_analyzer_failure_keeps_all_actual_original_siblings_and_top_report(monkeypatch, tmp_path):
    launched = synthetic_runner(monkeypatch, tmp_path, analysis_failure=True)
    result = runner.run(tmp_path / "public")
    assert launched == list(lab.CASES)
    assert len(result["blockers"]) >= 3
    for case in result["cases"]:
        assert case["errors"]["analysis"] == "ValueError"
        assert (tmp_path / "public" / case["case_id"] / "source.raw").exists()
        assert (tmp_path / "public" / case["case_id"] / "trust.json").exists()
    assert (tmp_path / "public/report.json").exists() and (tmp_path / "public/manifest.json").exists()


def test_supervisor_failure_keeps_prefix_and_stops_later_cases(monkeypatch, tmp_path):
    launched = synthetic_runner(monkeypatch, tmp_path, launch_failure=True)
    result = runner.run(tmp_path / "public")
    assert launched == ["clean"]
    assert "clean:supervisor_launch_or_collection_failed" in result["blockers"]
    assert (tmp_path / "public/clean/source.raw").read_bytes() == b"SYNTHETIC-known-prefix\n"
    assert result["cases"][1]["errors"]["not_run"] == "prior_unsafe_or_source_enrollment_failure"
    assert (tmp_path / "public/report.json").exists()


def test_final_reread_never_repins_changed_source_as_original_success(monkeypatch, tmp_path):
    synthetic_runner(monkeypatch, tmp_path, corrupt_after_analysis=True)
    result = runner.run(tmp_path / "public")
    assert len([x for x in result["blockers"] if "original_changed_or_missing_after_analysis" in x]) == 3
    case = result["cases"][0]
    first_sha = case["artifacts"]["source.raw"]["sha256"]
    final_sha = result["final_fence"]["clean/source.raw"]["sha256"]
    assert first_sha != final_sha and first_sha == case["expected"]["source_sha256"]


def test_source_inventory_final_fence_detects_mutation_and_keeps_both_hashes(tmp_path, monkeypatch):
    source = tmp_path / "tracked.py"
    source.write_bytes(b"before")
    initial = dict(bytes=6, sha256=lab.sha(b"before"))
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    source.write_bytes(b"after")
    problems, observed = runner.final_fences(tmp_path, [], {"tracked.py": initial})
    assert problems == ["tracked.py:source_inventory_changed_after_analysis"]
    assert observed["source:tracked.py"]["sha256"] != initial["sha256"]


def test_collector_private_probe_never_reads_unexpectedly_accessible_bytes(monkeypatch, tmp_path):
    import azazel_edge.benchmark.real_source_close_collection as collection
    actual_open, reads, replies = lab.os.open, [], []
    public = tmp_path / "SYNTHETIC-unexpected-access"
    public.write_bytes(b"DO NOT READ")
    missing = tmp_path / "SYNTHETIC-denied"
    class ProbeOS:
        def __getattr__(self, key):
            return getattr(os, key)
        def open(self, path, flags, *args, **kwargs):
            if path == str(missing):
                raise PermissionError(13, "SYNTHETIC")
            return actual_open(path, flags, *args, **kwargs)
        def read(self, *args):
            reads.append(args)
            raise AssertionError("private probe must never read")
    monkeypatch.setattr(lab, "os", ProbeOS())
    monkeypatch.setattr(lab, "role_boundary", lambda: {})
    monkeypatch.setattr(lab, "command", lambda: dict(command="read", expected_identity={}, private_probes=[str(missing), str(public)]))
    monkeypatch.setattr(lab, "reply", replies.append)
    monkeypatch.setattr(collection, "collect_regular_source_fd", lambda *args, **kwargs: dict(raw=b"SYNTHETIC", receipt={}))
    lab.collector_worker(777, tmp_path)
    assert reads == [] and replies[-1]["private_probes_denied"] == [True, False]


def test_missing_state_or_child_completion_blocks_without_invented_facts():
    assert runner.state_problems("clean", {}, {"completion": None}) == ["original_controller_or_state_unavailable"]


def test_actor_launch_passes_only_held_source_fd_and_hardens_existing_child_role(monkeypatch, tmp_path):
    import io
    calls, registry = [], []
    class Pipe(io.BytesIO):
        def fileno(self):
            return 333
    process = SimpleNamespace(stdin=Pipe(), stdout=Pipe(), stderr=Pipe())
    class Selector:
        def register(self, *args):
            assert registry[0].process is process
    actual_os = lab.os
    class ActorOS:
        def __getattr__(self, name):
            return getattr(actual_os, name)
        def set_blocking(self, *args):
            pass
    monkeypatch.setattr(lab, "os", ActorOS())
    monkeypatch.setattr(lab, "selectors", SimpleNamespace(DefaultSelector=Selector, EVENT_READ=1))
    monkeypatch.setattr(lab, "subprocess", SimpleNamespace(Popen=lambda argv, **kwargs: (calls.append((argv, kwargs)) or process), PIPE=-1))
    lab.Actor("collector", uid=61002, registry=registry, fd=77, arguments=("--output", tmp_path))
    argv, kwargs = calls[0]
    assert kwargs["pass_fds"] == (77,) and kwargs["close_fds"] is True
    assert all(flag in argv for flag in ("--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--clear-groups", "--reuid=61002"))


def test_invalid_supervision_halts_later_cases_even_if_completion_claims_safe(monkeypatch, tmp_path):
    launched = synthetic_runner(monkeypatch, tmp_path)
    original_launch = runner.launch
    def bad_child(*args):
        result = original_launch(*args)
        result["binding_errors"] = ["SYNTHETIC wrong bootstrap PID"]
        assert result["completion"]["safe_to_continue"] is True
        return result
    monkeypatch.setattr(runner, "launch", bad_child)
    result = runner.run(tmp_path / "public")
    assert launched == ["clean"]
    assert "clean:supervision_or_controller_evidence_failed" in result["blockers"]
    assert all(case["errors"].get("not_run") for case in result["cases"][1:])
    assert (tmp_path / "public/clean/source.raw").exists()


def test_producer_original_close_failure_is_never_retried(monkeypatch, tmp_path):
    import azazel_edge.outcome.input_auth as auth
    calls, replies = [], []
    class Writer:
        fd = 777
        def append(self, event):
            calls.append("append")
        def close(self):
            calls.append("close")
            raise OSError(5, "SYNTHETIC ambiguous close")
    monkeypatch.setattr(auth.TrustPolicy, "from_file", lambda *a, **k: SimpleNamespace(data={}))
    monkeypatch.setattr(auth, "SignedCaptureWriter", lambda *a, **k: Writer())
    monkeypatch.setattr(lab, "role_boundary", lambda: {})
    monkeypatch.setattr(lab, "reply", replies.append)
    work = iter([dict(command="start", case_id="clean", events=[dict(event={}) for _ in range(8)]), dict(command="finish")])
    monkeypatch.setattr(lab, "command", lambda: next(work))
    with pytest.raises(OSError, match="ambiguous close"):
        lab.producer_worker(tmp_path / "trust", tmp_path / "key", "SYNTHETIC")
    assert calls == ["append"] * 8 + ["close"]
    assert [row["kind"] for row in replies] == ["blocked", "prefix"]


def test_failed_witness_stop_retains_fixture_and_reports_unsafe(monkeypatch, tmp_path):
    import test_outcome_input_auth_linux as original
    from auth_input_helpers import make_policy
    fixture_root = tmp_path / "private-fixture"
    fixture_root.mkdir()
    p, *_ = make_policy(fixture_root, producer=1000, observer=65534, witness=0)
    source = Path(p.data["source_path"])
    source.write_bytes(b"SYNTHETIC known prefix")
    clean_calls, halt_calls = [], []
    class Fixture:
        def __init__(self):
            self.root, self.p, self.source = fixture_root, p, source
            self.policy_file = fixture_root / "trust.json"
            self.anchors = fixture_root / "absent-anchors"
            self.journal = fixture_root / "absent-journal"
            self.errors, self.thread = [OSError(5, "SYNTHETIC backend")], object()
        def start(self, **kwargs):
            raise OSError(5, "SYNTHETIC setup fails")
        def halt(self):
            halt_calls.append(True)
            raise TimeoutError("SYNTHETIC witness remains live")
        def clean(self):
            clean_calls.append(True)
            raise AssertionError("must retain unfinished private fixture")
    monkeypatch.setattr(original, "Fixture", Fixture)
    monkeypatch.setattr(lab, "actor_identity", lambda pid: dict(pid=pid, uid=0))
    monkeypatch.setattr(lab, "role_boundary", lambda: {})
    actual_os = lab.os
    class RootOS:
        def __getattr__(self, name):
            return getattr(actual_os, name)
        def geteuid(self):
            return 0
    monkeypatch.setattr(lab, "os", RootOS())
    output = tmp_path / "output"
    output.mkdir()
    result = lab.collect_case(output, "clean", run_id="SYNTHETIC", source_inventory_sha256="a" * 64)
    assert result["safe_to_continue"] is False
    assert halt_calls == [True] and clean_calls == [] and fixture_root.exists()
    assert (output / "source.raw").read_bytes() == b"SYNTHETIC known prefix"
    state = json.loads((output / "case-state.json").read_bytes())
    assert state["errors"]["witness_stop"]["type"] == "TimeoutError"
    assert state["witness_backend_errors"] == [dict(type="OSError", errno=5)]
    assert state["stage_facts"]["artifact_export_origins"]["source.raw"] == "ROOT_FALLBACK_ORIGINAL_READ_NOT_INDEPENDENT_COLLECTOR"
    assert not (output / "collection.json").exists()
    assert result["expected"]["read_sha256"] is None


def child_proc_fixture(tmp_path):
    pid = 4242
    base = tmp_path / str(pid)
    base.mkdir()
    fields = ["S"] + ["0"] * 18 + ["12345"]
    (base / "stat").write_text(str(pid) + " (SYNTHETIC child) " + " ".join(fields))
    (base / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
    (base / "timens_offsets").write_text("monotonic 0 0\nboottime 0 0\n")
    boot = tmp_path / "boot-id"
    boot.write_text("SYNTHETIC-boot\n")
    domain = dict(time_namespace_device=5, time_namespace_inode=6, established=True,
        timens_offsets=[dict(clock=k, seconds=0, nanoseconds=0) for k in ("monotonic", "boottime")])
    declared = dict(pid=pid, uid=1000, process_start_ticks=12345, boot_id="SYNTHETIC-boot", clock_domain=domain)
    return pid, base, boot, declared, dict(clock_domain=domain)


def test_cross_uid_binding_never_attempts_denied_namespace_read(tmp_path, monkeypatch):
    pid, base, boot, declared, controller = child_proc_fixture(tmp_path)
    actual_read, actual_stat = Path.read_text, Path.stat
    forbidden = []
    def guard(path):
        if str(path).endswith("/ns/time"):
            forbidden.append(str(path))
            raise PermissionError(13, "SYNTHETIC denied crossuid namespace")
    def read(path, *args, **kwargs):
        guard(path)
        return actual_read(path, *args, **kwargs)
    def stat(path, *args, **kwargs):
        guard(path)
        return actual_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(Path, "stat", stat)
    result = lab.bind_child_identity(pid, declared, controller, expected_uid=1000, proc_root=tmp_path, boot_path=boot)
    assert result["identity"] == declared and forbidden == []
    proof = result["clock_provenance"]
    assert proof["matched"] is True and proof["cross_uid_namespace_lookup"] == "NOT_ATTEMPTED"
    assert proof["basis"] == "TRUSTED_LAUNCHER_PINNED_WORKER_SELF_READ"
    assert proof["precollection_probe"]["errno"] == 13
    assert proof["precollection_probe"]["source"] == "HISTORICAL_LOCAL_FEATURE_PROBE"
    assert "NOT_FRESH_CASE_OR_CI_OBSERVATION" in proof["precollection_probe"]["environment"]


@pytest.mark.parametrize("fault", ["start", "uid", "boot", "offsets", "domain", "missing"])
def test_child_domain_or_incarnation_failure_stays_unknown_without_fallback(tmp_path, fault):
    pid, base, boot, declared, controller = child_proc_fixture(tmp_path)
    if fault == "start":
        declared["process_start_ticks"] += 1
    elif fault == "uid":
        declared["uid"] = 61002
    elif fault == "boot":
        declared["boot_id"] = "SYNTHETIC-other-boot"
    elif fault == "offsets":
        (base / "timens_offsets").write_text("monotonic 1 0\nboottime 0 0\n")
    elif fault == "domain":
        declared = dict(declared, clock_domain=None)
    else:
        (base / "stat").unlink()
    result = lab.bind_child_identity(pid, declared, controller, expected_uid=1000, proc_root=tmp_path, boot_path=boot)
    assert result["clock_provenance"]["matched"] is False
    assert result["identity"]["clock_domain"] is None
    assert result["clock_provenance"]["reasons"]


@pytest.mark.parametrize("leaf", ["source.raw", "analysis.json", "child-stdout.raw", "child-stderr.raw", "child-process.json", "source-inventory.json"])
def test_manifest_final_read_cannot_adopt_post_fence_raw_or_analysis_mutation(monkeypatch, tmp_path, leaf):
    synthetic_runner(monkeypatch, tmp_path)
    actual_fences = runner.final_fences
    def change_after_fence(output, cases, sources):
        result = actual_fences(output, cases, sources)
        (output / "clean" / leaf).write_bytes(b'{"SYNTHETIC":"changed_after_fence"}\n')
        return result
    monkeypatch.setattr(runner, "final_fences", change_after_fence)
    result = runner.run(tmp_path / "public")
    manifest = json.loads((tmp_path / "public/manifest.json").read_bytes())
    name = "clean/" + leaf
    assert manifest["missing_or_errors"][name] == "final_manifest_read_differs_from_original_pin"
    mismatch = manifest["final_read_disagreements"][name]
    assert mismatch["original"]["sha256"] != mismatch["observed"]["sha256"]
    assert mismatch["original"]["sha256"] == result["cases"][0]["artifacts"][leaf]["sha256"]
    assert mismatch["observed"]["sha256"] == lab.sha((tmp_path / "public/clean" / leaf).read_bytes())
    report = json.loads((tmp_path / "public/report.json").read_bytes())
    assert report == result  # Preserve original evaluation, separate integrity failure.
    if leaf == "analysis.json":
        assert lab.sha(lab.wire(report["cases"][0]["analysis"])) == mismatch["original"]["sha256"]
