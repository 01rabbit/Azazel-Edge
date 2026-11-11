"""Real recorder/pipe bytes; declared synthetic Root/namespace identities, no VM."""

import hashlib
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError
from test_signed_network_recording import collect

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_run as run


@pytest.fixture
def recorder(tmp_path, monkeypatch):
    path = tmp_path / "collector"
    event, _ = collect(path)
    closed = path.read_bytes()
    opened = b"".join(closed.splitlines(keepends=True)[:-1])
    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    monkeypatch.setattr(
        run,
        "read_regular",
        lambda *a, **k: (
            path.read_bytes(),
            SimpleNamespace(st_dev=4, st_ino=5, st_uid=61002),
        ),
    )
    return path, event, closed, opened


@pytest.mark.parametrize("tail", [b"", b'{"partial'])
def test_actual_callback_retains_original_bytes_and_original_complete_row(
    recorder, tail
):
    path, event, _, opened = recorder
    path.write_bytes(opened + tail)
    receipt = run._callback(
        event,
        "active",
        session=SimpleNamespace(poll=lambda: None),
        deadline_ns=time.monotonic_ns() + 1_000_000_000,
    )
    root = path.parent
    assert (root / "active-callback-observation-0.raw").read_bytes() == opened + tail
    assert (root / "active-callback-prefix.raw").read_bytes() == opened + tail
    assert (root / "active-callback-complete.raw").read_bytes() == opened
    assert receipt["row"]["data"]["event"] == event
    assert receipt["raw_sha256"] == hashlib.sha256(opened + tail).hexdigest()
    assert receipt["partial_tail_bytes"] == len(tail)
    assert receipt["recording_identity"] == dict(device=4, inode=5, uid=61002)
    assert receipt["observed_before_ns"] <= receipt["observed_after_ns"]
    # Later real sample/finalize calls follow the event; it need not be last.
    assert run.recording.decode_calls_prefix(opened)["calls"][-1] != receipt["row"]


@pytest.mark.parametrize(
    "fault", ["closed", "bad-complete", "future-clock", "duplicate"]
)
def test_callback_refusal_retains_failure_bytes_without_ready_authority(
    recorder, fault
):
    path, event, closed, opened = recorder
    raw = closed if fault == "closed" else opened
    if fault == "bad-complete":
        raw += b'{"invalid"}\n{'
    if fault in {"future-clock", "duplicate"}:
        rows = [json.loads(line) for line in opened.splitlines()]
        row = next(row for row in rows if row["kind"] == "event")
        if fault == "future-clock":
            row["data"]["clock_after"]["monotonic_after_ns"] = (
                time.monotonic_ns() + 10**12
            )
        else:
            rows.insert(rows.index(row) + 1, json.loads(json.dumps(row)))
        previous = "0" * 64
        for index, row in enumerate(rows):
            row["seq"], row["prev"] = index, previous
            row["sha256"] = run.recording.manifest_digest(
                {k: row[k] for k in ("seq", "prev", "kind", "data")}
            )
            previous = row["sha256"]
        raw = b"".join(run.recording.canonical(row) + b"\n" for row in rows)
    path.write_bytes(raw)
    with pytest.raises((BenefitInputError, ValueError)):
        run._callback(
            event,
            "active",
            session=SimpleNamespace(poll=lambda: None),
            deadline_ns=time.monotonic_ns() + 10**9,
        )
    assert (path.parent / "active-callback-observation-0.raw").read_bytes() == raw
    assert not (path.parent / "active-callback-ready.json").exists()


@pytest.mark.parametrize("fault", ["dead", "deadline", "kind", "missing"])
def test_no_callback_or_budget_never_produces_ready(recorder, monkeypatch, fault):
    path, event, _, opened = recorder
    path.write_bytes(opened.splitlines(keepends=True)[0])
    if fault == "missing":
        monkeypatch.setattr(run.time, "sleep", lambda _: None)
    with pytest.raises(BenefitInputError):
        run._callback(
            event,
            "other" if fault == "kind" else "active",
            session=SimpleNamespace(poll=lambda: 1 if fault == "dead" else None),
            deadline_ns=time.monotonic_ns() + (-1 if fault == "deadline" else 10**9),
        )
    assert not (path.parent / "active-callback-ready.json").exists()


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "bool-root",
        "pid",
        "partial",
        "nonzero",
        "late-wall",
        "early-mono",
        "horizon",
    ],
)
def test_root_query_binds_raw_original_child_and_callback_cutoffs(
    tmp_path, monkeypatch, fault
):
    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    identity = dict(
        source_revision="a" * 40, helper_sha256="b" * 64, network_driver_sha256="c" * 64
    )
    monkeypatch.setattr(run, "_source_identity", lambda: identity)
    monkeypatch.setattr(run.g, "boot", lambda: "boot-actual-fixture")
    now = time.monotonic_ns()
    receipt = dict(
        root_pid=123,
        root_uid=0,
        argv=list(run.flow.QUERY),
        returncode=0,
        source_identity=identity,
        kernel_boot_id="boot-actual-fixture",
        netns_inode=2,
        stdout='{"nftables":[]}',
        stderr="",
        query_started_at="2026-11-12T00:00:01+00:00",
        query_ended_at="2026-11-12T00:00:01.100000+00:00",
        query_start_clock_anchor=dict(monotonic_before_ns=now),
        query_end_clock_anchor=dict(monotonic_after_ns=now),
    )
    callback = dict(observed_after_ns=now - 1, row=dict(data=dict(epoch=1794441600.0)))
    if fault == "bool-root":
        receipt["root_uid"] = False
    if fault == "pid":
        receipt["root_pid"] = 999
    if fault == "late-wall":
        callback["row"]["data"]["epoch"] -= 3
    if fault == "early-mono":
        receipt["query_start_clock_anchor"]["monotonic_before_ns"] = now - 2
    raw = json.dumps(receipt).encode() + (b"" if fault == "partial" else b"\n")
    read, write = os.pipe()
    os.write(write, raw)
    os.close(write)
    with os.fdopen(read, "rb") as stream:
        child = SimpleNamespace(
            pid=123,
            args=["original-child"],
            stdout=stream,
            returncode=1 if fault == "nonzero" else 0,
            wait=lambda **kw: 0,
        )
        assets = SimpleNamespace(
            created={run.p.EDGE: (None, 1, 2)}, spawn=lambda *a, **kw: child
        )
        kwargs = dict(
            deadline_ns=time.monotonic_ns() + 10**9,
            callback=callback,
            horizon_ns=now - 1 if fault == "horizon" else now + 10**9,
        )
        if fault:
            with pytest.raises(BenefitInputError):
                run.root_query(assets, "active", {}, **kwargs)
        else:
            assert run.root_query(assets, "active", {}, **kwargs)[0] == receipt
    assert (tmp_path / "active-query.raw").read_bytes() == raw
    launch = json.loads((tmp_path / "active-query-launch.json").read_bytes())
    assert launch["pid"] == 123 and launch["actual_child_argv"] == ["original-child"]
    assert launch["launch_before_ns"] <= launch["launch_after_ns"]
    assert (tmp_path / "active-query.json").exists() == (fault is None)


@pytest.mark.parametrize("fault", ["source", "intent", "cleanup-too"])
def test_direct_preparation_context_cleanup_survives_early_runner_failure(
    tmp_path, monkeypatch, fault
):
    """Synthetic ownership context; no actor creation or authentication claim."""
    import types

    events = []
    original = RuntimeError("original-source-failure")

    def source():
        if fault != "intent":
            raise original
        return {}

    def close():
        events.append("context-close")
        if fault == "cleanup-too":
            raise ValueError("independent cleanup failed")

    ctx = SimpleNamespace(inputs={}, close=close)
    prep = types.ModuleType("signed_network_telemetry_phase")
    prep.prepare_telemetry_assignment = lambda *a, **k: ctx
    monkeypatch.setitem(sys.modules, prep.__name__, prep)
    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    monkeypatch.setattr(run.g, "boot", lambda: "fixture-boot")
    monkeypatch.setattr(run, "_source_identity", source)
    if fault == "intent":
        save = run.n.write_new

        def fail_intent(path, value):
            if path.name == "run-intent.json":
                raise original
            return save(path, value)

        monkeypatch.setattr(run.n, "write_new", fail_intent)
    with pytest.raises(RuntimeError) as caught:
        run.run_telemetry_assignment(
            tmp_path,
            **{
                k: "a" * 64
                for k in (
                    "manifest_sha256",
                    "start_head",
                    "source_commit",
                    "archive_sha256",
                    "core_sha256",
                    "abi_sha256",
                    "interpreter_sha256",
                )
            },
        )
    assert caught.value is original and events == ["context-close"]
    assert not (tmp_path / "run-facts.json").exists()
    failure = json.loads((tmp_path / "run-failure.json").read_bytes())
    assert failure["status"] == "withheld" and failure["error"] == "RuntimeError"
    if fault == "cleanup-too":
        assert any(
            "Owned context cleanup: ValueError" in note
            for note in caught.value.__notes__
        )


@pytest.mark.parametrize("fault", ["label", "callback-not-yet-retained"])
def test_query_cannot_spawn_before_closed_kind_and_retained_callback(
    tmp_path, monkeypatch, fault
):
    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    spawned = []
    assets = SimpleNamespace(spawn=lambda *a, **kw: spawned.append(a))
    with pytest.raises(BenefitInputError):
        run.root_query(
            assets,
            "unknown" if fault == "label" else "active",
            {},
            deadline_ns=time.monotonic_ns() + 10**9,
            callback=dict(observed_after_ns=time.monotonic_ns() + 10**9),
        )
    assert spawned == [] and list(tmp_path.iterdir()) == []


def test_query_worker_uses_real_validator_positional_signature(monkeypatch):
    """Bind against the frozen preparation function signature, without Root IO."""
    import ast
    import inspect
    import importlib.util
    import types

    # Load just the actual function declaration: its body has no execution here.
    source = Path(importlib.util.find_spec("signed_network_telemetry_phase").origin)
    tree = ast.parse(source.read_text())
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "validated_telemetry_inputs"
    )
    declaration = ast.FunctionDef(
        name=node.name, args=node.args, body=[ast.Pass()], decorator_list=[]
    )
    namespace = {}
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[declaration], type_ignores=[])),
            str(source),
            "exec",
        ),
        namespace,
    )
    signature = inspect.signature(namespace[node.name])
    sentinel = RuntimeError("constructor reached with correct arguments")

    def exact(*args, **kwargs):
        bound = signature.bind(*args, **kwargs)
        assert bound.arguments["expected_manifest_sha256"] == "manifest"
        assert bound.arguments["expected_start_head"] == "head"
        raise sentinel

    module = types.ModuleType("signed_network_telemetry_phase")
    module.validated_telemetry_inputs = exact
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(run.g, "guard", lambda: None)
    monkeypatch.setattr(run.os, "geteuid", lambda: 0)
    monkeypatch.setenv("EDGE_SIGNED_NETWORK_TELEMETRY", "1")
    pins = dict(
        manifest_sha256="manifest",
        start_head="head",
        source_commit="a",
        archive_sha256="b",
        core_sha256="c",
        abi_sha256="d",
        interpreter_sha256="e",
    )
    with pytest.raises(RuntimeError) as caught:
        run._query_worker(pins)
    assert caught.value is sentinel and pins["manifest_sha256"] == "manifest"


@pytest.mark.parametrize("candidate", [False, True])
@pytest.mark.parametrize("output_state", ["fresh", "existing", "dangling"])
def test_direct_context_complete_lifecycle_real_service_capture_synthetic_actors(
    tmp_path, monkeypatch, candidate, output_state
):
    """Actual orchestration/decision/capture/parser; synthetic actors/source/clock/IO."""
    from contextlib import contextmanager
    import types
    import test_signed_network_run as legacy

    log, work, clock, reader, event, released = legacy.run_fixture(
        tmp_path, monkeypatch, candidate=candidate
    )
    monkeypatch.setattr(run, "time", clock)
    monkeypatch.setattr(run, "_source_identity", lambda: dict(synthetic=True))
    trust = run.TrustPolicy.from_file("ignored")
    inputs = run.phase.validated_inputs()
    inputs["assignment"]["arm"] = "flow_throttle" if candidate else "c0"
    monkeypatch.setattr(
        run,
        "registration",
        lambda *a: dict(
            environment=run.plan.native_environment(inputs["assignment"]["arm"])
        ),
    )
    assets, _ = run.old.scope.reopen_assets(work)
    spawn = assets.spawn
    children = []

    def child(*a, **k):
        process = spawn(*a, **k)
        process.pid = 1000 + len(children)
        children.append(process)
        return process

    assets.spawn = child

    def close():
        log.append("direct-owned-context-close")

    ctx = SimpleNamespace(
        inputs=inputs,
        namespaces=SimpleNamespace(
            assets=assets, edge=lambda: log.append("owned-edge-fence")
        ),
        initialization={"direct": True},
        args={},
        owned=set(),
        tracked={},
        close=close,
    )
    prep = types.ModuleType("signed_network_telemetry_phase")
    prep.prepare_telemetry_assignment = lambda *a, **k: ctx
    monkeypatch.setitem(sys.modules, prep.__name__, prep)
    monkeypatch.setattr(
        run.g, "systemctl", lambda *a: log.append("ordinary-core-start")
    )
    monkeypatch.setattr(run.g, "wait_for", lambda check: check())
    monkeypatch.setattr(run.g, "Systemd", lambda: SimpleNamespace(cores=lambda: [123]))
    monkeypatch.setattr(run.lab, "unit_snapshot", lambda unit: dict(unit=unit))
    monkeypatch.setattr(
        run.g,
        "Switch",
        lambda *a: SimpleNamespace(
            plan=lambda: {}, apply=lambda *a: dict(status="started")
        ),
    )
    monkeypatch.setattr(run.g, "live", lambda: log.append("sealed-native-live"))
    query = run.old.root_query

    def root_query(assets, label, pins, **kwargs):
        if label == "active":
            assert (work / "active-callback-ready.json").exists()
        if label == "absence" and candidate:
            assert (work / "absence-callback-ready.json").exists()
        return query(assets, label)

    monkeypatch.setattr(run, "root_query", root_query)
    original_json = run.old._json
    directory = Path(trust.data["journal_directory"])
    closed_raw = (directory / "actual-collector-calls.jsonl").read_bytes()
    source_rows = [json.loads(line) for line in closed_raw.splitlines()]
    active = [False]

    def calls():
        rows = [source_rows[0]]
        for row in source_rows[1:-1]:
            release_row = row["data"]["event"] == released
            when = 32_250_000_000 if release_row else 2_250_000_000
            if release_row and clock.ns < when:
                continue
            row = json.loads(json.dumps(row))
            row["data"].update(epoch=100 + when / 1e9, start_ns=when, end_ns=when)
            for key in ("clock_before", "clock_after"):
                row["data"][key] = dict(
                    monotonic_before_ns=when,
                    monotonic_after_ns=when,
                    epoch_ns=100_000_000_000 + when,
                )
            rows.append(row)
        if not active[0]:
            rows.append(source_rows[-1])
        previous = "0" * 64
        for index, row in enumerate(rows):
            row["seq"], row["prev"] = index, previous
            row["sha256"] = run.recording.manifest_digest(
                {k: row[k] for k in ("seq", "prev", "kind", "data")}
            )
            previous = row["sha256"]
        return b"".join(run.recording.canonical(row) + b"\n" for row in rows)

    monkeypatch.setattr(
        run,
        "read_regular",
        lambda path, **kw: (
            calls()
            if Path(path).name == "actual-collector-calls.jsonl"
            else b"journal\n",
            SimpleNamespace(st_dev=4, st_ino=5, st_uid=61002),
        ),
    )

    # Root offline validation executes both reviewed physical guards unchanged.
    # Host nonroot authoring uses only an explicit ownership adapter here.
    preflight = run.observer.material.preflight.old
    if os.geteuid() != 0:
        monkeypatch.setattr(
            preflight, "private_output", lambda output: output.mkdir(mode=0o700)
        )
    if output_state == "existing":
        (work / "live").mkdir(mode=0o700)
    elif output_state == "dangling":
        (work / "live").symlink_to(work / "never-created")

    @contextmanager
    def live(output, **kwargs):
        log.append("fake-live-entry")
        assert kwargs["initialization"] is ctx.initialization
        assert output.is_dir() and output.stat().st_mode & 0o777 == 0o700
        if os.geteuid() == 0:
            run.observer.proof.p._output(output)
        launch = dict(
            client_launch_before_ns=clock.ns,
            client_launch_after_ns=clock.ns,
            client_pid=999,
        )
        run.n.write_new(output / "live-launch.json", launch)
        session = SimpleNamespace(
            client_launch_before_ns=clock.ns, poll=lambda: None, result=None
        )
        active[0] = True
        yield session
        active[0] = False
        session.result = dict(terminal=original_json(Path("observer-terminal.json")))
        log.append("natural-live-helper-return")

    monkeypatch.setattr(run.observer, "live", live)
    pins = {
        k: "a" * 64
        for k in (
            "manifest_sha256",
            "start_head",
            "source_commit",
            "archive_sha256",
            "core_sha256",
            "abi_sha256",
            "interpreter_sha256",
        )
    }
    if output_state != "fresh":
        with pytest.raises(FileExistsError):
            run.run_telemetry_assignment(work, **pins)
        assert "fake-live-entry" not in log
        assert log[-1] == "direct-owned-context-close"
        assert not (work / "run-facts.json").exists()
        assert (work / "live").is_symlink() == (output_state == "dangling")
        return
    result = run.run_telemetry_assignment(work, **pins)
    assert result["status"] == "run_facts_complete"
    assert result["record"]["service_receipt"] and result["record"]["capture"]
    assert (
        result["measurement_completed"] is False
        and result["production_admission"] is False
    )
    assert (
        log.index("root-readonly-active")
        < log.index("capture-core-stop")
        < log.index("natural-live-helper-return")
        < log.index("direct-owned-context-close")
    )
    for kind, child_process in zip(("service", "client"), children):
        receipt = json.loads((work / (kind + "-peer-launch.json")).read_bytes())
        assert (
            receipt["pid"] == child_process.pid
            and receipt["actual_child_argv"] == child_process.args
        )
    assert result["record"]["observer_helper_return_ns"] <= 41_000_000_000
    assert (
        result["record"]["controller_start_anchor"]["monotonic_before_ns"]
        < result["record"]["controller_end_anchor"]["monotonic_after_ns"]
    )
