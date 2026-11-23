"""Synthetic immutable snapshot/error disposition and explicit v2 integration."""

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

REAL = Path(__file__).parent / "real_systemd"
sys.path.insert(0, str(REAL))
import fresh_source_observe as lab  # noqa:E402
from azazel_edge.benchmark import fresh_source_observe_v2 as core  # noqa:E402
from fresh_source_data_v2 import make_fresh_case, pins  # noqa:E402


def publication_lab(tmp_path):
    instance = object.__new__(lab.FreshSourceObserveV2Lab)
    instance.g = SimpleNamespace(BASE=tmp_path, record=lambda *args, **kwargs: None)
    instance.public_directory = "fresh-v2-public"
    (tmp_path / instance.public_directory).mkdir()
    instance.core = core
    instance.protocol_sha256 = core.PROTOCOL_SHA256
    instance.run_ref = "a" * 32
    instance.run_started_ns = 1
    instance.source_revision = "b" * 40
    instance.results = []
    instance.outer_errors = []
    instance.contexts = {}
    instance.case_dispositions = {
        case: dict(
            case_id=case,
            state="not_run",
            snapshot_manifest_sha256=None,
            evaluation_sha256=None,
            error=None,
            cleanup_errors=[],
        )
        for case in lab.CASES
    }
    return instance


def add_case(instance, case="fresh-controls"):
    artifacts = make_fresh_case(case)
    context = dict(
        files=artifacts,
        controller=json.loads(artifacts["close-controller.json"]),
        exported=False,
        analysis_accepted=False,
    )
    instance.contexts[case] = context
    instance.source_revision = context["controller"]["source_revision"]
    return context


def inventory(directory):
    return {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}


@pytest.mark.parametrize("case", lab.CASES)
def test_v2_composed_original_clock_or_fault_and_publication(case):
    artifacts = make_fresh_case(case)
    expected = pins(artifacts)
    result = core.evaluate_fresh_source_case(artifacts, expected=expected)
    assert (
        result["status"] in ("bound_fresh_controls", "bound_interrupted_prefix")
        and result["publication"]["status"] == "qualified"
    ), result
    observer = lab.evaluate_fresh_observer_originals(artifacts, expected, version=2)
    assert observer["error"] is None, observer
    if case == "fresh-controls":
        assert (
            observer["clock"]["status"] == "qualified"
            and observer["normal_completion"] is True
        )
    else:
        assert observer["fault_verified"] is True and observer["clock"] is None


def test_postexport_qualification_failure_never_adds_snapshot_failure_file(tmp_path):
    instance = publication_lab(tmp_path)
    context = add_case(instance)
    result = instance.publish_case("fresh-controls")
    directory = tmp_path / instance.public_directory / "fresh-controls"
    before = inventory(directory)
    assert context["snapshot_published"] is True and "failure.json" not in before
    result["status"] = "withheld"
    with pytest.raises(AssertionError):
        instance.assert_case_result("fresh-controls", result)
    instance.retain_failures(AssertionError("same exported gate failure"))
    assert inventory(directory) == before and context["files"]["failure.json"] is None
    outer = json.loads(instance.write_disposition())
    assert (
        outer["cases"][0]["state"] == "rejected"
        and outer["cases"][0]["error"] is not None
    )
    assert outer["cases"][1]["state"] == "not_run"


@pytest.mark.parametrize("stage", ["manager-reference", "observer-close"])
def test_postexport_cleanup_failure_changes_only_outer_disposition(tmp_path, stage):
    instance = publication_lab(tmp_path)
    context = add_case(instance)
    result = instance.publish_case("fresh-controls")
    instance.assert_case_result("fresh-controls", result)
    directory = tmp_path / instance.public_directory / "fresh-controls"
    before = inventory(directory)
    instance.post_snapshot_error(
        "fresh-controls", OSError("synthetic cleanup failure"), stage=stage
    )
    assert inventory(directory) == before
    entry = json.loads(instance.write_disposition())["cases"][0]
    assert (
        entry["state"] == "cleanup_failed"
        and entry["error"]["type"] == "OSError"
        and entry["cleanup_errors"][0]["stage"] == stage
    )
    assert context["snapshot"]["files"]["failure.json"] is None


def test_snapshot_pins_actual_evaluation_and_null_absence(tmp_path):
    instance = publication_lab(tmp_path)
    context = add_case(instance)
    instance.publish_case("fresh-controls")
    snapshot = json.loads(context["snapshot_raw"])
    assert len(snapshot["files"]) == 49 and snapshot["files"][
        "evaluation.json"
    ] == lab.accounting.sha256(context["files"]["evaluation.json"])
    assert snapshot["files"]["failure.json"] is None
    directory = tmp_path / instance.public_directory / "fresh-controls"
    for name, pin in snapshot["files"].items():
        if pin is None:
            assert not (directory / name).exists()
        else:
            assert lab.accounting.sha256((directory / name).read_bytes()) == pin


def test_v2_collector_and_dispatch_leave_v1_default_available(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "fresh_v2_collector",
        REAL.parents[1] / ".github/scripts/collect_fresh_source_observe.py",
    )
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    assert collector.NAMES == core.FILES - {"observer-publication.raw"}
    assert collector.file_limit("observer-publication.raw") == 1024 * 1024
    assert (
        lab.FreshSourceObserveLab.version == 1
        and lab.FreshSourceObserveV2Lab.version == 2
    )
    assert (
        lab.FreshObserverProcess.role_mode == "fresh-source"
        and lab.FreshObserverProcessV2.role_mode == "fresh-source-v2"
    )
    workflow = (REAL.parents[1] / ".github/workflows/ci.yml").read_text()
    assert (
        "--native-core --fresh-source-observe-v2" in workflow
        and "collect_fresh_source_observe.py --v2" in workflow
    )


def test_later_failure_does_not_reject_previously_accepted_case(tmp_path):
    instance = publication_lab(tmp_path)
    add_case(instance)
    result = instance.publish_case("fresh-controls")
    instance.assert_case_result("fresh-controls", result)
    original = inventory(tmp_path / instance.public_directory / "fresh-controls")
    instance.retain_failures(AssertionError("later assigned case failure"))
    assert instance.case_dispositions["fresh-controls"]["state"] == "accepted"
    assert (
        inventory(tmp_path / instance.public_directory / "fresh-controls") == original
    )


def test_actual_manager_unref_failure_hook_keeps_snapshot_bytes(tmp_path):
    instance = publication_lab(tmp_path)
    add_case(instance)
    result = instance.publish_case("fresh-controls")
    instance.assert_case_result("fresh-controls", result)
    original = inventory(tmp_path / instance.public_directory / "fresh-controls")

    class Client:
        trace = []

        def call(self, method, unit):
            self.trace.append(dict(method=method))
            raise OSError("actual mocked UnrefUnit failure")

        def close(self):
            self.trace.append(dict(method="close"))

    instance.g.UNIT = "azazel-edge-core.service"
    instance._case_manager_clients = {"fresh-controls": Client()}
    with pytest.raises(OSError, match="UnrefUnit"):
        instance.release_case_reference("fresh-controls")
    assert (
        inventory(tmp_path / instance.public_directory / "fresh-controls") == original
    )
    assert instance.case_dispositions["fresh-controls"]["state"] == "cleanup_failed"
    assert not (
        tmp_path / instance.public_directory / "fresh-controls/failure.json"
    ).exists()


@pytest.mark.parametrize("fault", [None, "no_commit", "wrong_object", "wrong_hash"])
def test_barrier_uses_only_fsynced_prefix_not_visible_suffix(monkeypatch, fault):
    prefix = b"first committed rows\n"
    visible = prefix + b"visible but uncommitted row\n"
    metadata = dict(case_id="synthetic")
    identity = dict(pid=123)
    config = dict(
        metadata=metadata,
        paths=dict(publication="/synthetic/publication", calls="/synthetic/calls"),
    )
    context = dict(
        files={"observer-config.json": lab.accounting.canonical(config)},
        load=dict(observer=dict(identity=identity)),
    )
    obj = dict(
        device=9,
        inode=99,
        owner_uid=61002,
        mode=0o100600,
        nlink=1,
        size=len(visible),
        mtime_ns=0,
        ctime_ns=0,
    )
    clocks = dict(
        start_ns=10,
        end_ns=20,
        process_cpu_start_ns=1,
        process_cpu_end_ns=2,
        thread_cpu_start_ns=1,
        thread_cpu_end_ns=2,
    )
    commit = dict(
        stream="calls",
        first_seq=0,
        last_seq=1,
        rows=2,
        bytes=len(prefix),
        sha256=lab.accounting.sha256(prefix),
        object=dict(device=9, inode=99, owner_uid=61002, mode=0o100600, link_count=1),
        worker_native_tid=456,
        write=clocks,
        fsync=dict(clocks, start_ns=20, end_ns=30),
    )
    if fault == "wrong_object":
        commit["object"]["inode"] = 100
    if fault == "wrong_hash":
        commit["sha256"] = "0" * 64
    data = [("header", dict(metadata=metadata, identity=identity, limits={}))]
    if fault != "no_commit":
        data.append(("commit", commit))
    rows = []
    previous = "0" * 64
    for seq, (kind, value) in enumerate(data, 1):
        raw = lab.accounting.canonical(
            dict(
                schema_version="edge-observer-publication/v1",
                seq=seq,
                prev=previous,
                kind=kind,
                data=value,
            )
        )
        rows.append(raw)
        previous = lab.accounting.sha256(raw)
    publication = b"".join(rows)

    def read(path, limit):
        return (
            (publication, {})
            if str(path).endswith("publication")
            else (visible, dict(object=obj))
        )

    monkeypatch.setattr(lab, "stable_read", read)
    if fault in ("wrong_object", "wrong_hash"):
        with pytest.raises(AssertionError):
            lab.publication_commits(context, {"calls": 1})
    else:
        result = lab.publication_commits(context, {"calls": 1})
        if fault == "no_commit":
            assert result is None
        else:
            assert result[0]["calls"] == dict(
                size=len(prefix), sha256=lab.accounting.sha256(prefix)
            )


def sealed_pair(instance):
    for case in lab.CASES:
        add_case(instance, case)
        result = instance.publish_case(case)
        instance.assert_case_result(case, result)
    return instance.write_disposition()


def test_strict_final_replay_uses_both_sealed_original_case_maps(tmp_path):
    instance = publication_lab(tmp_path)
    disposition = sealed_pair(instance)
    result = instance.replay_run(disposition)
    assert result["status"] == "qualified", result


@pytest.mark.parametrize(
    "fault", ["snapshot_missing", "snapshot_changed", "extra_failure"]
)
def test_strict_final_replay_rejects_changed_snapshot_or_null_slot(tmp_path, fault):
    instance = publication_lab(tmp_path)
    disposition = sealed_pair(instance)
    directory = tmp_path / instance.public_directory
    snapshot = directory / "fresh-controls-snapshot.json"
    if fault == "snapshot_missing":
        snapshot.unlink()
    elif fault == "snapshot_changed":
        snapshot.write_bytes(snapshot.read_bytes() + b" ")
    else:
        (directory / "fresh-controls/failure.json").write_bytes(
            b'{"type":"late failure"}\n'
        )
    result = instance.replay_run(disposition)
    assert result["status"] == "withheld", result


def test_initial_exercise_error_publishes_valid_failed_disposition(
    tmp_path, monkeypatch
):
    instance = publication_lab(tmp_path)

    def fail_before_case(self):
        raise ValueError("original initial run error")

    monkeypatch.setattr(lab.FreshSourceObserveLab, "exercise", fail_before_case)
    with pytest.raises(ValueError, match="original initial"):
        instance.exercise()
    raw = (tmp_path / instance.public_directory / "disposition.json").read_bytes()
    result = instance.replay_run(raw)
    assert result["status"] == "withheld" and result["disposition"] is not None, result
    assert result["disposition"]["errors"] == [
        dict(stage="run", type="ValueError", message="original initial run error")
    ]
    assert all(entry["state"] == "not_run" for entry in result["disposition"]["cases"])


def test_final_replay_failure_publishes_error_without_changing_sealed_cases(
    tmp_path, monkeypatch
):
    instance = publication_lab(tmp_path)

    def publish_assigned(self):
        sealed_pair(self)

    monkeypatch.setattr(lab.FreshSourceObserveLab, "exercise", publish_assigned)
    original_replay = instance.replay_run
    saved = {}
    count = []

    def fail_first(raw):
        count.append(True)
        if len(count) == 1:
            saved.update(
                {
                    case: inventory(tmp_path / instance.public_directory / case)
                    for case in lab.CASES
                }
            )
            return dict(status="withheld", reasons=["synthetic first replay failure"])
        return original_replay(raw)

    monkeypatch.setattr(instance, "replay_run", fail_first)
    with pytest.raises(AssertionError):
        instance.exercise()
    raw = (tmp_path / instance.public_directory / "disposition.json").read_bytes()
    result = original_replay(raw)
    assert result["status"] == "withheld" and result["disposition"] is not None, result
    assert result["disposition"]["errors"][0]["stage"] == "final-replay"
    assert all(
        inventory(tmp_path / instance.public_directory / case) == saved[case]
        for case in lab.CASES
    )


def test_preseal_collection_failure_copies_actual_error_into_valid_outer_failure(
    tmp_path, monkeypatch
):
    instance = publication_lab(tmp_path)
    context = add_case(instance)
    monkeypatch.setattr(instance, "stopped", lambda case: None)
    monkeypatch.setattr(instance, "stores", lambda context, phase: None)

    def export(case):
        context["files"]["close-controller.json"] = lab.accounting.canonical(
            context["controller"]
        )
        result = instance.publish_case(case)
        instance.assert_case_result(case, result)

    monkeypatch.setattr(instance, "export", export)
    instance.retain_failures(OSError("original preseal collection failure"))
    disposition = instance.write_disposition()
    result = instance.replay_run(disposition)
    assert result["status"] == "withheld" and result["disposition"] is not None, result
    entry = result["disposition"]["cases"][0]
    assert entry["state"] == "collection_failed" and entry["error"] == dict(
        type="OSError", message="original preseal collection failure"
    )
    assert (
        context["files"]["failure.json"] is not None
        and context["snapshot_published"] is True
    )
