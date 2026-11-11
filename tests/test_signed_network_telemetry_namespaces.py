"""Synthetic Root/kernel/namespace/unit observations with real private owned FDs."""

import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_namespaces as ns


def fixture(tmp_path, monkeypatch, fault=None):
    output = tmp_path / "evidence"
    output.mkdir(mode=0o700)
    named = tmp_path / "virtual-netns"
    named.mkdir()
    events = []
    baseline = dict(
        kernel_boot_id="same-boot",
        pins=dict(abi_sha256="a" * 64, interpreter_sha256="b" * 64),
        material={"current": "same"},
        assets={"old": "same"},
        root_before={"parent": "same"},
    )
    stopped = []
    monkeypatch.setattr(ns.setup.g, "guard", lambda: None)
    monkeypatch.setattr(ns.setup.g, "boot", lambda: "same-boot")
    monkeypatch.setattr(ns.material.preflight, "_output", lambda output: None)

    def fresh(work):
        assert not work.exists()
        if fault == "fresh":
            raise AssertionError("synthetic used scope")

    monkeypatch.setattr(ns.setup, "_fresh", fresh)
    monkeypatch.setattr(
        ns.material.preflight.old, "private_output", lambda path: path.mkdir(mode=0o700)
    )
    monkeypatch.setattr(
        ns.setup,
        "_assets",
        lambda: {"old": "changed" if fault == "assets" and stopped else "same"},
    )
    monkeypatch.setattr(
        ns.setup.n,
        "root_snapshot",
        lambda: {"parent": "changed" if fault == "parent" and stopped else "same"},
    )
    monkeypatch.setattr(
        ns.material,
        "verify_current",
        lambda **pins: {
            "current": "changed" if fault == "material" and stopped else "same"
        },
    )
    real_fstat = os.fstat

    def fstat(fd):
        info = real_fstat(fd)
        return SimpleNamespace(
            st_uid=0, st_dev=info.st_dev, st_ino=info.st_ino, st_mode=info.st_mode
        )

    def metadata(path, **kw):
        path = Path(path)
        if str(path).startswith("/run/netns/"):
            path = named / path.name
        info = path.stat(follow_symlinks=kw.get("follow_symlinks", True))
        return SimpleNamespace(
            st_uid=0, st_dev=info.st_dev, st_ino=info.st_ino, st_mode=info.st_mode
        )

    monkeypatch.setattr(
        ns,
        "os",
        SimpleNamespace(
            **{
                key: getattr(os, key)
                for key in (
                    "open",
                    "close",
                    "get_inheritable",
                    "O_RDONLY",
                    "O_DIRECTORY",
                    "O_NOFOLLOW",
                )
            },
            fstat=fstat,
            stat=metadata,
            path=SimpleNamespace(
                lexists=lambda path: (named / Path(path).name).exists()
            ),
        ),
    )

    class Assets:
        def __init__(self, work):
            self.work, self.names, self.created, self.creation_intents = (
                work,
                {},
                {},
                {},
            )

        def create_namespace(self, name):
            self.creation_intents[name] = dict(state="creation_intent")
            ns.lab.save_json(
                self.work / ("intent-" + name + ".json"), self.creation_intents[name]
            )
            path = named / name
            path.write_bytes(b"VIRTUAL namespace object")
            events.append("create:" + name)
            if fault == "creation":
                raise TimeoutError("synthetic unknown add outcome")
            fd = os.open(path, os.O_RDONLY)
            info = os.fstat(fd)
            self.created[name] = (fd, info.st_dev, info.st_ino)
            self.creation_intents[name]["state"] = "confirmed_created"

        def _check(self, kind):
            name = self.names[kind]
            fd, dev, ino = self.created[name]
            info, current = os.fstat(fd), (named / name).stat()
            ns.lab.need(
                (info.st_dev, info.st_ino)
                == (current.st_dev, current.st_ino)
                == (dev, ino),
                "namespace replaced",
            )

        def ns(self, kind, *argv):
            self._check(kind)
            events.append((kind, argv))
            if fault == "lo":
                raise AssertionError("synthetic link failure")

        def close(self):
            pytest.fail("resident-killing Assets.close MUST NEVER run")

    monkeypatch.setattr(ns.setup.scope, "FencedAssets", Assets)

    class Marker:
        def __init__(self, marker_output, actual):
            assert marker_output == output / "namespace-marker" and actual is baseline

        def start(self):
            assert all(
                (named / name).exists() for name in ns.setup.role.NAMESPACE_NAMES
            )
            (output / "namespace-marker").mkdir()
            events.append("marker-start")
            if fault == "marker":
                raise AssertionError("synthetic unknown marker")

        def stop(self):
            stopped.append(1)
            events.append("marker-stop")
            if fault == "stop":
                raise AssertionError("synthetic marker stop failure")

    monkeypatch.setattr(ns.marker, "Marker", Marker)
    inspected = []

    def state(unit):
        inspected.append(unit)
        if fault == "state" and unit == ns.setup.g.UNIT:
            raise OSError("synthetic read failure")
        return dict(
            LoadState="not-found",
            ActiveState="active"
            if fault == "outeractive" and unit == ns.setup.g.UNIT
            else "inactive",
            MainPID="0",
            ControlPID="0",
            ControlGroup="",
        )

    monkeypatch.setattr(ns.setup.scope, "_state", state)
    monkeypatch.setattr(
        ns.lab.cg, "group_empty", lambda group, units: fault != "cgroup"
    )
    monkeypatch.setattr(
        ns.setup.g, "Systemd", lambda: SimpleNamespace(cores=lambda: [])
    )

    def query(argv, prefix, work):
        assert argv[:3] in (["ip", "netns", "pids"], ["ip", "netns", "del"])
        name = argv[-1]
        assert name in ns.setup.role.NAMESPACE_NAMES
        raw = b"999\n" if fault == "resident" and argv[2] == "pids" else b""
        code = None if fault == "query" else 0
        ns.lab.save(work / (prefix + ".stdout"), raw)
        ns.lab.save(work / (prefix + ".stderr"), b"")
        ns.lab.save_json(work / (prefix + ".result.json"), dict(returncode=code))
        if argv[2] == "del":
            events.append("delete:" + name)
            (named / name).unlink()
        return code, raw

    monkeypatch.setattr(ns.material.preflight.old, "_retained_query", query)
    if fault in ("actorpersist", "workspacepersist"):
        save = ns.lab.save_json

        def saving(path, value):
            if path.name == (
                "namespace-actor-cleanup.json"
                if fault == "actorpersist"
                else "namespace-workspace-created.json"
            ):
                raise OSError("synthetic evidence failure")
            return save(path, value)

        monkeypatch.setattr(ns.lab, "save_json", saving)
    return ns.NamespaceSetup(output, baseline), named, events, inspected


def test_exact_three_names_dummy_only_and_no_resident_kill_cleanup(
    tmp_path, monkeypatch
):
    state, named, events, inspected = fixture(tmp_path, monkeypatch)
    assert state.prepare() is state
    fd, pair = state.edge()
    assert pair == [os.fstat(fd).st_dev, os.fstat(fd).st_ino]
    receipt = state.close()
    assert receipt["cleanup_verified"] is True and not list(named.iterdir())
    assert set(inspected) == set(ns.setup.UNITS)
    assert [item for item in events if isinstance(item, tuple)] == [
        (kind, ("ip", "link", "set", "lo", "up"))
        for kind in ("edge", "client", "service")
    ] + [
        ("edge", ("ip", "link", "add", "es", "type", "dummy")),
        ("edge", ("ip", "link", "set", "es", "up")),
    ]
    assert (state.work / "cleanup.json").exists()
    assert (state.output / "namespace-actor-cleanup.json").exists()
    with pytest.raises(AssertionError):
        state.edge()
    for fd, _, _ in state.assets.created.values():
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize(
    "fault", ["fresh", "creation", "lo", "marker", "workspacepersist"]
)
def test_prepare_failure_keeps_state_intents_and_never_deletes_uncertain_names(
    tmp_path, monkeypatch, fault
):
    state, named, events, inspected = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, OSError, TimeoutError)):
        state.prepare()
    assert state.failed is True
    with pytest.raises(AssertionError):
        state.close()
    assert not any(str(e).startswith("delete:") for e in events)
    assert set(inspected) == set(ns.setup.UNITS) and "marker-stop" in events
    for fd, _, _ in state.assets.created.values():
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize(
    "fault",
    [
        "stop",
        "outeractive",
        "state",
        "cgroup",
        "resident",
        "query",
        "actorpersist",
        "assets",
        "parent",
        "material",
    ],
)
def test_any_close_gap_retains_names_checks_all_actors_and_invariants(
    tmp_path, monkeypatch, fault
):
    state, named, events, inspected = fixture(tmp_path, monkeypatch, fault)
    state.prepare()
    with pytest.raises(AssertionError):
        state.close()
    assert not any(str(e).startswith("delete:") for e in events)
    assert len(list(named.iterdir())) == 3 and set(inspected) == set(ns.setup.UNITS)
    for part in ("assets", "parent", "material"):
        assert (state.output / ("namespace-close-after-" + part + ".json")).exists()
    assert state.receipt["cleanup_verified"] is False


def test_replaced_named_handle_is_preserved_and_original_owned_fds_only_closed(
    tmp_path, monkeypatch
):
    state, named, events, _ = fixture(tmp_path, monkeypatch)
    state.prepare()
    path = named / ns.setup.role.NAMESPACE_NAMES[0]
    path.rename(named / "retained-original")
    path.write_bytes(b"FOREIGN")
    with pytest.raises(AssertionError):
        state.close()
    assert path.read_bytes() == b"FOREIGN" and not any(
        str(e).startswith("delete:") for e in events
    )
    for fd, _, _ in state.assets.created.values():
        with pytest.raises(OSError):
            os.fstat(fd)


def test_replaced_workspace_never_receives_cleanup_or_pid_query_writes(
    tmp_path, monkeypatch
):
    state, named, events, _ = fixture(tmp_path, monkeypatch)
    state.prepare()
    state.work.rename(state.output / "retained-original-workspace")
    state.work.mkdir(mode=0o700)
    (state.work / "foreign").write_bytes(b"FOREIGN")
    with pytest.raises(AssertionError):
        state.close()
    assert {p.name for p in state.work.iterdir()} == {"foreign"}
    assert len(list(named.iterdir())) == 3
    assert not any(str(e).startswith("delete:") for e in events)
