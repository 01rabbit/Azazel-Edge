"""One explicit fresh LIVE-material refusal after genuine initialization/native close.

This preserves the foreign fixture and proves no live consumption; no trial/effect.
"""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat

import signed_network_telemetry_commission as main
import signed_network_telemetry_live as live
from signed_network_telemetry_unit_refusal import _identity, _sync, _after
from azazel_edge.outcome.input_auth import (
    TrustPolicy,
    SourceVerifier,
    open_parent,
    read_regular,
)

lab, g, material, role = main.lab, main.g, main.material, main.setup.role
FLAG = "EDGE_SIGNED_NETWORK_LIVE_UNIT_REFUSAL"
DROPIN = Path("/etc/systemd/system") / (role.OBSERVER_UNIT + ".d")
HOOK = DROPIN / "90-fixed-refusal-marker.conf"
MARKER = Path("/run/edge400-inherited-live-marker")
WIRE = ("[Service]\nExecStartPre=/usr/bin/touch " + str(MARKER) + "\n").encode()
REFUSAL = "preexisting inherited fixed-role unit material refused"
OBSERVER_FILES = (
    "observations.journal",
    "observer-start-context.json",
    "actual-collector-calls.jsonl",
    "outcomes.jsonl",
    "observer-terminal-result.json",
)


def _absent(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False


def _foreign(output, create=False, phase="immediate"):
    if create:
        lab.save_json(
            output / "live-foreign-intent.json",
            dict(
                directory=str(DROPIN),
                file=str(HOOK),
                marker=str(MARKER),
                sha256=hashlib.sha256(WIRE).hexdigest(),
            ),
        )
        parent, name = open_parent(DROPIN, trusted_owner=0)
        try:
            os.mkdir(name, 0o755, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        fd = os.open(DROPIN, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(fd, 0o755)
            lab.save_json(
                output / "live-foreign-directory.json", _identity(os.fstat(fd))
            )
            hook = os.open(
                HOOK.name,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o644,
                dir_fd=fd,
            )
            try:
                os.fchmod(hook, 0o644)
                lab.need(os.write(hook, WIRE) == len(WIRE), "short live hook write")
                os.fsync(hook)
            finally:
                os.close(hook)
            os.fsync(fd)
        finally:
            os.close(fd)
    directory = os.lstat(DROPIN)
    raw, info = read_regular(HOOK, owner=0, mode=0o644, max_bytes=4096)
    prefix = "live-foreign-created" if create else "live-foreign-" + phase
    lab.save(output / (prefix + ".raw"), raw)
    lab.need(
        stat.S_ISDIR(directory.st_mode)
        and directory.st_uid == directory.st_gid == info.st_uid == info.st_gid == 0
        and stat.S_IMODE(directory.st_mode) == 0o755
        and info.st_nlink == 1
        and raw == WIRE,
        "live foreign material differs",
    )
    record = dict(
        directory=_identity(directory),
        file=_identity(info),
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    lab.save_json(output / (prefix + ".json"), record)
    return record


def _snapshot(output, phase):
    records = {}
    directory = g.BUNDLE / "observer"
    info = os.lstat(directory)
    names = sorted(os.listdir(directory))
    lab.save_json(
        output / (phase + "-observer-directory.json"),
        dict(identity=_identity(info), entries=names),
    )
    lab.need(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 61002
        and set(names) <= set(OBSERVER_FILES),
        "unknown observer directory/material",
    )
    records["observer_directory"] = _identity(info)
    paths = [
        ("source", g.BUNDLE / "input", 61001, 0o644),
        ("anchors", g.BUNDLE / "witness/anchors/anchors.journal", 0, 0o600),
    ]
    paths += [(name, directory / name, 61002, 0o600) for name in OBSERVER_FILES]
    for name, path, owner, mode in paths:
        if name not in ("source", "anchors", "observations.journal") and _absent(path):
            records[name] = dict(absent=True)
            continue
        raw, info = read_regular(
            path, owner=owner, mode=mode, max_bytes=8 * 1024 * 1024
        )
        lab.save(output / (phase + "-" + name + ".raw"), raw)
        lab.need(info.st_nlink == 1, "public snapshot hard link refused")
        records[name] = dict(
            identity=_identity(info), sha256=hashlib.sha256(raw).hexdigest(), raw=raw
        )
    lab.save_json(
        output / (phase + "-snapshot.json"),
        {
            name: {k: v for k, v in row.items() if k != "raw"}
            for name, row in records.items()
        },
    )
    _sync(output)
    return records


def _closed(output, trust):
    state = lab.unit_snapshot(g.UNIT)
    lab.save_json(output / "native-closed-unit.json", state)
    first = lab.cg.group_empty(state["ControlGroup"], main.setup.UNITS)
    second = lab.cg.group_empty("/system.slice/" + g.UNIT, main.setup.UNITS)
    lab.need(
        state["MainPID"] == state["ControlPID"] == "0"
        and state["ActiveState"] in ("inactive", "failed")
        and first is True
        and second is True
        and not g.Systemd().cores(),
        "native not independently quiescent",
    )
    raw, _ = read_regular(
        g.BUNDLE / "input", owner=61001, mode=0o644, max_bytes=4 * 1024 * 1024
    )
    lab.save(output / "native-closed-source.raw", raw)
    verifier = SourceVerifier(trust)
    verifier.verify(raw)
    frames = [main.plan.strict(row) for row in raw.splitlines()]
    lab.need(
        len(frames) == 3
        and verifier.live_state.closed
        and [row["event"]["capture_origin"]["kind"] for row in frames]
        == ["session_prepare", "session_start", "session_end"]
        and all(row["boot_ref"] == g.boot().replace("-", "") for row in frames),
        "exact signed native lifecycle required",
    )


def refuse_inherited_live_material(
    output,
    *,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    g.guard()
    lab.need(
        os.geteuid() == 0
        and os.environ.get(FLAG) == "1"
        and os.environ.get(material.FLAG) == "1",
        "explicit fresh Root live-refusal opt-in required",
    )
    lab.need(
        all(_absent(path) for path in (DROPIN, MARKER)),
        "existing live foreign fixture refused",
    )
    output = Path(output)
    original_init, original_live = main.initializer.initialize, main.live
    initialized = initial = baseline = foreign = None
    entered, refused, caught = False, False, None

    def initialize(path, **kwargs):
        nonlocal initialized, initial
        lab.need(initialized is None, "one direct initializer only")
        initialized = original_init(path, **kwargs)
        initial = _snapshot(output, "genuine-initialized")
        lab.need(initial["source"]["raw"] == b"", "initial Source was not empty")
        frames = lab.journal_frames(initial["observations.journal"]["raw"])
        lab.need(
            [row["kind"] for row in frames]
            == ["header", "session_open", "input_ready", "session_close"],
            "genuine clean empty journal required",
        )
        return initialized

    @contextmanager
    def observe(path, *, initialization, **kwargs):
        nonlocal entered, baseline, foreign, refused
        lab.need(
            not entered
            and Path(path) == output / "live"
            and initialization is initialized
            and initial is not None,
            "direct current initializer/live callback required",
        )
        entered = True
        g.stop()  # Existing signed session_end BEFORE the stable refusal boundary.
        trust = TrustPolicy(
            main.plan.strict(material._read(g.BUNDLE / "trust.json", 8192))
        )
        _closed(output, trust)
        evidence = output / "live-refusal-binding"
        material.preflight.old.private_output(evidence)
        current = material.verify_current(
            abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256
        )
        lab.need(
            current["source_sha256"] == kwargs["expected_sources"]
            and current["source_sha256"][
                str(Path(role.SOURCE).relative_to(material.SRC))
            ]
            == kwargs["source_sha256"],
            "current live source pins differ",
        )
        binding, _ = main.initializer._current_binding(
            current=current,
            namespace=main.initializer._namespace(
                kwargs["namespace_fd"], kwargs["namespace_identity"]
            ),
            source_sha256=kwargs["source_sha256"],
            kernel=g.boot(),
            output=evidence,
            phase="live-initial",
            transport_context=kwargs["transport_context"],
        )
        live._initialized(initialization, binding)
        lab.save_json(
            output / "live-refusal-entered.json",
            dict(
                binding=binding,
                helper_sha256=hashlib.sha256(
                    material._read(Path(__file__))
                ).hexdigest(),
            ),
        )
        baseline = _snapshot(output, "before-live-injection")
        lab.need(
            all(baseline[name] == initial[name] for name in initial if name != "source")
            and baseline["source"]["identity"] == initial["source"]["identity"],
            "initial journal/sidecars/anchors changed before live",
        )
        foreign = _foreign(output, create=True)
        _sync(output)
        try:
            with original_live(path, initialization=initialization, **kwargs):
                raise AssertionError(
                    "unexpected live yield; outer ready/workload forbidden"
                )
        except BaseException as exc:
            # Retain/compare here BEFORE the outer owner stops witness/namespaces.
            after = _snapshot(output, "immediate-live-refusal")
            lab.need(
                after == baseline and _foreign(output) == foreign and _absent(MARKER),
                "live refusal mutated protected state/foreign fixture",
            )
            lab.need(
                type(exc) is AssertionError
                and str(exc) == REFUSAL
                and not getattr(exc, "__notes__", ()),
                "exact live material refusal required",
            )
            refused = True
            lab.save_json(
                output / "original-live-refusal.json",
                dict(type=type(exc).__name__, message=str(exc)),
            )
            raise
        yield  # Generator protocol only; every preceding path raises.

    main.initializer.initialize, main.live = initialize, observe
    try:
        try:
            main.commission_telemetry(
                output,
                source_commit=source_commit,
                archive_sha256=archive_sha256,
                core_sha256=core_sha256,
                abi_sha256=abi_sha256,
                interpreter_sha256=interpreter_sha256,
            )
        except BaseException as exc:
            caught = exc
        cleanup, error = None, None
        try:
            cleanup = _after(output)
        except BaseException as exc:
            error = exc
        if caught is not None and not (
            type(caught) is AssertionError
            and str(caught) == REFUSAL
            and not getattr(caught, "__notes__", ())
        ):
            if error is not None:
                caught.add_note("independent cleanup: " + type(error).__name__)
            raise caught
        if error is not None:
            raise error
        lab.need(
            entered and refused and caught is not None, "live refusal proof incomplete"
        )
        prefix = output / "live/live-launch-unit-paths"
        expected = {
            "live-launch-unit-paths" + suffix
            for suffix in (".stdout", ".stderr", ".argv.json", ".result.json")
        }
        lab.need(
            set(os.listdir(output / "live")) == expected
            and main.plan.strict(material._read(Path(str(prefix) + ".argv.json")))
            == ["systemd-analyze", "unit-paths"]
            and main.plan.strict(material._read(Path(str(prefix) + ".result.json")))
            == dict(returncode=0, error=None)
            and material._read(Path(str(prefix) + ".stdout")).endswith(b"\n")
            and material._read(Path(str(prefix) + ".stderr")) == b"",
            "original live guard query incomplete/launch artifact present",
        )
        lab.need(
            _snapshot(output, "after-owner-cleanup") == baseline
            and _foreign(output, phase="owner") == foreign
            and _absent(MARKER),
            "post-cleanup public/foreign state changed",
        )
        result = dict(
            status="inherited_live_material_refusal_complete",
            cleanup=cleanup,
            intentional_foreign_material_retained=True,
            native_lifecycle_only=True,
            authorizes_transition=False,
            experiment=False,
            measurement_completed=False,
            production_admission=False,
        )
        lab.save_json(output / "live-unit-refusal-result.json", result)
        _sync(output)
        return result
    except BaseException as exc:
        if output.is_dir():
            try:
                lab.save_json(
                    output / "live-unit-refusal-failure.json",
                    dict(
                        type=type(exc).__name__,
                        message=str(exc)[:512],
                        entered=entered,
                        refused=refused,
                    ),
                )
            except BaseException as saved:
                exc.add_note("failure retention: " + type(saved).__name__)
        raise
    finally:
        main.initializer.initialize, main.live = original_init, original_live
