"""Fresh manual inherited-unit refusal; no launch, experiment or admission hook.

Root retains the intentional foreign drop-in. Marker absence alone proves nothing.
Only the current commissioning owner may provision/clean this one fresh scope.
"""

import hashlib
import os
from pathlib import Path
import stat

import signed_network_telemetry_commission as main
from azazel_edge.outcome.input_auth import open_parent, read_regular

lab, g, material, role = main.lab, main.g, main.material, main.setup.role
FLAG = "EDGE_SIGNED_NETWORK_UNIT_REFUSAL"
DROPIN = Path("/etc/systemd/system") / (role.INITIALIZER_UNIT + ".d")
HOOK = DROPIN / "90-fixed-refusal-marker.conf"
MARKER = Path("/run/edge400-inherited-initialize-marker")
WIRE = ("[Service]\nExecStartPre=/usr/bin/touch " + str(MARKER) + "\n").encode()
REFUSAL = "preexisting inherited fixed-role unit material refused"


def _identity(info):
    return dict(
        device=info.st_dev,
        inode=info.st_ino,
        uid=info.st_uid,
        gid=info.st_gid,
        mode=info.st_mode,
        nlink=info.st_nlink,
    )


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _foreign(output, *, create=False):
    if create:
        lab.save_json(
            output / "foreign-create-intent.json",
            dict(
                directory=str(DROPIN),
                file=str(HOOK),
                marker=str(MARKER),
                sha256=hashlib.sha256(WIRE).hexdigest(),
                retained_foreign_fixture=True,
            ),
        )
        parent, name = open_parent(DROPIN, trusted_owner=0)
        try:
            os.mkdir(name, 0o755, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        directory = os.open(DROPIN, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(directory, 0o755)
            lab.save_json(
                output / "foreign-directory-created.json",
                _identity(os.fstat(directory)),
            )
            fd = os.open(
                HOOK.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o644,
                dir_fd=directory,
            )
            try:
                os.fchmod(fd, 0o644)
                lab.need(os.write(fd, WIRE) == len(WIRE), "short foreign hook write")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
        finally:
            os.close(directory)
    directory = os.stat(DROPIN, follow_symlinks=False)
    raw, info = read_regular(HOOK, owner=0, mode=0o644, max_bytes=4096)
    lab.save(output / ("foreign-created.raw" if create else "foreign-after.raw"), raw)
    lab.need(
        stat.S_ISDIR(directory.st_mode)
        and directory.st_uid == directory.st_gid == 0
        and stat.S_IMODE(directory.st_mode) == 0o755
        and info.st_gid == 0
        and info.st_nlink == 1
        and raw == WIRE,
        "foreign fixed material differs",
    )
    record = dict(
        directory=_identity(directory),
        file=_identity(info),
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    lab.save_json(
        output / ("foreign-created.json" if create else "foreign-after.json"), record
    )
    return record


def _snapshot(output, phase):
    """Public Source/observer/anchors only; never private key material."""
    observer = g.BUNDLE / "observer"
    directory = os.stat(observer, follow_symlinks=False)
    lab.need(
        stat.S_ISDIR(directory.st_mode) and directory.st_uid == 61002,
        "observer directory differs",
    )
    names = sorted(os.listdir(observer))
    lab.save_json(
        output / (phase + "-observer-directory.json"),
        dict(identity=_identity(directory), entries=names),
    )
    lab.need(not names, "pre-initialization observer directory must remain empty")
    result = dict(observer=_identity(directory), observer_entries=names)
    for name, path, owner, mode in (
        ("source", g.BUNDLE / "input", 61001, 0o644),
        ("anchors", g.BUNDLE / "witness/anchors/anchors.journal", 0, 0o600),
    ):
        raw, info = read_regular(path, owner=owner, mode=mode, max_bytes=1024 * 1024)
        lab.save(output / (phase + "-" + name + ".raw"), raw)
        result[name] = dict(
            identity=_identity(info),
            sha256=hashlib.sha256(raw).hexdigest(),
            bytes=len(raw),
        )
        lab.need(
            info.st_nlink == 1 and (raw == b"" if name == "source" else bool(raw)),
            "fresh Source/anchor state required",
        )
    lab.save_json(output / (phase + "-public-snapshot.json"), result)
    return result


def _after(output):
    """Independent current checks: every fixed actor and invariant is attempted."""
    errors = []

    def attempt(name, operation):
        try:
            return operation()
        except BaseException as exc:
            errors.append(dict(step=name, error=type(exc).__name__))

    def receipts():
        actor = main.plan.strict(material._read(output / "actor-cleanup.json"))
        namespace = main.plan.strict(
            material._read(output / "namespace-evidence/cleanup.json")
        )
        lab.need(
            actor["errors"] == []
            and namespace["errors"] == []
            and namespace["cleanup_verified"] is True,
            "owner cleanup receipts incomplete",
        )

    attempt("owner-receipts", receipts)
    for unit in main.setup.UNITS:

        def actor(unit=unit):
            state = main.setup.scope._state(unit)
            lab.save_json(output / ("independent-" + unit + ".json"), state)
            original_empty = lab.cg.group_empty(state["ControlGroup"], main.setup.UNITS)
            canonical_empty = lab.cg.group_empty(
                "/system.slice/" + unit, main.setup.UNITS
            )
            lab.need(
                state["ActiveState"] in ("inactive", "failed")
                and state["MainPID"] == state["ControlPID"] == "0"
                and original_empty is True
                and canonical_empty is True,
                "actor cleanup not independently empty",
            )

        attempt(unit, actor)
    attempt("core", lambda: lab.need(not g.Systemd().cores(), "core remains"))
    observations = []
    for name in role.NAMESPACE_NAMES:

        def namespace(name=name):
            try:
                info = os.lstat(Path("/run/netns") / name)
            except FileNotFoundError:
                observations.append(dict(name=name, state="absent"))
                return
            except BaseException as exc:
                observations.append(
                    dict(name=name, state="unknown", error=type(exc).__name__)
                )
                raise
            observations.append(
                dict(name=name, state="present", identity=_identity(info))
            )
            lab.need(False, "namespace remains")

        attempt("namespace:" + name, namespace)
    attempt(
        "namespace observations",
        lambda: lab.save_json(
            output / "independent-namespace-observations.json",
            dict(observations=observations),
        ),
    )

    def parent():
        baseline = main.plan.strict(material._read(output / "commission-baseline.json"))
        root = main.setup.n.root_snapshot()
        lab.save_json(output / "independent-parent-after.json", root)
        lab.need(
            root == baseline["root_before"] and g.boot() == baseline["kernel_boot_id"],
            "parent/boot changed",
        )

    attempt("parent-and-boot", parent)
    lab.save_json(output / "independent-cleanup-checks.json", dict(errors=errors))
    lab.need(not errors, "independent cleanup incomplete")
    return dict(
        all_fixed_groups_empty=True,
        namespaces_absent=True,
        core_absent=True,
        parent_network_unchanged=True,
    )


def refuse_inherited_initializer_material(
    output,
    *,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """Use current owner once; exact guard refusal and verified cleanup only."""
    g.guard()
    lab.need(
        os.geteuid() == 0
        and os.environ.get(FLAG) == "1"
        and os.environ.get(material.FLAG) == "1",
        "explicit fresh Root unit-refusal opt-in required",
    )
    lab.need(
        not any(os.path.lexists(path) for path in (DROPIN, MARKER)),
        "existing foreign fixture refused",
    )
    output = Path(output)
    original = main.initializer.initialize
    entered, caught, failure = False, None, None
    foreign, before = None, None

    def initialize(path, **kwargs):
        nonlocal entered, foreign, before
        lab.need(
            not entered and Path(path) == output / "initialize",
            "fixed initializer callback only once",
        )
        entered = True
        # The current owner's callback is after witness readiness and exclusive BASE.
        main.initializer.namespace_observation(kwargs["transport_context"])
        witness = lab.unit_snapshot(g.WITNESS)
        lab.need(witness["MainPID"] != "0", "actual owned witness not running")
        lab.save_json(
            output / "unit-refusal-entered.json",
            dict(
                kernel_boot_id=g.boot(),
                witness=witness,
                helper_sha256=hashlib.sha256(
                    material._read(Path(__file__))
                ).hexdigest(),
                initialized=False,
            ),
        )
        before = _snapshot(output, "before-injection")
        foreign = _foreign(output, create=True)
        _sync(output)
        original(path, **kwargs)
        raise AssertionError(
            "unexpected initializer return; ordinary core/native/live forbidden"
        )

    main.initializer.initialize = initialize
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
        cleanup, cleanup_error = None, None
        try:
            cleanup = _after(output)
        except BaseException as exc:
            cleanup_error = exc
        if caught is not None and (
            type(caught) is not AssertionError or str(caught) != REFUSAL
        ):
            if cleanup_error is not None:
                caught.add_note("independent cleanup: " + type(cleanup_error).__name__)
            raise caught
        if cleanup_error is not None:
            raise cleanup_error
        lab.need(
            entered
            and type(caught) is AssertionError
            and str(caught) == REFUSAL
            and not getattr(caught, "__notes__", ()),
            "exact prelaunch refusal with clean owner exit required",
        )
        lab.save_json(
            output / "original-refusal.json",
            dict(type=type(caught).__name__, message=str(caught)),
        )
        query = output / "initialize/initialize-launch-unit-paths.stdout"
        prefix = output / "initialize/initialize-launch-unit-paths"
        lab.need(
            main.plan.strict(material._read(Path(str(prefix) + ".argv.json")))
            == ["systemd-analyze", "unit-paths"]
            and main.plan.strict(material._read(Path(str(prefix) + ".result.json")))
            == dict(returncode=0, error=None),
            "unit-path query did not succeed",
        )
        lab.need(
            material._read(query, 16384).endswith(b"\n")
            and material._read(
                output / "initialize/initialize-launch-unit-paths.stderr", 4096
            )
            == b"",
            "original unit-path query missing",
        )
        # No initializer launch receipt is permitted, including unknown new artifacts.
        allowed = {
            "initialize-launch-unit-paths.stdout",
            "initialize-launch-unit-paths.stderr",
            "initialize-launch-unit-paths.argv.json",
            "initialize-launch-unit-paths.result.json",
        }
        lab.need(
            set(os.listdir(output / "initialize")) <= allowed,
            "initializer launch/API artifact present",
        )
        lab.need(
            not list((output / "live").iterdir())
            and not os.path.lexists(MARKER)
            and not os.path.lexists(output / "commission-result.json"),
            "unexpected live/marker/success artifact",
        )
        lab.need(
            _snapshot(output, "after-refusal") == before
            and _foreign(output) == foreign,
            "public state/foreign fixture changed",
        )
        result = dict(
            status="inherited_initializer_material_refusal_complete",
            cleanup=cleanup,
            intentional_foreign_material_retained=True,
            source_read_is_not_cursor_consumption=True,
            authorizes_transition=False,
            experiment=False,
            measurement_completed=False,
            production_admission=False,
        )
        lab.save_json(output / "unit-refusal-result.json", result)
        _sync(output)
        return result
    except BaseException as exc:
        failure = exc
        if output.is_dir():
            try:
                lab.save_json(
                    output / "unit-refusal-failure.json",
                    dict(
                        type=type(exc).__name__, message=str(exc)[:512], entered=entered
                    ),
                )
            except BaseException as saved:
                failure.add_note("failure retention: " + type(saved).__name__)
        raise
    finally:
        main.initializer.initialize = original
