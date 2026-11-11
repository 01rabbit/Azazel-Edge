"""Explicit v2 owned empty preparation; no native start, workload or measurement.

External Root archive verification is mandatory. Persisted receipts describe facts;
only the returned in-memory owner may operate/close this current scope.
"""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess

import signed_network_phase as legacy
import signed_network_telemetry_commission as manual
from signed_network_telemetry_namespaces import _sync_dir
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_live import registration
from azazel_edge.outcome.input_service import layout

setup, plan, material, lab, g = (
    manual.setup,
    manual.plan,
    manual.material,
    manual.lab,
    manual.g,
)
WORK, MANIFEST, TICKET = legacy.WORK, legacy.MANIFEST, legacy.TICKET
_TOKEN, _active = object(), None


def validated_telemetry_inputs(
    expected_manifest_sha256,
    expected_start_head,
    *,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """Read-only exact validation; no scope/output or actor creation."""
    g.guard()
    lab.need(
        os.environ.get(material.FLAG) == "1", "explicit telemetry preparation required"
    )
    for value in (
        expected_manifest_sha256,
        expected_start_head,
        archive_sha256,
        core_sha256,
        abi_sha256,
        interpreter_sha256,
    ):
        material.pin(value)
    lab.need(
        type(source_commit) is str and re.fullmatch(r"[0-9a-f]{40}", source_commit),
        "external source commit required",
    )
    manifest_raw, ticket_raw = material._read(MANIFEST), material._read(TICKET, 4096)
    manifest, ticket = plan.strict(manifest_raw), plan.strict(ticket_raw)
    lab.need(
        type(manifest) is dict
        and plan.manifest_digest(manifest) == expected_manifest_sha256,
        "external frozen v2 manifest differs",
    )
    safety = plan.validate_telemetry_manifest(manifest, core_sha256)
    mode, pins = (
        plan.telemetry_assignment_mode(),
        manifest["measurement_binding"]["telemetry_lab"],
    )
    lab.need(
        manifest["provenance"]["repo_commits"]["01rabbit/Azazel-Edge"] == source_commit
        and pins["source_archive_sha256"] == archive_sha256
        and pins["abi_sha256"] == abi_sha256
        and pins["interpreter_sha256"] == interpreter_sha256
        and pins["assignment_mode"] == mode
        and pins["assignment_mode_sha256"] == plan.manifest_digest(mode),
        "external pins/mode differ",
    )
    lab.need(
        type(ticket) is dict
        and set(ticket)
        == {
            "schema_version",
            "manifest_sha256",
            "assignment_id",
            "run_id",
            "start_head",
        }
        and ticket["schema_version"] == mode["ticket_schema"]
        and ticket["manifest_sha256"] == expected_manifest_sha256
        and ticket["start_head"] == expected_start_head
        and type(ticket["run_id"]) is str
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,127}", ticket["run_id"]) is not None
        and type(ticket["assignment_id"]) is str,
        "explicit started v2 ticket differs",
    )
    selected = [
        a for a in manifest["assignments"] if a["id"] == ticket["assignment_id"]
    ]
    lab.need(
        len(selected) == 1 and selected[0]["arm"] in ("c0", "flow_throttle"),
        "unknown closed assignment",
    )
    revision, image = (
        material._read(material.SRC / "SOURCE_REVISION", 41),
        material._read(g.CORE, 128 * 1024 * 1024, 0o755),
    )
    direct = {
        str(path.relative_to(material.SRC)): hashlib.sha256(
            material._read(path)
        ).hexdigest()
        for path in material.source_paths()
    }
    lab.need(
        revision in (source_commit.encode(), (source_commit + "\n").encode())
        and image[:6] == b"\x7fELF\x02\x01"
        and hashlib.sha256(image).hexdigest() == core_sha256
        and direct == pins["source_sha256"],
        "current protected source/core differs",
    )
    return dict(
        schema_version="signed-network-telemetry-inputs/v2",
        manifest=manifest,
        ticket=ticket,
        assignment=selected[0],
        safety=safety[ticket["assignment_id"]],
        core_sha256=core_sha256,
        source_commit=source_commit,
        direct_files_sha256=direct,
        manifest_file_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        ticket_file_sha256=hashlib.sha256(ticket_raw).hexdigest(),
        external_pins=dict(
            source_commit=source_commit,
            archive_sha256=archive_sha256,
            core_sha256=core_sha256,
            abi_sha256=abi_sha256,
            interpreter_sha256=interpreter_sha256,
        ),
        assignment_mode_sha256=pins["assignment_mode_sha256"],
    )


class TelemetryAssignmentContext:
    def __init__(self, token, output, inputs, baseline):
        lab.need(
            token is _TOKEN, "only current validated preparation creates ownership"
        )
        self.output, self.inputs, self.baseline = output, deepcopy(inputs), baseline
        self.namespaces = manual.NamespaceSetup(output, baseline)
        self.owned, self.tracked, self.created = set(), {}, {}
        self.initialization = self.transport_context = None
        self.closed = self.ready = False
        self.cleanup_error = None
        self.original = (
            g.write,
            g.prepare,
            g.observer,
            dict(g.ENV),
            plan.p.a.NATIVE,
            g.Systemd.witness,
        )

    @property
    def args(self):
        lab.need(not self.closed and self.ready, "current preparation owner required")
        fd, pair = self.namespaces.edge()
        pins = self.baseline["pins"]
        sources = self.baseline["material"]["source_sha256"]
        return dict(
            abi_sha256=pins["abi_sha256"],
            interpreter_sha256=pins["interpreter_sha256"],
            source_sha256=sources[
                str(Path(setup.role.SOURCE).relative_to(material.SRC))
            ],
            expected_sources=deepcopy(sources),
            namespace_fd=fd,
            namespace_identity=pair,
            transport_context=self.transport_context,
        )

    def __enter__(self):
        lab.need(self.ready and not self.closed, "current preparation owner required")
        self.namespaces.edge()
        return self

    def __exit__(self, kind, error, traceback):
        try:
            self.close()
        except BaseException as cleanup:
            if error is None:
                raise
            error.add_note("assignment cleanup: " + type(cleanup).__name__)
        return False

    def close(self):
        global _active
        if self.closed:
            if self.cleanup_error is not None:
                raise self.cleanup_error
            return
        self.closed = True
        errors, processes = [], []

        def attempt(step, operation):
            try:
                return operation()
            except BaseException as exc:
                errors.append((step, type(exc).__name__))

        try:
            children = self.namespaces.assets.processes
            if len(children) > 5:
                errors.append(("process count", "exceeds fixed five children"))
            for process in children[:5]:
                row = dict(
                    pid=process.pid, argv=list(map(str, process.args)), forced=False
                )
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    row["forced"] = True
                    errors.append(("owned child", "forced"))
                    attempt("owned terminate", process.terminate)
                    attempt(
                        "owned wait", lambda process=process: process.wait(timeout=1)
                    )
                    try:
                        pending = process.poll() is None
                    except BaseException as exc:
                        pending = False
                        errors.append(("owned poll unknown", type(exc).__name__))
                    if pending:
                        attempt("owned kill", process.kill)
                        attempt(
                            "owned reap",
                            lambda process=process: process.wait(timeout=1),
                        )
                except BaseException as exc:
                    errors.append(("owned wait unknown", type(exc).__name__))
                row["returncode"] = process.returncode
                processes.append(row)
            fixed = (
                setup.role.INITIALIZER_UNIT,
                setup.role.OBSERVER_UNIT,
                g.UNIT,
                g.WITNESS,
            )
            if self.owned - set(fixed):
                errors.append(("unknown actor ownership", "refused"))
            units = tuple(unit for unit in fixed if unit in self.owned)
            stopped = attempt(
                "owned actors",
                lambda: lab.cleanup(units, {u: self.tracked.get(u, []) for u in units}),
            )
            attempt(
                "actor receipt",
                lambda: lab.save_json(self.output / "actor-cleanup.json", stopped),
            )
            attempt(
                "actor proof",
                lambda: lab.need(
                    type(stopped) is dict and stopped.get("errors") == [],
                    "actor cleanup unknown",
                ),
            )
            if errors:
                self.namespaces.failed = True
            namespace_cleanup = attempt("namespace close", self.namespaces.close)
            attempt(
                "namespace proof",
                lambda: lab.need(
                    type(namespace_cleanup) is dict
                    and namespace_cleanup.get("cleanup_verified") is True
                    and namespace_cleanup.get("errors") == [],
                    "namespace cleanup unknown",
                ),
            )
            if errors:
                self.namespaces.failed = True
            for name, operation, expected in (
                ("parent", setup.n.root_snapshot, self.baseline["root_before"]),
                ("assets", setup._assets, self.baseline["assets"]),
                (
                    "material",
                    lambda: material.verify_current(
                        abi_sha256=self.baseline["pins"]["abi_sha256"],
                        interpreter_sha256=self.baseline["pins"]["interpreter_sha256"],
                    ),
                    self.baseline["material"],
                ),
            ):

                def audit(name=name, operation=operation, expected=expected):
                    value = operation()
                    lab.save_json(
                        self.output / ("assignment-final-" + name + ".json"), value
                    )
                    lab.need(
                        value == expected, "independent assignment invariant changed"
                    )

                attempt(name, audit)
            attempt(
                "final receipt",
                lambda: lab.save_json(
                    self.output / "assignment-cleanup.json",
                    dict(
                        schema_version="signed-network-telemetry-cleanup/v2",
                        errors=errors,
                        processes=processes,
                        actor_cleanup=stopped,
                        namespace_cleanup=namespace_cleanup,
                        root_child_count=self.transport_context.count
                        if self.transport_context is not None
                        else 0,
                        cleanup_verified=not errors,
                        measurement_completed=False,
                        production_admission=False,
                    ),
                ),
            )
            lab.need(not errors, "assignment cleanup incomplete: " + str(errors))
        except BaseException as exc:
            self.cleanup_error = exc
            raise
        finally:
            (
                g.write,
                g.prepare,
                g.observer,
                environment,
                plan.p.a.NATIVE,
                g.Systemd.witness,
            ) = self.original
            g.ENV.clear()
            g.ENV.update(environment)
            _active = None

    def _created(self, path, data):
        info = os.stat(path, follow_symlinks=False)
        lab.need(
            path in (g.UNITS / g.UNIT, g.UNITS / g.WITNESS)
            and info.st_uid == 0
            and stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1,
            "exclusive current unit ownership required",
        )
        self.owned.add(path.name)  # Before any receipt write can fail.
        self.created[path.name] = dict(
            device=info.st_dev,
            inode=info.st_ino,
            sha256=hashlib.sha256(
                data if type(data) is bytes else data.encode()
            ).hexdigest(),
        )
        lab.save_json(
            self.output / ("created-" + path.name + ".json"), self.created[path.name]
        )

    def _initialize(self, create=False):
        lab.need(
            create is True and self.initialization is None,
            "only genuine empty initialization",
        )
        manual._base_created(self.output)
        # args is also usable during this private callback, before public return.
        self.ready = True
        self.initialization = manual.initializer.initialize(
            self.output / "initialize", **self.args
        )
        self.owned.add(setup.role.INITIALIZER_UNIT)
        self.tracked[setup.role.INITIALIZER_UNIT] = [
            self.initialization["proof"]["actor"]["evidence"]["before"]
        ]
        return self.initialization


def prepare_telemetry_assignment(
    output,
    *,
    manifest_sha256,
    start_head,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """Create one current empty v2 scope; returned owner MUST be closed."""
    global _active
    lab.need(
        _active is None and Path(output) == WORK,
        "fixed unused assignment output required",
    )
    pins = dict(
        source_commit=source_commit,
        archive_sha256=archive_sha256,
        core_sha256=core_sha256,
        abi_sha256=abi_sha256,
        interpreter_sha256=interpreter_sha256,
    )
    inputs = validated_telemetry_inputs(manifest_sha256, start_head, **pins)
    baseline = setup.preflight(output, **pins)  # All guards before scope mutation.
    context = TelemetryAssignmentContext(_TOKEN, Path(output), inputs, baseline)
    _active = context
    try:
        lab.save_json(context.output / "inputs.json", inputs)
        _sync_dir(context.output)
        context.namespaces.prepare_service()
        fd, pair = context.namespaces.edge()
        material.preflight.old.private_output(context.output / "initialize")
        context.transport_context = manual._configure(
            context._initialize,
            context._created,
            pair,
            owner=context.namespaces,
            output=context.output,
            arm=inputs["assignment"]["arm"],
        )
        for index in (1, 2, 3):
            for kind in ("intent", "confirmed"):
                name = f"namespace-{kind}-{index}.json"
                lab.save(
                    context.output / name,
                    material._read(context.namespaces.work / name, 8192),
                )
        lab.save_json(
            context.output / "namespace-boot.json",
            dict(
                kernel_boot_id=baseline["kernel_boot_id"],
                names=plan.names(),
                root_before=baseline["root_before"],
                foreign=context.namespaces.assets.foreign,
            ),
        )
        lab.need(not os.path.lexists(g.BASE), "fresh scope only")
        lab.save_json(
            context.output / "auth-scope-create-intent.json",
            dict(
                creator="current_guest_prepare_lab",
                environment=plan.native_environment(inputs["assignment"]["arm"]),
            ),
        )
        _sync_dir(context.output)
        g.prepare_lab()  # Witness first, genuine initialization; native stays stopped.
        context.tracked[g.WITNESS] = [lab.unit_snapshot(g.WITNESS)]
        trust = TrustPolicy(plan.strict(material._read(g.BUNDLE / "trust.json", 8192)))
        layout(g.BUNDLE, trust)
        enrolled = registration(trust, g.BUNDLE / "origin.json")
        lab.need(
            context.initialization is not None
            and trust.data["schema_version"] == "outcome-input-trust/v4"
            and enrolled["environment"]
            == plan.native_environment(inputs["assignment"]["arm"])
            and enrolled["binary_sha256"] == core_sha256
            and not g.Systemd().cores(),
            "prepared empty registration/native state differs",
        )
        context.namespaces.edge()
        context.ready = True
        lab.save_json(
            context.output / "prepared.json",
            dict(
                schema_version="signed-network-telemetry-prepared/v2",
                inputs=inputs,
                kernel_boot_id=baseline["kernel_boot_id"],
                trust_policy=dict(trust.data),
                registration=enrolled,
                initialization=context.initialization,
                namespace_kind=plan.telemetry_assignment_mode()["namespace_kind"],
                assignment_mode_sha256=inputs["assignment_mode_sha256"],
                measurement_completed=False,
                production_admission=False,
            ),
        )
        _sync_dir(context.output)
        return context
    except BaseException as error:
        try:
            context.close()
        except BaseException as cleanup:
            error.add_note("prepare cleanup: " + type(cleanup).__name__)
        raise
