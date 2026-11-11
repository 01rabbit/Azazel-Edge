"""Fixed owned namespace/marker state; no authenticated scope or actor provisioning.

Keep the state object across prepare failures and always call close. Outer owners
must first stop their witness/core/observer actors; this helper never signals them.
"""

import os
from pathlib import Path
import stat

import signed_network_telemetry_marker as marker
from telemetry_isolation_controller import _close_namespace_fd

setup, lab, material = marker.setup, marker.lab, marker.material


class NamespaceSetup:
    def __init__(self, output, baseline):
        self.output, self.baseline = Path(output), baseline
        self.work = self.output / "namespace-evidence"
        self.assets = setup.scope.FencedAssets(self.work)
        self.assets.names = setup.plan.names()
        self.marker = marker.Marker(self.output / "namespace-marker", baseline)
        self.ready = self.failed = self.closed = False
        self.receipt = self.workspace_identity = None

    def _workspace(self):
        info = os.stat(self.work, follow_symlinks=False)
        lab.need(
            self.workspace_identity == (info.st_dev, info.st_ino)
            and info.st_uid == 0
            and stat.S_ISDIR(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700,
            "owned namespace workspace replaced",
        )

    def _fence_all(self):
        lab.need(
            tuple(self.assets.names.values()) == setup.role.NAMESPACE_NAMES,
            "exact fixed namespace set required",
        )
        for kind in self.assets.names:
            self.assets._check(kind)
            fd = self.assets.created[self.assets.names[kind]][0]
            lab.need(
                not os.get_inheritable(fd), "parent-only CLOEXEC namespace FD required"
            )

    def edge(self):
        lab.need(self.ready and not self.closed, "namespace context is not usable")
        self._fence_all()
        fd, device, inode = self.assets.created[self.assets.names["edge"]]
        return fd, [device, inode]

    def _audit(self, phase):
        errors = []
        pins = self.baseline["pins"]
        for name, operation, expected in (
            ("assets", setup._assets, self.baseline["assets"]),
            ("parent", setup.n.root_snapshot, self.baseline["root_before"]),
            (
                "material",
                lambda: material.verify_current(
                    abi_sha256=pins["abi_sha256"],
                    interpreter_sha256=pins["interpreter_sha256"],
                ),
                self.baseline["material"],
            ),
        ):
            try:
                value = operation()
                lab.save_json(
                    self.output / ("namespace-" + phase + "-" + name + ".json"), value
                )
                lab.need(value == expected, "namespace invariant changed")
            except BaseException as exc:
                errors.append((name, type(exc).__name__))
        lab.need(not errors, "namespace invariants incomplete: " + str(errors))

    def prepare(self):
        lab.need(not self.ready and not self.closed, "new context only; no retry")
        try:
            setup.g.guard()
            material.preflight._output(self.output)
            lab.need(
                setup.g.boot() == self.baseline["kernel_boot_id"],
                "namespace boot differs",
            )
            setup._fresh(
                self.work
            )  # Existing parent evidence is allowed, no scope/name is.
            self._audit("before")
            lab.save_json(
                self.output / "namespace-workspace-intent.json",
                dict(path=str(self.work), mode=0o700),
            )
            material.preflight.old.private_output(self.work)
            fd = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                named = os.stat(self.work, follow_symlinks=False)
                self.workspace_identity = (info.st_dev, info.st_ino)
                lab.need(
                    info.st_uid == 0
                    and stat.S_IMODE(info.st_mode) == 0o700
                    and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino),
                    "workspace identity differs",
                )
                lab.save_json(
                    self.output / "namespace-workspace-created.json",
                    dict(device=info.st_dev, inode=info.st_ino),
                )
            finally:
                os.close(fd)
            for kind, name in self.assets.names.items():
                self.assets.create_namespace(
                    name
                )  # Existing intent + immediate FD confirmation.
                self.assets.ns(kind, "ip", "link", "set", "lo", "up")
            self._fence_all()
            self.assets.ns("edge", "ip", "link", "add", "es", "type", "dummy")
            self.assets.ns("edge", "ip", "link", "set", "es", "up")
            self._fence_all()
            self.marker.start()  # Fresh dedicated child; marker alone is NOT a fence.
            self._fence_all()
            lab.save_json(
                self.output / "namespace-prepared.json",
                dict(
                    kernel_boot_id=self.baseline["kernel_boot_id"],
                    names=self.assets.names,
                    scope="owned_namespaces_and_dependency_marker_only",
                    authorizes_transition=False,
                    experiment=False,
                    production_admission=False,
                ),
            )
            self.ready = True
            return self
        except BaseException:
            self.failed = True  # Unknown creation/persistence outcomes retain names.
            raise

    def _empty(self, name, prefix):
        self._workspace()
        code, raw = material.preflight.old._retained_query(
            ["ip", "netns", "pids", name], prefix, self.work
        )
        lab.need(
            code == 0 and len(raw) <= 4096 and not raw.strip(),
            "namespace residents/unknown query",
        )

    def close(self):
        if self.closed:
            lab.need(
                self.receipt is not None and not self.receipt["errors"],
                "previous close failed; no retry",
            )
            return self.receipt
        self.closed = True
        receipt = self.receipt = dict(
            errors=[], actors=[], names=[], cleanup_verified=False
        )

        def attempt(step, operation):
            try:
                return operation()
            except BaseException as exc:
                receipt["errors"].append(dict(step=step, error=type(exc).__name__))

        attempt("owned marker stop", self.marker.stop)
        # Never stop an unexpected outer or legacy actor. Always inspect every group.
        for unit in setup.UNITS:
            state = attempt(unit + ":state", lambda unit=unit: setup.scope._state(unit))

            def empty(unit=unit, state=state):
                lab.need(
                    type(state) is dict
                    and state["ActiveState"] in ("inactive", "failed")
                    and state["MainPID"] == state["ControlPID"] == "0",
                    "outer actor still active/unknown",
                )
                if unit in (setup.scope.INITIALIZER_UNIT, setup.scope.OBSERVER_UNIT):
                    lab.need(
                        setup.scope._known_collected(state), "unexpected legacy unit"
                    )
                lab.need(
                    lab.cg.group_empty(state["ControlGroup"], setup.UNITS),
                    "outer group not empty",
                )

            attempt(unit + ":empty", empty)
            attempt(
                unit + ":canonical",
                lambda unit=unit: lab.need(
                    lab.cg.group_empty("/system.slice/" + unit, setup.UNITS),
                    "canonical group not empty",
                ),
            )
            receipt["actors"].append(dict(unit=unit, state=state))
        attempt(
            "native scan",
            lambda: lab.need(not setup.g.Systemd().cores(), "native process remains"),
        )
        attempt(
            "boot",
            lambda: lab.need(
                setup.g.boot() == self.baseline["kernel_boot_id"], "boot changed"
            ),
        )
        attempt("before-delete invariants", lambda: self._audit("close-before"))

        def confirmed():
            lab.need(
                not self.failed
                and set(self.assets.creation_intents) == set(self.assets.created)
                and all(
                    v["state"] == "confirmed_created"
                    for v in self.assets.creation_intents.values()
                ),
                "setup/creation/persistence uncertainty: retain namespaces",
            )

        attempt("all creation outcomes", confirmed)
        for index, name in enumerate(self.assets.created, 1):
            kind = next(k for k, v in self.assets.names.items() if v == name)
            attempt(name + ":fence", lambda kind=kind: self.assets._check(kind))
            attempt(
                name + ":residents",
                lambda name=name, index=index: self._empty(
                    name, "namespace-residents-" + str(index)
                ),
            )
        attempt(
            "actor receipt",
            lambda: lab.save_json(
                self.output / "namespace-actor-cleanup.json", receipt
            ),
        )
        if not receipt["errors"]:
            for index, name in enumerate(reversed(list(self.assets.created)), 1):
                kind = next(k for k, v in self.assets.names.items() if v == name)

                def delete(name=name, kind=kind, index=index):
                    self.assets._check(kind)
                    self._empty(name, "namespace-predelete-residents-" + str(index))
                    lab.save_json(
                        self.work / ("namespace-delete-intent-" + str(index) + ".json"),
                        dict(name=name),
                    )
                    self.assets._check(kind)
                    code, _ = material.preflight.old._retained_query(
                        ["ip", "netns", "del", name],
                        "namespace-delete-" + str(index),
                        self.work,
                    )
                    lab.need(
                        code == 0 and not os.path.lexists(Path("/run/netns") / name),
                        "namespace deletion unknown",
                    )
                    receipt["names"].append(name)

                attempt(name + ":delete", delete)
                if receipt["errors"]:
                    break
        for fd, device, inode in self.assets.created.values():
            attempt(
                "owned FD close",
                lambda fd=fd, device=device, inode=inode: _close_namespace_fd(
                    fd, device, inode
                ),
            )
        attempt("after-delete invariants", lambda: self._audit("close-after"))
        receipt["cleanup_verified"] = not receipt["errors"]
        if self.workspace_identity is not None:

            def evidence():
                self._workspace()
                lab.save_json(self.work / "cleanup.json", receipt)

            attempt("namespace cleanup evidence", evidence)
        receipt["cleanup_verified"] = not receipt["errors"]
        lab.need(
            not receipt["errors"],
            "namespace/marker cleanup incomplete; retain used case",
        )
        return receipt
