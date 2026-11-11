"""Fixed owned provider dependency marker ONLY, never namespace/API readiness.

The outer namespace owner fences all three handles before use. This component
creates no namespace, scope, key, witness or core, and grants no role capability.
"""

import hashlib
import os
from pathlib import Path
import stat

import signed_network_telemetry_commission_setup as setup

lab, g, p, material = setup.lab, setup.g, setup.p, setup.material
UNIT_TEXT = """[Unit]
Description=Owned single-case namespace dependency marker only
DefaultDependencies=no
[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX
Restart=no
TimeoutStartSec=5
TimeoutStopSec=3
ExecStart=/usr/bin/true
"""


def _validate(value):
    expected = dict(
        User="root",
        Group="root",
        NoNewPrivileges="yes",
        CapabilityBoundingSet="",
        AmbientCapabilities="",
        RestrictAddressFamilies="AF_UNIX",
        Restart="no",
        DefaultDependencies="no",
        NetworkNamespacePath="",
        AppArmorProfile="",
        DropInPaths="",
        FragmentPath=str(g.UNITS / p.NET_UNIT),
        TimeoutStopUSec="3s",
    )
    empty = (
        *material.preflight.old.HOOKS,
        "Wants",
        "Requisite",
        "BindsTo",
        "PartOf",
        "Upholds",
        "OnFailure",
        "OnSuccess",
        "Triggers",
        "TriggeredBy",
        "Before",
        "Conflicts",
    )
    lab.need(
        all(value[k] == v for k, v in expected.items())
        and all(value[k] == "" for k in empty)
        and set(value["Requires"].split()) <= {"system.slice"}
        and set(value["After"].split()) <= {"system.slice", "systemd-journald.socket"},
        "unexpected dependency marker authority/hooks",
    )
    command = value["ExecStart"]
    lab.need(
        command.startswith("{ ")
        and command.endswith(" }")
        and command.count("{") == command.count("}") == 1,
        "ambiguous marker command",
    )
    rows = [part.partition("=") for part in command[2:-2].split(" ; ")]
    lab.need(
        all(sep for _, sep, _ in rows) and len({k for k, _, _ in rows}) == len(rows),
        "duplicate marker command field",
    )
    fields = {k: v for k, _, v in rows}
    lab.need(
        fields.get("path") == fields.get("argv[]") == "/usr/bin/true"
        and fields.get("ignore_errors") == "no",
        "marker command differs",
    )


class Marker:
    """Create the state object before start; retain it through every failure."""

    def __init__(self, output, baseline):
        self.output, self.baseline, self.identity = Path(output), baseline, None
        self.finalized = self.manager_attempted = self.start_attempted = False

    def _identity(self):
        parent, name = material.preflight.open_parent(
            g.UNITS / p.NET_UNIT, trusted_owner=0
        )
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            lab.need(
                (info.st_dev, info.st_ino) == self.identity
                and info.st_uid == 0
                and stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1,
                "owned marker file identity differs; no foreign stop",
            )
            return info
        finally:
            os.close(parent)

    def start(self):
        g.guard()
        pins = self.baseline["pins"]
        lab.need(
            g.boot() == self.baseline["kernel_boot_id"]
            and material.verify_current(
                abi_sha256=pins["abi_sha256"],
                interpreter_sha256=pins["interpreter_sha256"],
            )
            == self.baseline["material"],
            "current marker source/material differs",
        )
        lab.need(
            not os.path.lexists(self.output),
            "fresh dedicated marker evidence child required",
        )
        material.preflight.old.private_output(self.output)
        material.preflight._output(self.output)
        setup._unit_material(self.output)  # All families/prefixes, before creation.
        lab.need(
            setup.scope._known_collected(setup.scope._state(p.NET_UNIT))
            and lab.cg.group_empty("/system.slice/" + p.NET_UNIT, setup.UNITS),
            "existing marker refused",
        )
        raw = UNIT_TEXT.encode()
        lab.save_json(
            self.output / "marker-file-intent.json",
            dict(
                path=str(g.UNITS / p.NET_UNIT),
                sha256=hashlib.sha256(raw).hexdigest(),
                mode=0o644,
                scope="dependency_marker_only",
            ),
        )
        parent, name = material.preflight.open_parent(
            g.UNITS / p.NET_UNIT, trusted_owner=0
        )
        fd = None
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            info = os.fstat(fd)
            self.identity = (info.st_dev, info.st_ino)
            self._identity()
            lab.save_json(
                self.output / "marker-file-created.json",
                dict(device=info.st_dev, inode=info.st_ino),
            )
            os.fchmod(fd, 0o644)
            lab.need(os.write(fd, raw) == len(raw), "short marker file write")
            os.fsync(fd)
            os.fsync(parent)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)
        lab.need(
            stat.S_IMODE(self._identity().st_mode) == 0o644
            and material._read(g.UNITS / p.NET_UNIT, 16384, 0o644) == raw,
            "marker file bytes/mode differ",
        )
        self.finalized = True
        lab.save_json(
            self.output / "marker-file-finalized.json",
            dict(
                device=self.identity[0],
                inode=self.identity[1],
                mode=0o644,
                sha256=hashlib.sha256(raw).hexdigest(),
            ),
        )
        for prefix, argv in (
            ("marker-reload", ["systemctl", "daemon-reload"]),
            ("marker-start", ["systemctl", "start", p.NET_UNIT]),
        ):
            lab.save_json(
                self.output / (prefix + "-intent.json"),
                dict(argv=argv, file_identity=self.identity),
            )
            self.manager_attempted = True
            if prefix == "marker-start":
                self.start_attempted = True
            code, _ = material.preflight.old._retained_query(argv, prefix, self.output)
            lab.need(code == 0, "owned marker manager command failed")
        effective = material.preflight._collect_effective(
            p.NET_UNIT, "marker", self.output
        )
        _validate(effective)
        code, raw_state = material.preflight.old._retained_query(
            [
                "systemctl",
                "show",
                p.NET_UNIT,
                "--property=Type,RemainAfterExit,ActiveState,SubState,LoadState,MainPID,ControlPID",
            ],
            "marker-state",
            self.output,
        )
        rows = [row.partition("=") for row in raw_state.decode().splitlines()]
        lab.need(
            code == 0
            and len(raw_state) <= 4096
            and all(sep for _, sep, _ in rows)
            and len(rows) == len({k for k, _, _ in rows}),
            "unknown marker state",
        )
        lab.need(
            {k: v for k, _, v in rows}
            == dict(
                Type="oneshot",
                RemainAfterExit="yes",
                ActiveState="active",
                SubState="exited",
                LoadState="loaded",
                MainPID="0",
                ControlPID="0",
            )
            and lab.cg.group_empty("/system.slice/" + p.NET_UNIT, setup.UNITS),
            "marker not active-exited/empty",
        )
        self._identity()
        lab.save_json(
            self.output / "marker-verified.json",
            dict(
                effective=effective,
                scope="dependency_marker_only",
                authorizes_transition=False,
                experiment=False,
                production_admission=False,
            ),
        )
        return self

    def _finalized_file(self, prefix):
        info = self._identity()
        lab.save_json(
            self.output / (prefix + "-file.json"),
            dict(device=info.st_dev, inode=info.st_ino, mode=info.st_mode),
        )
        lab.need(
            self.finalized and stat.S_IMODE(info.st_mode) == 0o644,
            "finalized exact marker file mode required",
        )
        raw = material._read(g.UNITS / p.NET_UNIT, 16384, 0o644)
        lab.save_json(
            self.output / (prefix + "-file-hash.json"),
            dict(sha256=hashlib.sha256(raw).hexdigest()),
        )
        lab.need(raw == UNIT_TEXT.encode(), "finalized marker bytes changed")
        self._identity()

    def stop(self):
        if self.identity is None:
            return dict(errors=[], scope="marker_not_created", stop_attempted=False)
        if not self.start_attempted:
            return dict(
                errors=[],
                scope="marker_not_started_no_stop_authority",
                stop_attempted=False,
            )
        before = setup.scope._state(p.NET_UNIT)
        lab.save_json(self.output / "marker-stop-before.json", before)
        if setup.scope._known_collected(before):
            empty = lab.cg.group_empty("/system.slice/" + p.NET_UNIT, setup.UNITS)
            after = setup.scope._state(p.NET_UNIT)
            lab.save_json(self.output / "marker-stop-absent-after.json", after)
            lab.need(
                empty
                and setup.scope._known_collected(after)
                and lab.cg.group_empty("/system.slice/" + p.NET_UNIT, setup.UNITS),
                "unknown absent marker cgroup",
            )
            return dict(
                errors=[],
                scope="marker_known_absent_full_cgroup_empty",
                stop_attempted=False,
            )
        self._finalized_file("marker-stop-before")
        effective = material.preflight._collect_effective(
            p.NET_UNIT, "marker-stop-fence", self.output
        )
        lab.save_json(self.output / "marker-stop-effective.json", effective)
        _validate(effective)
        code, raw = material.preflight.old._retained_query(
            [
                "systemctl",
                "show",
                p.NET_UNIT,
                "--property=Type,RemainAfterExit,LoadState",
            ],
            "marker-stop-type",
            self.output,
        )
        rows = [row.partition("=") for row in raw.decode().splitlines()]
        lab.need(
            code == 0
            and len(raw) <= 4096
            and all(sep for _, sep, _ in rows)
            and len(rows) == len({k for k, _, _ in rows})
            and {k: v for k, _, v in rows}
            == dict(Type="oneshot", RemainAfterExit="yes", LoadState="loaded"),
            "current marker type/loaded identity differs",
        )
        self._finalized_file("marker-stop-recheck")
        receipt = lab.cleanup((p.NET_UNIT,), {p.NET_UNIT: []})
        lab.save_json(self.output / "marker-stop.json", receipt)
        lab.need(receipt["errors"] == [], "owned marker stop/cgroup proof incomplete")
        return receipt
