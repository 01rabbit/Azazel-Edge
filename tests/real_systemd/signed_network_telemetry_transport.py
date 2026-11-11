"""Fixed Root witness metadata for the explicit lab transport, never admission."""

import hashlib
import os
import re

import signed_network_telemetry_material as material
import signed_network_telemetry_contract as role
from azazel_edge.outcome.input_transport import SCHEMA, validate_transport

p, lab, g = material.preflight, material.preflight.lab, material.preflight.old.g


def witness_command():
    return (
        f"{g.PYTHON} -I -B -m azazel_edge.outcome.input_witness "
        f"--policy {g.BUNDLE}/trust.json --private-key {g.BUNDLE}/witness/key.raw "
        "--systemd-notify --apparmor-profile edge400-witness"
    )


def witness_binding(auth, namespace, output, phase):
    """Sample the actual fixed witness; never connect or read keys/endpoints."""
    g.guard()
    p._output(output)
    lab.need(os.environ.get(material.FLAG) == "1", "explicit lab transport required")
    lab.need(
        phase
        in {
            "initialize-initial",
            "initialize-before-go",
            "initialize-after-init",
            "live-initial",
            "live-before-go",
            "live-after-terminal",
        },
        "fixed witness evidence phase required",
    )
    expected = dict(zip(("device", "inode"), p.contract._pair(namespace)))
    transport = validate_transport(auth["scope_ref"], auth["witness_transport"])
    lab.need(
        auth["trust_schema"] == SCHEMA and transport["network_namespace"] == expected,
        "current explicit transport/owned EDGE differs",
    )
    evidence = dict(transport=transport)
    try:
        before = lab.unit_snapshot(g.WITNESS)
        evidence["before"] = before
        pid = before["MainPID"]
        lab.need(
            type(pid) is str
            and re.fullmatch(r"[1-9][0-9]{0,9}", pid)
            and 1 < int(pid) < 2**31,
            "actual witness PID required",
        )
        policy, file_info = p.read_regular(
            g.UNITS / g.WITNESS, owner=0, max_bytes=16384
        )
        evidence["unit_file_sha256"] = hashlib.sha256(policy).hexdigest()
        evidence["unit_file_identity"] = [file_info.st_dev, file_info.st_ino]
        expected_properties = dict(
            User="root",
            Group="root",
            AppArmorProfile="edge400-witness",
            NetworkNamespacePath=role.NSFS_TARGETS[0],
            NoNewPrivileges="yes",
            CapabilityBoundingSet="cap_dac_read_search",
            AmbientCapabilities="",
            RestrictAddressFamilies="AF_UNIX",
            Restart="no",
            DropInPaths="",
            FragmentPath=str(g.UNITS / g.WITNESS),
        )
        code, raw = p.old._retained_query(
            [
                "systemctl",
                "show",
                g.WITNESS,
                "--property=" + ",".join((*expected_properties, "ExecStart")),
            ],
            "witness-" + phase + "-effective",
            output,
        )
        pairs = [line.split("=", 1) for line in raw.decode().splitlines()]
        lab.need(
            code == 0
            and material._read(
                output / ("witness-" + phase + "-effective.stderr"), 4096
            )
            == b""
            and len(raw) <= 16384
            and all(len(row) == 2 for row in pairs)
            and len(pairs) == len({row[0] for row in pairs}),
            "unknown witness unit properties",
        )
        value = dict(pairs)
        evidence["effective"] = value
        lab.need(
            set(value) == set(expected_properties) | {"ExecStart"}
            and all(value[k] == v for k, v in expected_properties.items()),
            "witness unit context differs",
        )
        command = value["ExecStart"]
        lab.need(
            command.startswith("{ ")
            and command.endswith(" }")
            and command.count("{") == command.count("}") == 1,
            "ambiguous witness command",
        )
        rows = [row.partition("=") for row in command[2:-2].split(" ; ")]
        lab.need(
            all(sep for _, sep, _ in rows)
            and len(rows) == len({k for k, _, _ in rows}),
            "ambiguous witness command fields",
        )
        fields = {k: v for k, _, v in rows}
        lab.need(
            fields.get("path") == str(g.PYTHON)
            and fields.get("argv[]") == witness_command()
            and fields.get("ignore_errors") == "no",
            "fixed witness command differs",
        )
        lines = policy.decode().splitlines()
        lab.need(
            [x for x in lines if x.lstrip().startswith("ExecStart=")]
            == ["ExecStart=" + witness_command()]
            and [x for x in lines if x.lstrip().startswith("NetworkNamespacePath=")]
            == ["NetworkNamespacePath=" + role.NSFS_TARGETS[0]],
            "fixed witness file differs",
        )
        label = p.cg._kernel_text(f"/proc/{pid}/attr/apparmor/current", 4096)
        evidence["label"] = label
        info = os.stat(f"/proc/{pid}/ns/net")
        evidence["namespace"] = dict(device=info.st_dev, inode=info.st_ino)
        after = lab.unit_snapshot(g.WITNESS)
        evidence["after"] = after
        policy_after, file_after = p.read_regular(
            g.UNITS / g.WITNESS, owner=0, max_bytes=16384
        )
        lab.need(
            all(
                before[k] == after[k]
                for k in (
                    "LoadState",
                    "ActiveState",
                    "MainPID",
                    "ControlPID",
                    "ControlGroup",
                )
            )
            and before["LoadState"] == "loaded"
            and before["ActiveState"] == "active"
            and before["ControlPID"] == "0"
            and before["ControlGroup"] == "/system.slice/" + g.WITNESS
            and lab.pid_identity(before["pid_stat"])
            == lab.pid_identity(after["pid_stat"])
            and label == "edge400-witness (enforce)\n"
            and evidence["namespace"] == expected
            and policy_after == policy
            and (file_after.st_dev, file_after.st_ino)
            == (file_info.st_dev, file_info.st_ino),
            "actual witness identity/namespace drift",
        )
        return dict(
            unit=g.WITNESS,
            pid=int(pid),
            start_ticks=lab.pid_identity(before["pid_stat"])[1],
            apparmor=label.strip(),
            network_namespace=expected,
            unit_file_sha256=evidence["unit_file_sha256"],
            unit_file_identity=evidence["unit_file_identity"],
            witness_transport=transport,
        )
    finally:
        lab.save_json(output / ("witness-" + phase + ".json"), evidence)
