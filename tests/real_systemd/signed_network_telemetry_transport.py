"""Fixed Root witness metadata for the explicit lab transport, never admission."""

from dataclasses import dataclass
import hashlib
import os
import re
import time

import signed_network_telemetry_material as material
import signed_network_telemetry_contract as role
from azazel_edge.outcome.input_transport import SCHEMA, validate_transport

p, lab, g = material.preflight, material.preflight.lab, material.preflight.old.g


@dataclass(frozen=True)
class _StartupPending:
    inode: str
    fd: str
    abstract_name: str


def witness_command():
    return (
        f"{g.PYTHON} -I -B -m azazel_edge.outcome.input_witness "
        f"--policy {g.BUNDLE}/trust.json --private-key {g.BUNDLE}/witness/key.raw "
        "--apparmor-profile edge400-witness"
    )


def _witness_sample(auth, namespace, output, phase, observed_namespace, index):
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
        auth["trust_schema"] == SCHEMA
        and transport["network_namespace"] == observed_namespace
        and observed_namespace["kernel_boot_id"] == g.boot(),
        "current explicit transport/owned EDGE differs",
    )
    prefix = "witness-" + phase + "-sample-" + str(index)
    evidence = dict(
        transport=transport,
        namespace_observation=observed_namespace,
        owned_namespace=expected,
    )
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
            Type="exec",
            NotifyAccess="none",
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
            prefix + "-effective",
            output,
        )
        pairs = [line.split("=", 1) for line in raw.decode().splitlines()]
        lab.need(
            code == 0
            and material._read(output / (prefix + "-effective.stderr"), 4096) == b""
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
            == ["NetworkNamespacePath=" + role.NSFS_TARGETS[0]]
            and [x for x in lines if x.lstrip().startswith("Type=")] == ["Type=exec"]
            and [x for x in lines if x.lstrip().startswith("NotifyAccess=")]
            == ["NotifyAccess=none"],
            "fixed witness file differs",
        )
        label = p.cg._kernel_text(f"/proc/{pid}/attr/apparmor/current", 4096)
        evidence["label"] = label
        info = os.stat(f"/proc/{pid}/ns/net")
        evidence["namespace"] = dict(device=info.st_dev, inode=info.st_ino)
        listener = _listener(
            pid,
            transport["name"],
            output,
            prefix,
            allow_startup_transition=phase == "initialize-initial",
        )
        pending = listener if type(listener) is _StartupPending else None
        evidence["listener"] = None if pending is not None else listener
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
            namespace_observation=observed_namespace,
            listener=evidence["listener"],
        ), pending
    finally:
        lab.save_json(output / (prefix + ".json"), evidence)


def _listener_row(raw, name):
    lines = raw.splitlines()
    lab.need(
        raw.endswith("\n")
        and 1 <= len(lines) <= 2049
        and lines[0].split()
        == ["Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path"],
        "unknown Unix socket table",
    )
    listeners, seen = [], set()
    for line in lines[1:]:
        row = line.split(maxsplit=7)
        lab.need(
            len(row) in (7, 8)
            and re.fullmatch(r"[0-9a-fA-F]{8,16}:", row[0]) is not None
            and all(re.fullmatch(r"[0-9A-F]{8}", v) for v in row[1:4])
            and re.fullmatch(r"[0-9A-F]{4}", row[4]) is not None
            and re.fullmatch(r"[0-9A-F]{2}", row[5]) is not None
            and re.fullmatch(r"0|[1-9][0-9]{0,19}", row[6]) is not None
            and int(row[6]) < 2**64,
            "malformed Unix socket row",
        )
        if row[6] != "0":
            lab.need(row[6] not in seen, "duplicate Unix socket inode")
            seen.add(row[6])
        if len(row) == 8 and row[7] == "@" + name:
            lab.need(
                row[2] == "00000000"
                and row[4] == "0001"
                and row[3] in ("00000000", "00010000"),
                "wrong expected socket kind",
            )
            if row[3] == "00010000":
                lab.need(
                    row[5] == "01" and row[6] != "0", "invalid expected listener state"
                )
                listeners.append(row[6])
    lab.need(len(listeners) <= 1, "ambiguous expected listener")
    return listeners[0] if listeners else None


def _startup_forward(before, after, name, inode):
    """Already syntax-validated tables: exactly unnamed→named LISTEN, same row."""

    def rows(raw):
        return [line.split(maxsplit=7) for line in raw.splitlines()[1:]]

    old = [row for row in rows(before) if row[6] == inode]
    new = [row for row in rows(after) if row[6] == inode]
    return (
        len(old) == len(new) == 1
        and len(old[0]) == 7
        and len(new[0]) == 8
        and old[0][2:6] == ["00000000", "00000000", "0001", "01"]
        and new[0][2:6] == ["00000000", "00010000", "0001", "01"]
        and new[0][7] == "@" + name
        and old[0][:3] == new[0][:3]
    )


def _listener(pid, name, output, prefix, *, allow_startup_transition=False):
    evidence = dict(pid=pid, links=[], names=[])
    try:
        raw = p.cg._kernel_text(f"/proc/{pid}/net/unix", 256 * 1024)
        lab.save(output / (prefix + "-unix-before.raw"), raw.encode("ascii"))
        inode = _listener_row(raw, name)
        with os.scandir(f"/proc/{pid}/fd") as entries:
            for entry in entries:
                evidence["names"].append(entry.name)
                lab.need(
                    len(evidence["links"]) < 256
                    and re.fullmatch(r"0|[1-9][0-9]{0,9}", entry.name) is not None
                    and int(entry.name) < 2**31
                    and evidence["names"].count(entry.name) == 1,
                    "unknown witness FD inventory",
                )
                target = os.readlink(f"/proc/{pid}/fd/{entry.name}")
                evidence["links"].append(dict(fd=entry.name, target=target))
                lab.need(len(target) <= 4096, "oversized witness FD target")
        # Persist the complete unparsed kernel inventory before interpreting links.
        lab.save_json(output / (prefix + "-fd.raw.json"), evidence)
        matched = (
            [
                row["fd"]
                for row in evidence["links"]
                if row["target"] == f"socket:[{inode}]"
            ]
            if inode is not None
            else []
        )
        lab.need(
            inode is None or len(matched) == 1,
            "listener not uniquely held by witness PID",
        )
        raw_after = p.cg._kernel_text(f"/proc/{pid}/net/unix", 256 * 1024)
        lab.save(output / (prefix + "-unix-after.raw"), raw_after.encode("ascii"))
        after_inode = _listener_row(raw_after, name)
        if inode is None and after_inode is not None and allow_startup_transition:
            lab.need(
                _startup_forward(raw, raw_after, name, after_inode),
                "not an exact startup listener transition",
            )
            held = [
                row["fd"]
                for row in evidence["links"]
                if row["target"] == f"socket:[{after_inode}]"
            ]
            lab.need(
                len(held) == 1
                and os.readlink(f"/proc/{pid}/fd/{held[0]}")
                == f"socket:[{after_inode}]",
                "startup listener FD changed or ambiguous",
            )
            evidence["startup_transition_pending"] = dict(inode=after_inode, fd=held[0])
            return _StartupPending(
                after_inode, held[0], name
            )  # Final actor fences still mandatory.
        lab.need(after_inode == inode, "listener changed during sample")
        if inode is None:
            return None
        fd = matched[0]
        lab.need(
            os.readlink(f"/proc/{pid}/fd/{fd}") == f"socket:[{inode}]",
            "listener FD changed during sample",
        )
        return dict(inode=inode, fd=fd, abstract_name=name)
    except BaseException as exc:
        evidence["error"] = type(exc).__name__
        raise
    finally:
        lab.save_json(output / (prefix + "-listener.json"), evidence)


def witness_binding(auth, namespace, output, phase, observed_namespace):
    """Only initial pre-Popen readiness may passively await an absent listener."""
    initial = phase == "initialize-initial"
    deadline, previous, receipt = time.monotonic() + 2, None, dict(samples=[])
    candidate = None
    try:
        for index in range(101):
            current, pending = _witness_sample(
                auth, namespace, output, phase, observed_namespace, index
            )
            receipt["samples"].append(current)
            if candidate is not None:
                lab.need(
                    pending is None
                    and current["listener"]
                    == dict(
                        inode=candidate.inode,
                        fd=candidate.fd,
                        abstract_name=candidate.abstract_name,
                    ),
                    "pending startup listener disappeared, changed or was not stable",
                )
            if pending is not None:
                candidate = pending
            stable = {key: value for key, value in current.items() if key != "listener"}
            lab.need(
                previous is None or stable == previous,
                "witness changed during readiness wait",
            )
            previous = stable
            lab.need(
                not initial or time.monotonic() <= deadline,
                "initial listener readiness exceeded two seconds",
            )
            if current["listener"] is not None:
                return current
            lab.need(
                initial and index < 100 and time.monotonic() < deadline,
                "expected witness listener absent",
            )
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    finally:
        # The phase is validated by the fixed sampler before creating any path.
        if receipt["samples"]:
            lab.save_json(output / ("witness-" + phase + ".json"), receipt)
