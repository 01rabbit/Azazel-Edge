"""Explicit owned Root child for the unchanged sealed-Switch witness proof.

Never changes the parent namespace or passes a namespace FD to the observer.
Only the separate manual lab commissioner installs this adapter temporarily.
"""

import ctypes
import json
import os
import select
import signal
import socket
import time

import signed_network_telemetry_transport as context
from azazel_edge.outcome.input_transport import (
    SCHEMA,
    validate_transport,
    transport,
    socket_namespace,
)

lab, g = context.lab, context.g
ACK = {
    "namespace-metadata": b"sample-unbound-namespace\n",
    "original-witness": b"run-original-witness-proof\n",
}


def _net():
    info = os.stat("/proc/self/ns/net")
    return dict(device=info.st_dev, inode=info.st_ino)


def _frame(fd, deadline, retained):
    while not retained.endswith(b"\n"):
        left = deadline - time.monotonic()
        lab.need(
            left > 0 and select.select([fd], [], [], left)[0], "witness child deadline"
        )
        part = os.read(fd, 1025 - len(retained))
        retained.extend(part)
        lab.need(part and len(retained) <= 1024, "witness child EOF/overflow")
    lab.need(retained.count(b"\n") == 1, "one child frame required")


def _send(fd, value):
    raw = json.dumps(value, sort_keys=True, allow_nan=False).encode() + b"\n"
    lab.need(len(raw) <= 1024 and os.write(fd, raw) == len(raw), "short child frame")


def _exited(pid, deadline):
    while True:
        exited = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if exited is not None:
            lab.need(exited.si_pid == pid, "owned child exit identity differs")
            return exited
        lab.need(time.monotonic() < deadline, "owned child exit deadline")
        time.sleep(0.01)


def _members(pid):
    """Root metadata only; leader stays unreaped to reserve its process group."""
    members = {}
    with os.scandir("/proc") as entries:
        for index, entry in enumerate(entries):
            lab.need(index < 4096, "owned group inventory bound")
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            try:
                raw = context.p.cg._kernel_text(f"/proc/{entry.name}/stat", 8192)
            except (FileNotFoundError, ProcessLookupError):
                continue
            fields = raw.rsplit(")", 1)[1].split()
            lab.need(
                raw.split(" ", 1)[0] == entry.name and len(fields) >= 20,
                "unknown group inventory",
            )
            if entry.name != str(pid) and (
                fields[2] == str(pid) or fields[3] == str(pid)
            ):
                members[entry.name] = dict(
                    state=fields[0],
                    group=fields[2],
                    session=fields[3],
                    start_ticks=fields[19],
                )
    return members


class WitnessProof:
    def __init__(self, owner, output):
        self.owner, self.output, self.count = owner, output, 0
        self.namespace = None

    def sample_namespace(self):
        observed = self._execute("namespace-metadata")
        if self.namespace is not None:
            if observed != self.namespace:
                self.owner.failed = True
                raise RuntimeError("owned namespace cookie/boot changed")
        self.namespace = observed
        return dict(observed)

    def run(self, original, system, bundle, policy):
        declared = validate_transport(
            policy.data["scope_ref"], policy.data["witness_transport"]
        )
        lab.need(
            policy.data["schema_version"] == SCHEMA
            and self.namespace is not None
            and declared["network_namespace"] == self.namespace,
            "current sampled transport required",
        )
        self._execute("original-witness", original, system, bundle, policy)

    def _execute(self, operation, original=None, system=None, bundle=None, policy=None):
        lab.need(
            type(operation) is str and operation in ACK,
            "fixed child operation required",
        )
        g.guard()
        context.p._output(self.output)
        lab.need(
            os.environ.get(context.material.FLAG) == "1", "explicit lab child required"
        )
        fd, pair = self.owner.edge()
        expected = dict(zip(("device", "inode"), pair))
        parent = _net()
        lab.need(parent != expected, "Root parent must remain outside EDGE")
        self.count += 1
        prefix = (
            "namespace-cookie-"
            if operation == "namespace-metadata"
            else "switch-witness-"
        ) + str(self.count)
        lab.save_json(
            self.output / (prefix + "-intent.json"),
            dict(namespace=expected, parent=parent, operation=operation),
        )
        reply_r = reply_w = go_r = go_w = None
        pid, status, group_owned, error = None, None, False, None
        ready_raw, result_raw = bytearray(), bytearray()
        receipt = dict(
            scope="owned_Root_child_fixed_lab_operation", operation=operation, errors=[]
        )
        deadline = time.monotonic() + 7
        try:
            reply_r, reply_w = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            go_r, go_w = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            pid = os.fork()
            if pid == 0:
                os.close(reply_r)
                os.close(go_w)
                try:
                    os.setsid()  # No descendants before the parent's explicit ACK.
                    self.owner.edge()
                    libc = ctypes.CDLL(None, use_errno=True)
                    libc.setns.argtypes, libc.setns.restype = (
                        [ctypes.c_int, ctypes.c_int],
                        ctypes.c_int,
                    )
                    lab.need(
                        libc.setns(fd, 0x40000000) == 0 and _net() == expected,
                        "owned child namespace transition failed",
                    )
                    identity = lab.pid_identity(
                        context.p.cg._kernel_text("/proc/self/stat", 8192)
                    )
                    _send(
                        reply_w,
                        dict(
                            kind="ready",
                            operation=operation,
                            pid=os.getpid(),
                            start_ticks=identity[1],
                            pgid=os.getpgrp(),
                            sid=os.getsid(0),
                        ),
                    )
                    control = bytearray()
                    _frame(go_r, deadline, control)
                    lab.need(control == ACK[operation], "exact child ACK required")
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unbound:
                        observed = socket_namespace(unbound)
                    if operation == "original-witness":
                        lab.need(
                            observed == self.namespace,
                            "sealed proof namespace cookie differs",
                        )
                        # The unchanged implementation owns its UID61002 subprocess.
                        original(system, bundle, policy)
                    _send(
                        reply_w,
                        dict(
                            kind="complete",
                            operation=operation,
                            pid=os.getpid(),
                            namespace=observed,
                        ),
                    )
                    os._exit(0)
                except BaseException as exc:
                    try:
                        _send(reply_w, dict(kind="blocked", error=type(exc).__name__))
                    finally:
                        os._exit(1)
            receipt["pid"] = pid
            os.close(reply_w)
            reply_w = None
            os.close(go_r)
            go_r = None
            _frame(reply_r, deadline, ready_raw)
            lab.save(self.output / (prefix + "-ready.raw"), bytes(ready_raw))
            from signed_network_plan import strict

            ready = strict(bytes(ready_raw))
            actual = lab.pid_identity(
                context.p.cg._kernel_text(f"/proc/{pid}/stat", 8192)
            )
            namespace = os.stat(f"/proc/{pid}/ns/net")
            lab.need(
                type(ready) is dict
                and set(ready)
                == {"kind", "operation", "pid", "start_ticks", "pgid", "sid"}
                and ready["kind"] == "ready"
                and ready["operation"] == operation
                and type(ready["pid"]) is int
                and ready["pid"] == pid
                and type(ready["pgid"]) is int
                and ready["pgid"] == os.getpgid(pid) == pid
                and type(ready["sid"]) is int
                and ready["sid"] == os.getsid(pid) == pid
                and actual == (str(pid), ready["start_ticks"])
                and [namespace.st_dev, namespace.st_ino] == pair,
                "owned child/session identity differs",
            )
            group_owned = True
            receipt["identity"] = ready
            self.owner.edge()
            lab.save_json(self.output / (prefix + "-authorized.json"), receipt)
            lab.need(
                os.write(go_w, ACK[operation]) == len(ACK[operation]),
                "short owned child ACK",
            )
            os.close(go_w)
            go_w = None
            _frame(reply_r, deadline, result_raw)
            value = strict(bytes(result_raw))
            lab.need(
                type(value) is dict
                and set(value) == {"kind", "operation", "pid", "namespace"}
                and value["kind"] == "complete"
                and value["operation"] == operation
                and type(value["pid"]) is int
                and value["pid"] == pid,
                "fixed owned child operation failed",
            )
            transport("namespace-validation", value["namespace"])
            lab.need(
                value["namespace"]["kernel_boot_id"] == g.boot(), "sample boot differs"
            )
            receipt["namespace_observation"] = value["namespace"]
            self.owner.edge()  # Bind the sample to the still-held original handle.
            exited = _exited(pid, deadline)  # WNOWAIT: group PID remains reserved.
            lab.need(
                exited.si_code == os.CLD_EXITED and exited.si_status == 0,
                "witness child failed",
            )
        except BaseException as exc:
            error = exc
            self.owner.failed = True
        finally:
            if pid is not None and status is None:

                def attempt(name, call):
                    try:
                        return True, call()
                    except BaseException as exc:
                        receipt["errors"].append(name + ":" + type(exc).__name__)
                        self.owner.failed = True
                        return False, None

                reserved, exited = attempt(
                    "exit_probe",
                    lambda: os.waitid(
                        os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
                    ),
                )
                known, members = attempt(
                    "group_inventory", lambda: _members(pid) if group_owned else {}
                )
                receipt["members_before_reap"] = members
                if reserved:
                    if exited is None or not known or members:
                        self.owner.failed = True
                        receipt["forced"] = True
                        attempt(
                            "kill_owned",
                            lambda: os.killpg(pid, signal.SIGKILL)
                            if group_owned
                            else os.kill(pid, signal.SIGKILL),
                        )
                    attempt("leader_exit", lambda: _exited(pid, time.monotonic() + 2))

                    def group_empty():
                        until = time.monotonic() + 2
                        while group_owned:
                            receipt["members_after_kill"] = _members(pid)
                            if not receipt["members_after_kill"]:
                                break
                            lab.need(
                                time.monotonic() < until,
                                "owned descendants remain/unknown",
                            )
                            time.sleep(0.01)

                    receipt["group_empty_before_reap"] = attempt(
                        "group_empty", group_empty
                    )[0]
                # No group signal is permitted after this reap releases its PID.
                if receipt.get("group_empty_before_reap") is True:
                    try:
                        got, reaped = os.waitpid(pid, os.WNOHANG)
                        lab.need(got == pid, "owned leader not reaped")
                        status = reaped
                    except BaseException as exc:
                        receipt["errors"].append("leader_reap:" + type(exc).__name__)
                else:
                    self.owner.failed = True
                    receipt["errors"].append("leader_pid_retained_unknown_group")
            for descriptor in (reply_r, reply_w, go_r, go_w):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except BaseException as exc:
                        receipt["errors"].append("close:" + type(exc).__name__)
            try:
                lab.need(_net() == parent, "Root parent namespace changed")
                receipt.update(
                    reaped=status is not None,
                    status=status,
                    error=type(error).__name__ if error else None,
                )
                lab.save(
                    self.output / (prefix + "-ready-retained.raw"), bytes(ready_raw)
                )
                lab.save(self.output / (prefix + "-result.raw"), bytes(result_raw))
                lab.save_json(self.output / (prefix + "-receipt.json"), receipt)
                lab.need(
                    not receipt["errors"]
                    and status is not None
                    and receipt.get("group_empty_before_reap") is True
                    and not receipt.get("forced"),
                    "owned child cleanup incomplete/forced",
                )
            except BaseException as exc:
                self.owner.failed = True
                if error is None:
                    error = exc
                else:
                    error.add_note("owned child final proof:" + type(exc).__name__)
        if error is not None:
            raise error
        return dict(receipt["namespace_observation"])
