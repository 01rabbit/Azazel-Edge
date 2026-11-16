"""Finite native recv and natural-close protocol copies; no application branch claim."""

import ctypes as C
import errno
import hashlib
import json
import os
from pathlib import Path
import time

from .authority_ingress_bpf import _Libbpf as _Tracing, _role
from .postconnect_copy_bpf import validate_kernel_prototype as _copy_prototype
from .protected_ingress import _proc_bytes
from .safety_observations import _fields, _int


class NaturalCloseRecvBPFError(ValueError):
    pass


def _need(ok, reason):
    if not ok:
        raise NaturalCloseRecvBPFError(reason)


class Configuration(C.Structure):
    _fields_ = [
        (k, C.c_uint64)
        for k in (
            "pidns_device",
            "pidns_inode",
            "server_start_ticks",
            "actor_start_ticks",
            "started_ns",
            "deadline_ns",
        )
    ] + [
        (k, C.c_uint32)
        for k in (
            "server_tgid",
            "actor_tgid",
            "user_hz",
            "max_events",
            "server_uid",
            "actor_uid",
        )
    ]


class Event(C.Structure):
    _fields_ = (
        [
            (k, C.c_uint64)
            for k in (
                "token",
                "entered_ns",
                "exited_ns",
                "start_ns",
                "receiver_inode",
                "peer_inode",
                "endpoint_inode",
                "requested_len",
            )
        ]
        + [("ret", C.c_int64)]
        + [
            (k, C.c_uint32)
            for k in (
                "kind",
                "role",
                "tgid",
                "tid",
                "uid",
                "euid",
                "netns_inode",
                "fd",
                "flags",
                "iter_type",
                "data_source",
                "skip",
                "chunk",
                "consumed",
                "skb_len",
                "data_len",
                "endpoint_major",
                "endpoint_minor",
                "peer_status",
                "endpoint_status",
                "reserved",
                "reserved2",
            )
        ]
        + [("data", C.c_ubyte * 256)]
    )


class Counters(C.Structure):
    _fields_ = [
        (k, C.c_uint64)
        for k in (
            "selected_entries",
            "pending_inserted",
            "successful_copies",
            "emitted",
            "copy_failure",
            "unsupported",
            "read_failure",
            "identity_failure",
            "correlation_loss",
            "overflow",
            "inflight",
            "unmatched_exit",
            "recv_selected",
            "recv_completed",
            "recv_inflight",
            "unmatched_recv_exit",
        )
    ]


assert tuple(map(C.sizeof, (Configuration, Event, Counters))) == (72, 416, 128)
MAPS = {
    "config": (2, 4, 72, 1),
    "recv_pending": (1, 8, 416, 2),
    "copy_pending": (1, 8, 416, 2),
    "events": (1, 4, 416, 32),
    "zero_template": (2, 4, 416, 1),
    "stats": (2, 4, 128, 1),
}
MAP_FLAGS = {name: (128 if name == "zero_template" else 0) for name in MAPS}
PROGRAMS = {
    "recv_entry": (b"fentry/__arm64_sys_recvfrom", 24),
    "recv_exit": (b"fexit/__arm64_sys_recvfrom", 25),
    "copy_entry": (b"fentry/unix_stream_read_actor", 24),
    "copy_exit": (b"fexit/unix_stream_read_actor", 25),
}
SOURCE = (
    Path(__file__).resolve().parents[3] / "native/natural_close_recv_observer.bpf.c"
)


def _configuration(value):
    _fields(value, " ".join(k for k, _ in Configuration._fields_))
    for key, kind in Configuration._fields_:
        _int(value[key], 1, 2 ** (C.sizeof(kind) * 8) - 1)
    _need(
        value["server_tgid"] > 1
        and value["actor_tgid"] > 1
        and value["server_tgid"] != value["actor_tgid"]
        and value["server_uid"] == value["actor_uid"] == 65534
        and value["user_hz"] == 100
        and value["max_events"] <= 32
        and 0 < value["deadline_ns"] - value["started_ns"] <= 5_000_000_000,
        "fixed bounded roles required",
    )
    ns = os.stat("/proc/self/ns/pid")
    _need(
        (ns.st_dev, ns.st_ino) == (value["pidns_device"], value["pidns_inode"]),
        "PID namespace differs",
    )
    _need(
        _proc_bytes("/proc/self/timens_offsets", 4096).split()
        == [b"monotonic", b"0", b"0", b"boottime", b"0", b"0"],
        "zero time namespace required",
    )
    return Configuration(**value)


def _source_hash(expected):
    _need(type(expected) is str and len(expected) == 64, "source pin required")
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        _need(
            a.st_size <= 128 * 1024
            and a.st_nlink == 1
            and (a.st_mode & 0o170000) == 0o100000,
            "source regular bound",
        )
        raw = os.read(fd, 128 * 1024 + 1)
        b = os.fstat(fd)
        _need(
            (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns)
            == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns)
            and len(raw) == a.st_size
            and hashlib.sha256(raw).hexdigest() == expected,
            "fixed source differs",
        )
    finally:
        os.close(fd)


def _dict(value):
    result = {
        name: getattr(value, name) for name, _ in value._fields_ if name != "data"
    }
    if isinstance(value, Event):
        result["data_hex"] = (
            bytes(value.data[: value.chunk]).hex() if value.kind == 1 else ""
        )
        if value.peer_status != 1:
            result["peer_inode"] = None
        if value.endpoint_status != 1:
            for key in ("endpoint_inode", "endpoint_major", "endpoint_minor"):
                result[key] = None
    return result


class _Libbpf(_Tracing):
    def lookup_optional(self, fd, key, value):
        C.set_errno(0)
        rc = self.lib.bpf_map_lookup_elem(fd, C.byref(key), C.byref(value))
        if rc == 0:
            return value
        if rc == -errno.ENOENT:
            return None
        raise NaturalCloseRecvBPFError("event lookup failed")

    def inspect(self, obj):
        maps, programs = {}, {}
        previous = None
        while item := self.lib.bpf_object__next_map(obj, previous):
            previous = item
            name = self.lib.bpf_map__name(item).decode("ascii")
            _need(name in MAPS and name not in maps, "unexpected map")
            actual = tuple(
                getattr(self.lib, "bpf_map__" + k)(item)
                for k in ("type", "key_size", "value_size", "max_entries")
            )
            _need(
                actual == MAPS[name]
                and self.lib.bpf_map__map_flags(item) == MAP_FLAGS[name],
                "map ABI differs",
            )
            maps[name] = item
        previous = None
        while item := self.lib.bpf_object__next_program(obj, previous):
            previous = item
            name = self.lib.bpf_program__name(item).decode("ascii")
            _need(name in PROGRAMS and name not in programs, "unexpected program")
            section, attach = PROGRAMS[name]
            _need(
                self.lib.bpf_program__section_name(item) == section
                and self.lib.bpf_program__type(item) == 26
                and self.lib.bpf_program__expected_attach_type(item) == attach,
                "fixed copy hook required",
            )
            programs[name] = item
        _need(
            set(maps) == set(MAPS) and set(programs) == set(PROGRAMS),
            "missing map/program",
        )
        return maps, programs


def _capture_events(
    configuration, object_raw, *, expected_object_sha256, expected_source_sha256
):
    _role()
    _need(type(configuration) is dict, "configuration object required")
    configuration = configuration.copy()
    cfg = _configuration(configuration)
    _source_hash(expected_source_sha256)
    _need(
        type(object_raw) is bytes
        and 0 < len(object_raw) <= 2 * 1024 * 1024
        and hashlib.sha256(object_raw).hexdigest() == expected_object_sha256,
        "external object pin differs",
    )
    _need(
        configuration["started_ns"]
        <= time.monotonic_ns()
        < configuration["deadline_ns"],
        "deadline unavailable",
    )
    result = dict(
        schema_version="edge-natural-close-probe/v1",
        architecture="aarch64",
        started_ns=configuration["started_ns"],
        finished_ns=None,
        configuration=configuration.copy(),
        events=[],
        counters=None,
        partial_reasons=[],
        link_identities={name: None for name in PROGRAMS},
    )
    backend, obj, links, identities = _Libbpf(), None, {}, {}
    slots = set()

    def reason(label):
        if label not in result["partial_reasons"]:
            result["partial_reasons"].append(label)

    def snapshot():
        try:
            counters = backend.lookup(
                backend.lib.bpf_map__fd(maps["stats"]), C.c_uint32(), Counters()
            )
            result["counters"] = _dict(counters)
        except Exception:
            reason("acquisition_error")
        for index in range(32):
            if index in slots:
                continue
            try:
                event = backend.lookup_optional(
                    backend.lib.bpf_map__fd(maps["events"]), C.c_uint32(index), Event()
                )
                if event is not None:
                    _need(
                        event.kind in (0, 1, 2)
                        and event.token > 0
                        and event.entered_ns > 0,
                        "event kind/token differs",
                    )
                    _need(
                        (event.kind == 0 and event.exited_ns == 0 and event.chunk == 0)
                        or (
                            event.kind in (1, 2)
                            and event.exited_ns > 0
                            and (
                                1 <= event.chunk <= 256
                                if event.kind == 1
                                else event.chunk == 0
                            )
                        ),
                        "event bound differs",
                    )
                    result["events"].append(_dict(event))
                    slots.add(index)
            except Exception:
                reason("acquisition_error")

    def health(name):
        identity = identities.get(name)
        state = backend.check_link(identity) if identity is not None else "unknown"
        if state != "retained":
            reason("observer_link_lost")
            result["link_identities"][name] = None
        return state

    try:
        buffer = C.create_string_buffer(object_raw)
        obj = backend.pointer(
            backend.lib.bpf_object__open_mem(buffer, len(object_raw), None),
            "object open",
        )
        maps, programs = backend.inspect(obj)
        _need(backend.lib.bpf_object__load(obj) == 0, "BPF load failed")
        _need(
            backend.lib.bpf_map_update_elem(
                backend.lib.bpf_map__fd(maps["config"]),
                C.byref(C.c_uint32()),
                C.byref(cfg),
                0,
            )
            == 0,
            "config update failed",
        )
        for name in ("recv_exit", "copy_exit", "copy_entry", "recv_entry"):
            links[name] = backend.pointer(
                backend.lib.bpf_program__attach(programs[name]), "copy attach"
            )
            identities[name] = backend.link_identity(
                links[name], programs[name], PROGRAMS[name][1]
            )
            result["link_identities"][name] = identities[name]
        while time.monotonic_ns() < configuration["deadline_ns"]:
            snapshot()
            if any(health(name) != "retained" for name in tuple(links)):
                break
            time.sleep(
                min(
                    0.02,
                    max(0, (configuration["deadline_ns"] - time.monotonic_ns()) / 1e9),
                )
            )
        snapshot()
        _role()
        _configuration(configuration)
    except Exception:
        reason("acquisition_error")
        if obj is not None and "maps" in locals():
            snapshot()
    finally:
        # Pop each owning pointer BEFORE destruction, which frees even on error.
        for name in ("recv_entry", "copy_entry", "copy_exit", "recv_exit"):
            if name not in links:
                continue
            owned = links.pop(name)
            try:
                state = health(name)
                if state != "retained":
                    backend.lib.bpf_link__disconnect(owned)
                    if state == "unknown":
                        reason("observer_cleanup_unverified")
                if backend.lib.bpf_link__destroy(owned) != 0:
                    reason("observer_cleanup_unverified")
            except Exception:
                reason("observer_cleanup_unverified")
        if obj is not None and "maps" in locals():
            snapshot()
            try:
                for pending_name in ("recv_pending", "copy_pending"):
                    key = C.c_uint64()
                    C.set_errno(0)
                    rc = backend.lib.bpf_map_get_next_key(
                        backend.lib.bpf_map__fd(maps[pending_name]), None, C.byref(key)
                    )
                    if rc == 0:
                        reason("pending_not_empty")
                    elif rc != -errno.ENOENT:
                        reason("acquisition_error")
            except Exception:
                reason("acquisition_error")
        if obj is not None:
            try:
                backend.lib.bpf_object__close(obj)
            except Exception:
                reason("observer_cleanup_unverified")
    for key, label in (
        ("copy_failure", "copy_failure"),
        ("unsupported", "unsupported_copy"),
        ("read_failure", "read_failure"),
        ("identity_failure", "identity_failure"),
        ("correlation_loss", "correlation_loss"),
        ("overflow", "overflow"),
        ("inflight", "pending_not_empty"),
        ("unmatched_exit", "unmatched_exit"),
        ("recv_inflight", "pending_not_empty"),
        ("unmatched_recv_exit", "unmatched_recv_exit"),
    ):
        if result["counters"] is not None and result["counters"][key]:
            reason(label)
    result["finished_ns"] = time.monotonic_ns()
    return result


def validate_kernel_prototype(raw):
    """Read-actor validation plus exact native wrapper and FD-table type checks."""
    base = _copy_prototype(raw)
    rows = json.loads(raw)[
        "types"
    ]  # Shared validator already rejects duplicate keys/IDs.
    types = {r["id"]: r for r in rows}

    def get(key):
        _need(type(key) is int and key in types, "missing BTF reference")
        return types[key]

    def resolve(key):
        seen = set()
        for _ in range(16):
            _need(key not in seen, "cyclic wrapper BTF")
            seen.add(key)
            row = get(key)
            if row["kind"] not in ("TYPEDEF", "CONST", "VOLATILE", "RESTRICT"):
                return row
            key = row.get("type_id")
        raise NaturalCloseRecvBPFError("wrapper BTF depth")

    def unique(kind, name):
        found = [r for r in rows if r["kind"] == kind and r.get("name") == name]
        _need(len(found) == 1, "unique wrapper BTF symbol: " + name)
        return found[0]

    def integer(key, size, encoding):
        row = resolve(key)
        _need(
            row["kind"] == "INT"
            and type(row.get("size")) is int
            and row["size"] == size
            and type(row.get("nr_bits")) is int
            and row["nr_bits"] == size * 8
            and type(row.get("bits_offset")) is int
            and row["bits_offset"] == 0
            and row.get("encoding") == encoding,
            "wrapper fixed integer",
        )
        return row

    def member(row, name):
        _need(row["kind"] in ("STRUCT", "UNION"), "wrapper aggregate")
        found = [m for m in row.get("members", []) if m.get("name") == name]
        _need(len(found) == 1, "unique wrapper member: " + name)
        m = found[0]
        _need(
            type(m.get("bits_offset")) is int
            and m["bits_offset"] >= 0
            and m["bits_offset"] % 8 == 0
            and m["bits_offset"] < row["size"] * 8
            and not m.get("bitfield_size"),
            "wrapper member offset",
        )
        get(m["type_id"])
        return m

    def ptr(key, target=None):
        row = resolve(key)
        _need(row["kind"] == "PTR", "wrapper pointer")
        value = resolve(row["type_id"])
        _need(target is None or value["id"] == target["id"], "wrapper pointer target")
        return value

    wrapper = unique("FUNC", "__arm64_sys_recvfrom")
    proto = get(wrapper["type_id"])
    _need(
        proto["kind"] == "FUNC_PROTO"
        and type(proto.get("vlen")) is int
        and proto["vlen"] == 1
        and len(proto.get("params", [])) == 1
        and proto["params"][0].get("name") == "regs",
        "native recvfrom signature",
    )
    returned = integer(proto["ret_type_id"], 8, "SIGNED")
    _need(returned.get("name") == "long int", "native recvfrom signed long")
    registers = unique("STRUCT", "pt_regs")
    parameter = get(proto["params"][0]["type_id"])
    _need(parameter["kind"] == "PTR", "native regs pointer")
    const = get(parameter["type_id"])
    _need(
        const["kind"] == "CONST" and const["type_id"] == registers["id"],
        "native const pt_regs",
    )

    def shape(row, kind, size, fields):
        _need(
            row["kind"] == kind
            and type(row.get("size")) is int
            and row["size"] == size
            and type(row.get("vlen")) is int
            and row["vlen"] == len(fields)
            and [(m.get("name"), m.get("bits_offset")) for m in row.get("members", [])]
            == fields,
            "frozen native aggregate shape",
        )
        for name, _ in fields:
            member(row, name)

    def scalar(row, name, size, encoding="(none)"):
        integer(member(row, name)["type_id"], size, encoding)

    if registers.get("size") == 336:
        shape(
            registers,
            "STRUCT",
            336,
            [
                ("(anon)", 0),
                ("orig_x0", 2176),
                ("syscallno", 2240),
                ("unused2", 2272),
                ("sdei_ttbr1", 2304),
                ("pmr_save", 2368),
                ("stackframe", 2432),
                ("lockdep_hardirqs", 2560),
                ("exit_rcu", 2624),
            ],
        )
        scalar(registers, "orig_x0", 8)
        scalar(registers, "syscallno", 4, "SIGNED")
        scalar(registers, "unused2", 4)
        for name in ("sdei_ttbr1", "pmr_save", "lockdep_hardirqs", "exit_rcu"):
            scalar(registers, name, 8)
        stack = resolve(member(registers, "stackframe")["type_id"])
        _need(
            stack["kind"] == "ARRAY"
            and type(stack.get("nr_elems")) is int
            and stack["nr_elems"] == 2,
            "native 336 stackframe array",
        )
        integer(stack["type_id"], 8, "(none)")
        recv_profile = "aarch64_const_pt_regs_336_u64_stackframe2_fdtable_56"
    elif registers.get("size") == 320:
        shape(
            registers,
            "STRUCT",
            320,
            [
                ("(anon)", 0),
                ("orig_x0", 2176),
                ("syscallno", 2240),
                ("pmr", 2272),
                ("sdei_ttbr1", 2304),
                ("stackframe", 2368),
            ],
        )
        scalar(registers, "orig_x0", 8)
        scalar(registers, "syscallno", 4, "SIGNED")
        scalar(registers, "pmr", 4)
        scalar(registers, "sdei_ttbr1", 8)
        stack = resolve(member(registers, "stackframe")["type_id"])
        _need(
            stack["id"] == unique("STRUCT", "frame_record_meta")["id"],
            "native 320 stackframe metadata",
        )
        shape(stack, "STRUCT", 24, [("record", 0), ("type", 128)])
        scalar(stack, "type", 8)
        record = resolve(member(stack, "record")["type_id"])
        _need(
            record["id"] == unique("STRUCT", "frame_record")["id"],
            "native frame record type",
        )
        shape(record, "STRUCT", 16, [("fp", 0), ("lr", 64)])
        scalar(record, "fp", 8)
        scalar(record, "lr", 8)
        recv_profile = "aarch64_const_pt_regs_320_frame_record_meta24_fdtable_56"
    else:
        raise NaturalCloseRecvBPFError("unknown native pt_regs profile")
    overlay = resolve(member(registers, "(anon)")["type_id"])
    shape(overlay, "UNION", 272, [("user_regs", 0), ("(anon)", 0)])
    for arm in ("user_regs", "(anon)"):
        nested = resolve(member(overlay, arm)["type_id"])
        if arm == "user_regs":
            _need(
                nested["id"] == unique("STRUCT", "user_pt_regs")["id"],
                "native user register arm",
            )
        shape(
            nested,
            "STRUCT",
            272,
            [("regs", 0), ("sp", 1984), ("pc", 2048), ("pstate", 2112)],
        )
        array = resolve(member(nested, "regs")["type_id"])
        _need(
            array["kind"] == "ARRAY"
            and type(array.get("nr_elems")) is int
            and array["nr_elems"] == 31,
            "native 31 registers",
        )
        integer(array["type_id"], 8, "(none)")
        for name in ("sp", "pc", "pstate"):
            scalar(nested, name, 8)
    task, files, table, file, inode = [
        unique("STRUCT", n)
        for n in ("task_struct", "files_struct", "fdtable", "file", "inode")
    ]
    ptr(member(task, "files")["type_id"], files)
    ptr(member(files, "fdt")["type_id"], table)
    _need(
        table.get("size") == 56
        and [m.get("name") for m in table.get("members", [])]
        == ["max_fds", "fd", "close_on_exec", "open_fds", "full_fds_bits", "rcu"],
        "native fdtable layout",
    )
    _need(
        member(table, "max_fds")["bits_offset"] == 0
        and member(table, "fd")["bits_offset"] == 64,
        "native fdtable offsets",
    )
    integer(member(table, "max_fds")["type_id"], 4, "(none)")
    ptr(ptr(member(table, "fd")["type_id"])["id"], file)
    ptr(member(file, "f_inode")["type_id"], inode)
    private = resolve(member(file, "private_data")["type_id"])
    _need(
        private["kind"] == "PTR" and private["type_id"] == 0,
        "socket private void pointer",
    )
    integer(member(inode, "i_mode")["type_id"], 2, "(none)")
    integer(member(inode, "i_ino")["type_id"], 8, "(none)")
    return base | {
        "recv_function_id": wrapper["id"],
        "recvfrom_profile": recv_profile,
    }
