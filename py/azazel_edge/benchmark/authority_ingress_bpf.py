"""Fixed ARM AF_UNIX connect-return observer; own-map writes, no target mutation."""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import time

from .udp_queue_bpf import _Libbpf as _Base, _role as _base_role
from .protected_ingress import _proc_bytes
from .safety_observations import _fields, _int


class AuthorityIngressBPFError(ValueError):
    pass


class Configuration(C.Structure):
    _fields_ = [
        (k, C.c_uint64)
        for k in (
            "pidns_device",
            "pidns_inode",
            "actor_start_ticks",
            "started_ns",
            "deadline_ns",
        )
    ] + [(k, C.c_uint32) for k in ("actor_tgid", "actor_uid", "user_hz", "max_events")]


class Event(C.Structure):
    _fields_ = (
        [(k, C.c_uint64) for k in ("at_ns", "start_ns", "client_inode", "peer_inode")]
        + [
            (k, C.c_uint32)
            for k in ("tgid", "tid", "uid", "peer_major", "peer_minor", "netns_inode")
        ]
        + [
            ("ret", C.c_int32),
            ("addr_len", C.c_int32),
            ("path", C.c_char * 108),
            ("reserved", C.c_uint32),
        ]
    )


class Counters(C.Structure):
    _fields_ = [
        (k, C.c_uint64)
        for k in ("observed", "emitted", "overflow", "identity_failure", "read_failure")
    ]


assert tuple(map(C.sizeof, (Configuration, Event, Counters))) == (56, 176, 40)
MAPS = {"config": (2, 4, 56, 1), "events": (2, 4, 176, 16), "stats": (2, 4, 40, 1)}
SOURCE = (
    Path(__file__).resolve().parents[3] / "native" / "authority_ingress_observer.bpf.c"
)


def _need(ok, why):
    if not ok:
        raise AuthorityIngressBPFError(why)


def _role():
    _need(platform.machine() == "aarch64", "only native64 AArch64 supported")
    _base_role()


def _configuration(value):
    _fields(value, " ".join(name for name, _ in Configuration._fields_))
    for name, ctype in Configuration._fields_:
        _int(
            value[name], 0 if name == "actor_uid" else 1, 2 ** (C.sizeof(ctype) * 8) - 1
        )
    _need(
        value["actor_tgid"] > 1
        and value["user_hz"] == 100
        and value["max_events"] <= 16
        and 0 < value["deadline_ns"] - value["started_ns"] <= 5_000_000_000,
        "fixed bounded actor configuration required",
    )
    namespace = os.stat("/proc/self/ns/pid")
    _need(
        (namespace.st_dev, namespace.st_ino)
        == (value["pidns_device"], value["pidns_inode"]),
        "observer PID namespace differs",
    )
    _need(
        _proc_bytes("/proc/self/timens_offsets", 4096).split()
        == [b"monotonic", b"0", b"0", b"boottime", b"0", b"0"],
        "zero time namespace required",
    )
    return Configuration(**value)


def _source_hash(expected):
    _need(
        type(expected) is str and re.fullmatch("[0-9a-f]{64}", expected),
        "source pin required",
    )
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        _need(
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 32768,
            "fixed source bounds",
        )
        raw = os.read(fd, 32769)
        after = os.fstat(fd)
        _need(
            len(raw) == info.st_size
            and (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            and hashlib.sha256(raw).hexdigest() == expected,
            "fixed source pin differs",
        )
    finally:
        os.close(fd)


def _dict(value):
    return {
        name: (
            bytes(getattr(value, name)).decode("ascii")
            if name == "path"
            else getattr(value, name)
        )
        for name, _ in value._fields_
    }


class _Libbpf(_Base):
    def inspect(self, obj):
        maps, programs = {}, {}
        previous = None
        while item := self.lib.bpf_object__next_map(obj, previous):
            previous = item
            name = self.lib.bpf_map__name(item).decode("ascii")
            _need(name in MAPS and name not in maps, "unexpected map")
            actual = tuple(
                getattr(self.lib, "bpf_map__" + key)(item)
                for key in ("type", "key_size", "value_size", "max_entries")
            )
            _need(
                actual == MAPS[name] and self.lib.bpf_map__map_flags(item) == 0,
                "map ABI differs",
            )
            maps[name] = item
        previous = None
        while item := self.lib.bpf_object__next_program(obj, previous):
            previous = item
            name = self.lib.bpf_program__name(item).decode("ascii")
            _need(name == "authority_exit" and not programs, "unexpected program")
            _need(
                self.lib.bpf_program__section_name(item) == b"fexit/unix_stream_connect"
                and self.lib.bpf_program__type(item) == 26
                and self.lib.bpf_program__expected_attach_type(item) == 25,
                "fixed connect-return hook required",
            )
            programs[name] = item
        _need(set(maps) == set(MAPS) and len(programs) == 1, "missing map/program")
        return maps, programs["authority_exit"]


def _capture_events(
    configuration, object_raw, *, expected_object_sha256, expected_source_sha256
):
    """Snapshot known rows before cleanup; partial ownership never means absence."""
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
        "capture deadline unavailable",
    )
    result = dict(
        schema_version="edge-authority-ingress-probe/v1",
        architecture="aarch64",
        started_ns=configuration["started_ns"],
        finished_ns=None,
        configuration=dict(configuration),
        events=[],
        counters=None,
        partial_reasons=[],
        link_identity=None,
    )
    backend = _Libbpf()
    obj = link = identity = None
    health = "unknown"
    retained_slots = set()

    def reason(value):
        if value not in result["partial_reasons"]:
            result["partial_reasons"].append(value)

    def snapshot(maps):
        zero = C.c_uint32()
        try:
            counters = backend.lookup(
                backend.lib.bpf_map__fd(maps["stats"]), zero, Counters()
            )
            result["counters"] = _dict(counters)
        except Exception:
            reason("acquisition_error")
        # Each slot is written once. Never replace an already retained raw row.
        for index in range(configuration["max_events"]):
            if index in retained_slots:
                continue
            try:
                value = backend.lookup(
                    backend.lib.bpf_map__fd(maps["events"]), C.c_uint32(index), Event()
                )
                row = _dict(value)
                if value.at_ns:
                    result["events"].append(row)
                    retained_slots.add(index)
            except Exception:
                reason("acquisition_error")

    try:
        buffer = C.create_string_buffer(object_raw)
        obj = backend.pointer(
            backend.lib.bpf_object__open_mem(buffer, len(object_raw), None),
            "object open",
        )
        maps, program = backend.inspect(obj)
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
        link = backend.pointer(
            backend.lib.bpf_program__attach(program), "connect-return attach"
        )
        identity = backend.link_identity(link, program, 25)
        result["link_identity"] = identity
        while time.monotonic_ns() < configuration["deadline_ns"]:
            health = backend.check_link(identity)
            if health != "retained":
                reason("observer_link_lost")
                result["link_identity"] = None
                break
            time.sleep(
                min(
                    0.02,
                    max(0, (configuration["deadline_ns"] - time.monotonic_ns()) / 1e9),
                )
            )
        health = backend.check_link(identity)
        if health != "retained":
            reason("observer_link_lost")
            result["link_identity"] = None
        snapshot(maps)
        _role()
        _configuration(configuration)
    except Exception:
        reason("acquisition_error")
        if obj is not None and "maps" in locals():
            snapshot(maps)
    finally:
        if link is not None:
            owned, link = link, None
            try:
                if identity is not None:
                    health = backend.check_link(identity)
                    if health != "retained":
                        reason("observer_link_lost")
                        result["link_identity"] = None
                if health != "retained":
                    backend.lib.bpf_link__disconnect(owned)
                    if health == "unknown":
                        reason("observer_cleanup_unverified")
                if backend.lib.bpf_link__destroy(owned) != 0:
                    reason("observer_cleanup_unverified")
            except Exception:
                reason("observer_cleanup_unverified")
        if obj is not None:
            try:
                backend.lib.bpf_object__close(obj)
            except Exception:
                reason("observer_cleanup_unverified")
    for key, label in (
        ("overflow", "overflow"),
        ("identity_failure", "identity_failure"),
        ("read_failure", "read_failure"),
    ):
        if result["counters"] is not None and result["counters"][key]:
            reason(label)
    result["finished_ns"] = time.monotonic_ns()
    return result


def validate_kernel_prototype(raw):
    """Pure fixed build-time check of Root-obtained bpftool JSON, not attestation."""

    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "duplicate BTF JSON key")
            result[key] = value
        return result

    def invalid(value):
        raise AuthorityIngressBPFError("nonfinite BTF JSON")

    try:
        _need(type(raw) is bytes and 0 < len(raw) <= 32 * 1024 * 1024, "BTF JSON bound")
        value = json.loads(
            raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=invalid
        )
        _fields(value, "types")
        rows = value["types"]
        _need(type(rows) is list and 0 < len(rows) <= 250000, "BTF row bound")
        types = {}
        for row in rows:
            _need(type(row) is dict, "BTF type object")
            key = row.get("id")
            _need(
                type(key) is int
                and 0 < key < 2**32
                and key not in types
                and type(row.get("kind")) is str,
                "BTF unique typed ID",
            )
            types[key] = row

        def get(key):
            _need(type(key) is int and key in types, "referenced BTF type unavailable")
            return types[key]

        def resolve(key):
            seen = set()
            for _ in range(16):
                _need(key not in seen, "cyclic BTF wrapper")
                seen.add(key)
                row = get(key)
                if row["kind"] not in ("TYPEDEF", "CONST", "VOLATILE", "RESTRICT"):
                    return row
                key = row.get("type_id")
            raise AuthorityIngressBPFError("BTF wrapper depth")

        def integer(key):
            row = resolve(key)
            _need(
                row["kind"] == "INT"
                and row.get("name") == "int"
                and type(row.get("size")) is int
                and row["size"] == 4
                and type(row.get("nr_bits")) is int
                and row["nr_bits"] == 32
                and type(row.get("bits_offset")) is int
                and row["bits_offset"] == 0
                and row.get("encoding") == "SIGNED",
                "signed32 int prototype required",
            )

        def pointer(key, name):
            row = resolve(key)
            _need(row["kind"] == "PTR", "prototype pointer required")
            target = resolve(row.get("type_id"))
            _need(
                target["kind"] == "STRUCT" and target.get("name") == name,
                "prototype pointee differs",
            )

        found = [
            row
            for row in rows
            if row["kind"] == "FUNC" and row.get("name") == "unix_stream_connect"
        ]
        _need(len(found) == 1, "unique unix_stream_connect function required")
        function = found[0]
        proto = get(function.get("type_id"))
        _need(
            proto["kind"] == "FUNC_PROTO"
            and type(proto.get("params")) is list
            and type(proto.get("vlen")) is int
            and proto["vlen"] == 4
            and len(proto["params"]) == 4,
            "exact four-argument prototype required",
        )
        params = proto["params"]
        _need(
            all(type(row) is dict for row in params)
            and [row.get("name") for row in params]
            == ["sock", "uaddr", "addr_len", "flags"],
            "fixed ordered parameter bindings required",
        )
        integer(proto.get("ret_type_id"))
        pointer(params[0].get("type_id"), "socket")
        pointer(params[1].get("type_id"), "sockaddr")
        integer(params[2].get("type_id"))
        integer(params[3].get("type_id"))
        return dict(
            function="unix_stream_connect",
            function_id=function["id"],
            prototype_id=proto["id"],
            arguments=4,
            btf_sha256=hashlib.sha256(raw).hexdigest(),
        )
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        if isinstance(exc, AuthorityIngressBPFError):
            raise
        raise AuthorityIngressBPFError("invalid fixed kernel prototype") from exc
