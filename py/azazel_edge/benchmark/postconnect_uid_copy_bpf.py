"""Fixed UID65534 development-profile copies; not internal authorization proof."""

import ctypes as C
import errno
import hashlib
import os
from pathlib import Path
import time

from .authority_ingress_bpf import _Libbpf as _Tracing, _role
from .postconnect_copy_bpf import validate_kernel_prototype  # noqa: F401
from .protected_ingress import _proc_bytes
from .safety_observations import _fields, _int


class PostconnectUIDCopyBPFError(ValueError):
    pass


def _need(ok, reason):
    if not ok:
        raise PostconnectUIDCopyBPFError(reason)


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
                "entered_ns",
                "exited_ns",
                "start_ns",
                "receiver_inode",
                "peer_inode",
                "endpoint_inode",
            )
        ]
        + [
            (k, C.c_uint32)
            for k in (
                "role",
                "tgid",
                "tid",
                "uid",
                "euid",
                "netns_inode",
                "endpoint_major",
                "endpoint_minor",
                "flags",
                "iter_type",
                "data_source",
                "skip",
                "chunk",
                "consumed",
                "skb_len",
                "data_len",
            )
        ]
        + [("ret", C.c_int32), ("reserved", C.c_uint32), ("data", C.c_ubyte * 256)]
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
        )
    ]


assert tuple(map(C.sizeof, (Configuration, Event, Counters))) == (72, 376, 96)
MAPS = {
    "config": (2, 4, 72, 1),
    "pending": (1, 8, 376, 2),
    "events": (1, 4, 376, 16),
    "zero_template": (2, 4, 376, 1),
    "stats": (2, 4, 96, 1),
}
MAP_FLAGS = {name: (128 if name == "zero_template" else 0) for name in MAPS}
PROGRAMS = {
    "copy_entry": (b"fentry/unix_stream_read_actor", 24),
    "copy_exit": (b"fexit/unix_stream_read_actor", 25),
}
SOURCE = (
    Path(__file__).resolve().parents[3] / "native/postconnect_uid_copy_observer.bpf.c"
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
        and value["max_events"] <= 16
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
    return {
        name: getattr(value, name) for name, _ in value._fields_ if name != "data"
    } | (
        {"data_hex": bytes(value.data[: value.chunk]).hex()}
        if isinstance(value, Event)
        else {}
    )


class _Libbpf(_Tracing):
    def lookup_optional(self, fd, key, value):
        C.set_errno(0)
        rc = self.lib.bpf_map_lookup_elem(fd, C.byref(key), C.byref(value))
        if rc == 0:
            return value
        if rc == -errno.ENOENT:
            return None
        raise PostconnectUIDCopyBPFError("event lookup failed")

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
        schema_version="edge-postconnect-uid-copy-probe/v1",
        architecture="aarch64",
        started_ns=configuration["started_ns"],
        finished_ns=None,
        configuration=configuration.copy(),
        events=[],
        counters=None,
        partial_reasons=[],
        link_identities={"entry": None, "exit": None},
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
        for index in range(16):
            if index in slots:
                continue
            try:
                event = backend.lookup_optional(
                    backend.lib.bpf_map__fd(maps["events"]), C.c_uint32(index), Event()
                )
                if event is not None and event.entered_ns and event.exited_ns:
                    _need(1 <= event.chunk <= 256, "event bound differs")
                    result["events"].append(_dict(event))
                    slots.add(index)
            except Exception:
                reason("acquisition_error")

    def health(name):
        identity = identities.get(name)
        state = backend.check_link(identity) if identity is not None else "unknown"
        if state != "retained":
            reason("observer_link_lost")
            result["link_identities"][name.removeprefix("copy_")] = None
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
        for name in ("copy_exit", "copy_entry"):
            links[name] = backend.pointer(
                backend.lib.bpf_program__attach(programs[name]), "copy attach"
            )
            identities[name] = backend.link_identity(
                links[name], programs[name], PROGRAMS[name][1]
            )
            result["link_identities"][name.removeprefix("copy_")] = identities[name]
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
        for name in ("copy_entry", "copy_exit"):
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
                key = C.c_uint64()
                C.set_errno(0)
                rc = backend.lib.bpf_map_get_next_key(
                    backend.lib.bpf_map__fd(maps["pending"]), None, C.byref(key)
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
    ):
        if result["counters"] is not None and result["counters"][key]:
            reason(label)
    result["finished_ns"] = time.monotonic_ns()
    return result
