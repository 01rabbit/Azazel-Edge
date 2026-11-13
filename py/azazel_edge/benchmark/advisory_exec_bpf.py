"""Fixed ARM syscall-entry observer; own-map writes, no target mutation."""

import ctypes as C
import errno
import hashlib
import os
from pathlib import Path
import platform
import re
import stat
import struct
import time

from .udp_queue_bpf import _Libbpf as _Base, _role as _base_role
from .protected_ingress import _proc_bytes
from .safety_observations import _fields, _int


class AdvisoryExecBPFError(ValueError):
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


class Calibration(C.Structure):
    _fields_ = [(k, C.c_uint64) for k in ("calibrated_at_ns", "start_boottime_ns")] + [
        (k, C.c_uint32) for k in ("tgid", "tid", "uid", "native_abi")
    ]


class Event(C.Structure):
    _fields_ = [
        (k, C.c_uint64) for k in ("monotonic_ns", "start_boottime_ns", "syscall_id")
    ] + [
        (k, C.c_uint32)
        for k in ("tgid", "tid", "uid", "event_kind", "native_abi", "reserved")
    ]


class Counters(C.Structure):
    _fields_ = [
        (k, C.c_uint64)
        for k in (
            "observed",
            "emitted",
            "overflow",
            "identity_failure",
            "abi_rejected",
            "uncalibrated",
            "creation_attempts",
            "calibration_conflict",
        )
    ]


assert tuple(map(C.sizeof, (Configuration, Calibration, Event, Counters))) == (
    56,
    32,
    48,
    64,
)
MAPS = {
    "config": (2, 4, 56, 1),
    "state": (2, 4, 32, 1),
    "events": (2, 4, 48, 64),
    "stats": (2, 4, 64, 1),
}
SOURCE = Path(__file__).resolve().parents[3] / "native" / "advisory_exec_observer.bpf.c"


def _need(ok, why):
    if not ok:
        raise AdvisoryExecBPFError(why)


def _role():
    _need(platform.machine() == "aarch64", "only native64 AArch64 supported")
    _base_role()


def _configuration(value):
    _fields(value, " ".join(name for name, _ in Configuration._fields_))
    for name, ctype in Configuration._fields_:
        _int(value[name], 1, 2 ** (C.sizeof(ctype) * 8) - 1)
    _need(
        value["actor_uid"] != 0
        and value["actor_tgid"] > 1
        and value["user_hz"] == 100
        and value["max_events"] <= 64
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
    return {name: getattr(value, name) for name, _ in value._fields_}


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
            _need(name == "advisory_enter" and not programs, "unexpected program")
            _need(
                self.lib.bpf_program__section_name(item) == b"raw_tp/sys_enter"
                and self.lib.bpf_program__type(item) == 17
                and self.lib.bpf_program__expected_attach_type(item) == 0,
                "fixed raw tracepoint required",
            )
            programs[name] = item
        _need(set(maps) == set(MAPS) and len(programs) == 1, "missing map/program")
        return maps, programs["advisory_enter"]

    def _raw_fields(self, fd):
        raw = self._object_info(fd)
        kind, link_id, prog_id = struct.unpack_from("=3I", raw)
        fields = {}
        wanted = {"link_type", "link_id", "prog_id", "prog_tag", "tp_name"}
        try:
            lines = (
                _proc_bytes(f"/proc/self/fdinfo/{fd}", 8192)
                .decode("ascii")
                .splitlines()
            )
        except OSError as exc:
            # A proc read failure is not the cached FD's kernel query result.
            raise AdvisoryExecBPFError("raw link fdinfo unavailable") from exc
        for line in lines:
            key, sep, value = line.partition(":")
            if sep and key in wanted:
                _need(key not in fields, "duplicate link identity")
                fields[key] = value.strip()
        _need(
            set(fields) == wanted
            and fields["link_type"] == "raw_tracepoint"
            and fields["tp_name"] == "sys_enter",
            "raw link fdinfo differs",
        )
        _need(
            kind == 1
            and link_id > 0
            and prog_id > 0
            and fields["link_id"] == str(link_id)
            and fields["prog_id"] == str(prog_id)
            and re.fullmatch("[0-9a-f]{16}", fields["prog_tag"]),
            "raw link identity differs",
        )
        return dict(
            fd=fd,
            link_type=kind,
            link_id=link_id,
            prog_id=prog_id,
            tp_name="sys_enter",
            prog_tag=fields["prog_tag"],
        )

    def link_identity(self, link, program):
        identity = self._raw_fields(self.lib.bpf_link__fd(link))
        program_fd = self.lib.bpf_program__fd(program)
        _need(program_fd >= 0, "owned program FD unavailable")
        raw = self._object_info(program_fd)
        kind, prog_id = struct.unpack_from("=2I", raw)
        _need(
            kind == 17
            and prog_id == identity["prog_id"]
            and raw[8:16].hex() == identity["prog_tag"],
            "program/link differ",
        )
        return identity

    def check_link(self, identity):
        try:
            current = self._raw_fields(identity["fd"])
            if current == identity:
                return "retained"
            return (
                "lost"
                if any(current[k] != identity[k] for k in ("link_type", "link_id"))
                else "unknown"
            )
        except OSError as exc:
            if exc.errno in (errno.EBADF, getattr(errno, "EBADFD", 77)):
                return "lost"
            if exc.errno == errno.EINVAL:
                try:
                    raw = _proc_bytes(f"/proc/self/fdinfo/{identity['fd']}", 8192)
                    if b"raw_tracepoint" not in raw and self._foreign_fd(
                        identity["fd"]
                    ):
                        return "lost"
                except Exception:
                    pass
            return "unknown"
        except Exception:
            return "unknown"


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
        schema_version="edge-advisory-exec-probe/v1",
        architecture="aarch64",
        started_ns=configuration["started_ns"],
        finished_ns=None,
        configuration=dict(configuration),
        calibration=None,
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
            state = backend.lookup(
                backend.lib.bpf_map__fd(maps["state"]), zero, Calibration()
            )
            if state.calibrated_at_ns:
                result["calibration"] = _dict(state)
        except Exception:
            reason("acquisition_error")
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
                if value.monotonic_ns:
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
        link = backend.pointer(backend.lib.bpf_program__attach(program), "raw attach")
        identity = backend.link_identity(link, program)
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
    if result["calibration"] is None:
        reason("uncalibrated")
    for key, label in (
        ("overflow", "overflow"),
        ("identity_failure", "identity_failure"),
        ("abi_rejected", "abi_rejected"),
        ("uncalibrated", "uncalibrated"),
        ("creation_attempts", "creation_attempt"),
        ("calibration_conflict", "calibration_conflict"),
    ):
        if result["counters"] is not None and result["counters"][key]:
            reason(label)
    result["finished_ns"] = time.monotonic_ns()
    return result
