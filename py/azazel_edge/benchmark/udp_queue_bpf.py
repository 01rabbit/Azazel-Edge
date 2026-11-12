"""Fixed libbpf provider: read-only target tracing; writes owned BPF maps only."""

import ctypes as C
import errno
import os
import re
import socket
import struct
import sys
import time

from .safety_observations import _fields, _hex, _int
from .protected_ingress import _proc_bytes


class UDPQueueBPFError(ValueError):
    """Unavailable, unsafe or incompletely closed observer; never a zero result."""


class Configuration(C.Structure):
    _fields_ = (
        [
            (name, C.c_uint64)
            for name in (
                "socket_inode",
                "socket_cookie",
                "netns_cookie",
                "netns_inode",
                "started_ns",
                "deadline_ns",
            )
        ]
        + [(name, C.c_uint32) for name in ("socket_uid", "src_ip", "dst_ip")]
        + [(name, C.c_uint16) for name in ("src_port", "dst_port")]
        + [
            ("max_events", C.c_uint32),
            ("reserved", C.c_uint32),
            ("payload", C.c_ubyte * 64),
        ]
    )


class Event(C.Structure):
    _fields_ = (
        [
            (name, C.c_uint64)
            for name in (
                "entered_ns",
                "exited_ns",
                "socket_inode",
                "socket_cookie",
                "netns_cookie",
                "netns_inode",
            )
        ]
        + [(name, C.c_uint32) for name in ("socket_uid", "src_ip", "dst_ip")]
        + [(name, C.c_uint16) for name in ("src_port", "dst_port")]
        + [("payload", C.c_ubyte * 64)]
    )


class Invocation(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ("sk", "skb", "pid_tgid")] + [
        ("cpu", C.c_uint32),
        ("reserved", C.c_uint32),
    ]


class Counters(C.Structure):
    _fields_ = [
        (name, C.c_uint64)
        for name in (
            "entry_matches",
            "accepted",
            "rejected",
            "correlation_loss",
            "overflow",
        )
    ]


assert (
    C.sizeof(Configuration),
    C.sizeof(Event),
    C.sizeof(Invocation),
    C.sizeof(Counters),
) == (136, 128, 32, 40)
_MAPS = {
    "config": (2, 4, 136, 1),
    "pending": (1, 32, 128, 64),
    "events": (2, 4, 128, 16),
    "stats": (2, 4, 40, 1),
}
_PROGRAMS = {
    "queue_entry": ("fentry/__udp_enqueue_schedule_skb", 26, 24),
    "queue_exit": ("fexit/__udp_enqueue_schedule_skb", 26, 25),
}


def _need(condition, message):
    if not condition:
        raise UDPQueueBPFError(message)


def _role():
    _need(
        sys.platform == "linux" and sys.byteorder == "little" and os.geteuid() == 0,
        "Linux little-endian Root observer required",
    )
    wanted = {"Uid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
    fields = {}
    for line in _proc_bytes("/proc/self/status", 65536).decode("ascii").splitlines():
        key, sep, value = line.partition(":")
        if sep and key in wanted:
            _need(key not in fields, "duplicate capability field")
            fields[key] = value.strip()
    _need(
        set(fields) == wanted
        and fields["Uid"].split() == ["0"] * 4
        and fields["NoNewPrivs"] == "1",
        "Root/NNP role differs",
    )
    for key in ("CapEff", "CapPrm", "CapBnd"):
        _need(
            int(fields[key], 16) == (1 << 38) | (1 << 39), "BPF+PERFMON only required"
        )
    _need(
        int(fields["CapInh"], 16) == int(fields["CapAmb"], 16) == 0,
        "inheritable/ambient capabilities forbidden",
    )


def _configuration(value):
    _fields(
        value,
        "socket_inode socket_cookie netns_cookie netns_inode socket_uid src_ip dst_ip src_port dst_port payload_hex started_ns deadline_ns max_events",
    )
    for key in ("socket_inode", "socket_cookie", "netns_cookie", "netns_inode"):
        _int(value[key], 1, 2**64 - 1)
    _int(value["socket_uid"], 1, 2**32 - 1)
    _need(value["src_ip"] == value["dst_ip"] == "127.0.0.1", "fixed loopback only")
    for key in ("src_port", "dst_port"):
        _int(value[key], 1, 65535)
    _hex(value["payload_hex"], 128)
    _int(value["started_ns"])
    _int(value["deadline_ns"])
    _need(
        0 < value["deadline_ns"] - value["started_ns"] <= 5_000_000_000,
        "absolute bounded deadline required",
    )
    _int(value["max_events"], 1, 16)
    result = Configuration()
    for key in (
        "socket_inode",
        "socket_cookie",
        "netns_cookie",
        "netns_inode",
        "socket_uid",
        "src_port",
        "dst_port",
        "started_ns",
        "deadline_ns",
        "max_events",
    ):
        setattr(result, key, value[key])
    for key in ("src_ip", "dst_ip"):
        setattr(result, key, struct.unpack("=I", socket.inet_aton(value[key]))[0])
    result.payload[:] = bytes.fromhex(value["payload_hex"])
    return result


class _Libbpf:
    def __init__(self):
        self.lib = C.CDLL("libbpf.so.1", use_errno=True)
        ptr = C.c_void_p
        integer = C.c_int
        u32 = C.c_uint32
        prototypes = {
            "libbpf_get_error": ([ptr], C.c_long),
            "bpf_object__open_mem": ([ptr, C.c_size_t, ptr], ptr),
            "bpf_object__close": ([ptr], None),
            "bpf_object__load": ([ptr], integer),
            "bpf_object__next_program": ([ptr, ptr], ptr),
            "bpf_program__name": ([ptr], C.c_char_p),
            "bpf_program__section_name": ([ptr], C.c_char_p),
            "bpf_program__type": ([ptr], integer),
            "bpf_program__expected_attach_type": ([ptr], integer),
            "bpf_program__attach": ([ptr], ptr),
            "bpf_link__destroy": ([ptr], integer),
            "bpf_link__disconnect": ([ptr], None),
            "bpf_link__fd": ([ptr], integer),
            "bpf_program__fd": ([ptr], integer),
            "bpf_obj_get_info_by_fd": ([integer, ptr, ptr], integer),
            "bpf_object__next_map": ([ptr, ptr], ptr),
            "bpf_map__name": ([ptr], C.c_char_p),
            "bpf_map__type": ([ptr], integer),
            "bpf_map__key_size": ([ptr], u32),
            "bpf_map__value_size": ([ptr], u32),
            "bpf_map__max_entries": ([ptr], u32),
            "bpf_map__map_flags": ([ptr], u32),
            "bpf_map__fd": ([ptr], integer),
            "bpf_map_update_elem": ([integer, ptr, ptr, C.c_uint64], integer),
            "bpf_map_lookup_elem": ([integer, ptr, ptr], integer),
            "bpf_map_get_next_key": ([integer, ptr, ptr], integer),
        }
        for name, (arguments, result) in prototypes.items():
            method = getattr(self.lib, name)
            method.argtypes = arguments
            method.restype = result

    def pointer(self, value, stage):
        _need(bool(value) and self.lib.libbpf_get_error(value) == 0, stage + " failed")
        return value

    def inspect(self, obj):
        maps = {}
        programs = {}
        previous = None
        while True:
            item = self.lib.bpf_object__next_map(obj, previous)
            if not item:
                break
            previous = item
            name = self.lib.bpf_map__name(item).decode("ascii")
            _need(name in _MAPS and name not in maps, "unexpected/duplicate map")
            actual = tuple(
                getattr(self.lib, "bpf_map__" + field)(item)
                for field in ("type", "key_size", "value_size", "max_entries")
            )
            _need(
                actual == _MAPS[name] and self.lib.bpf_map__map_flags(item) == 0,
                "map ABI differs",
            )
            maps[name] = item
        previous = None
        while True:
            item = self.lib.bpf_object__next_program(obj, previous)
            if not item:
                break
            previous = item
            name = self.lib.bpf_program__name(item).decode("ascii")
            _need(
                name in _PROGRAMS and name not in programs,
                "unexpected/duplicate program",
            )
            actual = (
                self.lib.bpf_program__section_name(item).decode("ascii"),
                self.lib.bpf_program__type(item),
                self.lib.bpf_program__expected_attach_type(item),
            )
            _need(actual == _PROGRAMS[name], "program type/attachment differs")
            programs[name] = item
        _need(
            set(maps) == set(_MAPS) and set(programs) == set(_PROGRAMS),
            "missing fixed map/program",
        )
        return maps, programs

    def _object_info(self, fd):
        # Query BEFORE any proc open: an EBADF must not be hidden by FD reuse.
        raw = C.create_string_buffer(64)
        length = C.c_uint32(64)
        C.set_errno(0)
        result = self.lib.bpf_obj_get_info_by_fd(fd, raw, C.byref(length))
        if result != 0:
            error = C.get_errno()
            if error in (errno.EBADF, getattr(errno, "EBADFD", 77), errno.EINVAL):
                raise OSError(error, "cached BPF object query failed")
            raise UDPQueueBPFError("BPF object identity unavailable")
        _need(28 <= length.value <= 64, "BPF object identity truncated")
        return raw.raw

    def _link_fields(self, fd):
        _need(type(fd) is int and fd >= 0, "invalid cached link FD")
        raw = self._object_info(fd)
        kind, link_id, program_id, _, attach, target, btf = struct.unpack_from(
            "=7I", raw
        )
        required = {
            "link_type",
            "link_id",
            "prog_id",
            "attach_type",
            "target_obj_id",
            "target_btf_id",
        }
        fields = {}
        try:
            lines = (
                _proc_bytes(f"/proc/self/fdinfo/{fd}", 8192)
                .decode("ascii")
                .splitlines()
            )
        except OSError as exc:
            # A proc read's EBADF/EBADFD is not the cached-link syscall result.
            raise UDPQueueBPFError("link fdinfo unavailable") from exc
        for line in lines:
            key, separator, value = line.partition(":")
            if separator and key in required:
                _need(key not in fields, "duplicate link fdinfo field")
                fields[key] = value.strip()
        if "link_type" not in fields or fields["link_type"] != "tracing":
            raise OSError(errno.EINVAL, "cached FD is a foreign object")
        _need(set(fields) == required, "link fdinfo incomplete")
        for name, value in fields.items():
            if name != "link_type":
                _need(
                    value.isascii() and value.isdecimal() and str(int(value)) == value,
                    "invalid link fdinfo integer",
                )
        expected = {
            "link_id": link_id,
            "prog_id": program_id,
            "attach_type": attach,
            "target_obj_id": target,
            "target_btf_id": btf,
        }
        _need(
            all(int(fields[key]) == value for key, value in expected.items()),
            "link fdinfo/kernel identity differs",
        )
        return dict(fd=fd, type=kind, **expected)

    def link_identity(self, link, program, expected_attach):
        # The libbpf pointer remains owned; its FD is acquired exactly ONCE.
        fd = self.lib.bpf_link__fd(link)
        identity = self._link_fields(fd)
        program_fd = self.lib.bpf_program__fd(program)
        _need(program_fd >= 0, "owned program FD unavailable")
        program_type, program_id = struct.unpack_from(
            "=2I", self._object_info(program_fd)
        )
        _need(
            expected_attach in (24, 25)
            and identity["type"] == 2
            and identity["link_id"] > 0
            and identity["prog_id"] == program_id > 0
            and program_type == 26
            and identity["attach_type"] == expected_attach
            and identity["target_btf_id"] > 0,
            "initial tracing identity differs",
        )
        return identity

    def _foreign_fd(self, fd):
        # EINVAL alone is ambiguous: require actual complete foreign fdinfo.
        try:
            fields = {}
            for line in (
                _proc_bytes(f"/proc/self/fdinfo/{fd}", 8192)
                .decode("ascii")
                .splitlines()
            ):
                key, separator, value = line.partition(":")
                _need(separator and key not in fields, "malformed foreign fdinfo")
                fields[key] = value.strip()
            _need(
                {"pos", "flags", "mnt_id", "ino"} <= set(fields),
                "foreign fdinfo incomplete",
            )
            for key in ("pos", "mnt_id", "ino"):
                value = fields[key]
                _need(
                    value.isascii() and value.isdecimal() and str(int(value)) == value,
                    "foreign fdinfo integer",
                )
            _need(
                int(fields["mnt_id"]) > 0
                and int(fields["ino"]) > 0
                and re.fullmatch(r"[0-7]+", fields["flags"]) is not None,
                "foreign fdinfo basics",
            )
            nontracing = {
                "raw_tracepoint",
                "cgroup",
                "iter",
                "netns",
                "xdp",
                "perf_event",
                "kprobe_multi",
                "struct_ops",
                "netfilter",
                "tcx",
                "uprobe_multi",
                "netkit",
            }
            if fields.get("link_type") in nontracing:
                return True
            tracing_fields = {
                "link_type",
                "link_id",
                "prog_id",
                "attach_type",
                "target_obj_id",
                "target_btf_id",
            }
            return not (set(fields) & tracing_fields)
        except Exception:
            return False

    def check_link(self, identity):
        try:
            current = self._link_fields(identity["fd"])
            if current == identity:
                return "retained"
            if any(current[field] != identity[field] for field in ("type", "link_id")):
                return "lost"
            # Same kernel link object may still be live with changed metadata.
            return "unknown"
        except OSError as exc:
            if exc.errno in (errno.EBADF, getattr(errno, "EBADFD", 77)):
                return "lost"
            if exc.errno == errno.EINVAL and self._foreign_fd(identity["fd"]):
                return "lost"
            return "unknown"
        except Exception:
            return "unknown"

    def lookup(self, fd, key, value):
        _need(
            self.lib.bpf_map_lookup_elem(fd, C.byref(key), C.byref(value)) == 0,
            "own-map lookup failed",
        )
        return value


def _event(value):
    result = {
        name: getattr(value, name)
        for name in (
            "entered_ns",
            "exited_ns",
            "socket_inode",
            "socket_cookie",
            "netns_cookie",
            "netns_inode",
            "socket_uid",
            "src_port",
            "dst_port",
        )
    }
    for name in ("src_ip", "dst_ip"):
        result[name] = socket.inet_ntoa(struct.pack("=I", getattr(value, name)))
    result["payload_hex"] = bytes(value.payload).hex()
    return result


def _link_state(backend, identity):
    if identity is None:
        return "unknown"
    try:
        state = backend.check_link(identity)
        return state if state in ("retained", "lost", "unknown") else "unknown"
    except Exception:
        return "unknown"


def _release_link(backend, link, identity):
    state = _link_state(backend, identity)
    if state != "retained":
        # Pointer is STILL owned; only its cached FD may have been lost/reused.
        # Disconnect skips the stale FD close, destroy frees the pointer once.
        backend.lib.bpf_link__disconnect(link)
    result = backend.lib.bpf_link__destroy(link)
    _need(result == 0, "fixed program detach failed")
    _need(state != "unknown", "link ownership unknown during cleanup")
    return state


def _capture_events(configuration, object_raw):
    """Capture only fixed target-matching events; no target socket API is invoked."""
    backend = None
    obj = None
    links = {}
    identities = {}
    observer_link_lost = False
    failure = None
    result = None
    close_errors = []
    try:
        _need(type(configuration) is dict, "fixed configuration dictionary required")
        configuration = configuration.copy()  # Freeze flat scalar inputs/deadline.
        cfg = _configuration(configuration)
        _need(
            type(object_raw) is bytes
            and 64 <= len(object_raw) <= 2 * 1024 * 1024
            and object_raw[:6] == b"\x7fELF\x02\x01"
            and object_raw[18:20] == b"\xf7\x00",
            "bounded little-endian BPF ELF required",
        )
        _role()
        _need(
            configuration["started_ns"]
            <= time.monotonic_ns()
            < configuration["deadline_ns"],
            "capture outside original deadline",
        )
        backend = _Libbpf()
        raw = C.create_string_buffer(object_raw)
        obj = backend.pointer(
            backend.lib.bpf_object__open_mem(raw, len(object_raw), None),
            "open approved object bytes",
        )
        maps, programs = backend.inspect(obj)
        _need(backend.lib.bpf_object__load(obj) == 0, "BPF load failed")
        fds = {name: backend.lib.bpf_map__fd(value) for name, value in maps.items()}
        _need(all(fd >= 0 for fd in fds.values()), "owned-map FD unavailable")
        zero = C.c_uint32(0)
        _need(
            backend.lib.bpf_map_update_elem(
                fds["config"], C.byref(zero), C.byref(cfg), 0
            )
            == 0,
            "single config write failed",
        )
        for name in ("queue_exit", "queue_entry"):
            _need(
                time.monotonic_ns() < configuration["deadline_ns"],
                "attach exceeded deadline",
            )
            links[name] = backend.pointer(
                backend.lib.bpf_program__attach(programs[name]), "fixed program attach"
            )
            identities[name] = backend.link_identity(
                links[name], programs[name], _PROGRAMS[name][2]
            )
        _need(
            all(
                identities["queue_entry"][field] == identities["queue_exit"][field]
                for field in ("target_obj_id", "target_btf_id")
            ),
            "tracing links target different functions",
        )
        while True:
            if any(
                _link_state(backend, identities[name]) != "retained" for name in links
            ):
                observer_link_lost = True
                break
            remaining = configuration["deadline_ns"] - time.monotonic_ns()
            if remaining <= 0:
                break
            time.sleep(min(remaining / 1_000_000_000, 0.01))
        # Detach entry first, exit second. No final own-map read until BOTH detach.
        for name in ("queue_entry", "queue_exit"):
            # libbpf frees the link even if detach returns an error.
            link = links.pop(name)
            if _release_link(backend, link, identities.get(name)) == "lost":
                observer_link_lost = True
        finished = time.monotonic_ns()
        counters = backend.lookup(fds["stats"], zero, Counters())
        counts = {name: getattr(counters, name) for name, _ in Counters._fields_}
        pending_count = 0
        previous = None
        while True:
            key = Invocation()
            C.set_errno(0)
            code = backend.lib.bpf_map_get_next_key(
                fds["pending"],
                C.byref(previous) if previous is not None else None,
                C.byref(key),
            )
            if code != 0:
                _need(C.get_errno() == errno.ENOENT, "pending-map enumeration failed")
                break
            pending_count += 1
            _need(pending_count <= 64, "pending map exceeded ABI")
            previous = key
        counts["correlation_loss"] += pending_count
        captured = []
        for index in range(min(counts["accepted"], configuration["max_events"])):
            event = backend.lookup(fds["events"], C.c_uint32(index), Event())
            row = _event(event)
            # An empty/partial array slot is loss, never a manufactured positive.
            valid = (
                configuration["started_ns"]
                <= row["entered_ns"]
                <= row["exited_ns"]
                <= configuration["deadline_ns"]
            )
            valid = valid and all(
                row[key] == configuration[key]
                for key in (
                    "socket_inode",
                    "socket_cookie",
                    "netns_cookie",
                    "netns_inode",
                    "socket_uid",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "payload_hex",
                )
            )
            if valid:
                captured.append(row)
            else:
                counts["correlation_loss"] += 1
        reasons = ["observer_link_lost"] if observer_link_lost else ["timeout"]
        if counts["accepted"] >= configuration["max_events"]:
            reasons.append("event_bound")
        if counts["correlation_loss"]:
            reasons.append("correlation_loss")
        if counts["overflow"]:
            reasons.append("event_overflow")
        _role()
        result = dict(
            started_ns=configuration["started_ns"],
            finished_ns=finished,
            events=captured,
            counters=counts,
            partial_reasons=reasons,
        )
    except BaseException as exc:
        failure = exc
    finally:
        if backend is not None:
            for name in ("queue_entry", "queue_exit"):
                if name in links:
                    try:
                        _release_link(backend, links.pop(name), identities.get(name))
                    except BaseException:
                        close_errors.append("link detach")
            if obj is not None:
                try:
                    backend.lib.bpf_object__close(obj)
                except BaseException:
                    close_errors.append("object close")
    if failure is not None or close_errors:
        raise UDPQueueBPFError(
            "fixed queue observer failed"
            + (f": {failure}" if failure else "")
            + ("; " + ",".join(close_errors) if close_errors else "")
        ) from failure
    return result
