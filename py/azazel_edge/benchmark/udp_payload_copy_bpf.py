"""Fixed three-hook socket-bound protocol payload-copy backend; no target APIs.

The old queue backend remains unchanged. Only cached-link ownership primitives
are shared; this module fixes its own program identities and native map ABI.
"""

import ctypes as C
import errno
import socket
import struct
import time
from . import udp_queue_bpf as old
from .safety_observations import _fields, _hex, _int


class UDPPayloadCopyBPFError(ValueError):
    """Unknown acquisition or cleanup, never a manufactured zero observation."""


def _need(condition, message):
    if not condition:
        raise UDPPayloadCopyBPFError(message)


_role = old._role
_link_state = old._link_state
_release_link = old._release_link


class Configuration(C.Structure):
    _fields_ = (
        [
            (x, C.c_uint64)
            for x in "socket_inode socket_cookie netns_cookie netns_inode started_ns deadline_ns pidns_device pidns_inode".split()
        ]
        + [(x, C.c_uint32) for x in "socket_uid src_ip dst_ip".split()]
        + [(x, C.c_uint16) for x in "src_port dst_port".split()]
        + [(x, C.c_uint32) for x in "max_events reserved".split()]
        + [("payload", C.c_ubyte * 64)]
    )


class Event(C.Structure):
    _fields_ = (
        [
            (x, C.c_uint64)
            for x in "entered_ns consumed_ns exited_ns socket_inode socket_cookie netns_cookie netns_inode receiver_start_boottime_ns".split()
        ]
        + [
            (x, C.c_uint32)
            for x in "socket_uid receiver_real_uid receiver_effective_uid receiver_tgid receiver_tid src_ip dst_ip".split()
        ]
        + [(x, C.c_uint16) for x in "src_port dst_port".split()]
        + [("payload", C.c_ubyte * 64)]
    )


class Counters(C.Structure):
    _fields_ = [
        (x, C.c_uint64)
        for x in "entry_matches consume_matches accepted rejected correlation_loss overflow".split()
    ]


class Invocation(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ("pid_tgid", "sk")]


assert (
    C.sizeof(Configuration),
    C.sizeof(Event),
    C.sizeof(Invocation),
    C.sizeof(Counters),
) == (152, 160, 16, 48)
_MAPS = {
    "config": (2, 4, 152, 1),
    "pending": (1, 16, 160, 64),
    "events": (2, 4, 160, 16),
    "stats": (2, 4, 48, 1),
}
_PROGRAMS = {
    "copy_entry": ("fentry/udp_recvmsg", 26, 24),
    "copy_consume": ("fentry/skb_consume_udp", 26, 24),
    "copy_exit": ("fexit/udp_recvmsg", 26, 25),
}


def _configuration(value):
    _fields(
        value,
        "socket_inode socket_cookie netns_cookie netns_inode socket_uid src_ip dst_ip src_port dst_port payload_hex started_ns deadline_ns max_events pidns_device pidns_inode",
    )
    for key in (
        "socket_inode",
        "socket_cookie",
        "netns_cookie",
        "netns_inode",
        "pidns_device",
        "pidns_inode",
    ):
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
        "pidns_device",
        "pidns_inode",
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


class _Libbpf(old._Libbpf):
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


def _event(value):
    result = {
        name: getattr(value, name)
        for name, _ in Event._fields_
        if name not in ("src_ip", "dst_ip", "payload")
    }
    for name in ("src_ip", "dst_ip"):
        result[name] = socket.inet_ntoa(struct.pack("=I", getattr(value, name)))
    result["payload_hex"] = bytes(value.payload).hex()
    return result


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
        for name in ("copy_exit", "copy_consume", "copy_entry"):
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
                identities["copy_entry"][field] == identities["copy_exit"][field]
                for field in ("target_obj_id", "target_btf_id")
            ),
            "outer tracing links target different functions",
        )
        _need(
            (
                identities["copy_consume"]["target_obj_id"],
                identities["copy_consume"]["target_btf_id"],
            )
            != (
                identities["copy_entry"]["target_obj_id"],
                identities["copy_entry"]["target_btf_id"],
            ),
            "consume tracing link must target its distinct fixed function",
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
        # Detach entry, consume, exit. No map read until ALL owned links detach.
        for name in ("copy_entry", "copy_consume", "copy_exit"):
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
            try:
                event = backend.lookup(fds["events"], C.c_uint32(index), Event())
            except Exception:
                # The owned maps are already detached. One unreadable slot does
                # not invalidate independently checked earlier slots. Preserve
                # those facts, mark loss, and never invent the missing row.
                counts["correlation_loss"] += 1
                continue
            row = _event(event)
            # An empty/partial array slot is loss, never a manufactured positive.
            valid = (
                configuration["started_ns"]
                <= row["entered_ns"]
                <= row["consumed_ns"]
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
            valid = valid and (
                row["receiver_real_uid"]
                == row["receiver_effective_uid"]
                == configuration["socket_uid"]
                and row["receiver_tgid"] > 0
                and row["receiver_tid"] > 0
                and row["receiver_start_boottime_ns"] > 0
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
            for name in ("copy_entry", "copy_consume", "copy_exit"):
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
        raise UDPPayloadCopyBPFError(
            "fixed payload-copy observer failed"
            + (f": {failure}" if failure else "")
            + ("; " + ",".join(close_errors) if close_errors else "")
        ) from failure
    return result
