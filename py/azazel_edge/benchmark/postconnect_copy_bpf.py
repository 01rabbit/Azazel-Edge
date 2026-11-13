"""Fixed read-only AF_UNIX protocol-copy observer; not application branch proof."""

import ctypes as C
import errno
import hashlib
import json
import os
from pathlib import Path
import time

from .authority_ingress_bpf import _Libbpf as _Tracing, _role
from .protected_ingress import _proc_bytes
from .safety_observations import _fields, _int


class PostconnectCopyBPFError(ValueError):
    pass


def _need(ok, reason):
    if not ok:
        raise PostconnectCopyBPFError(reason)


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
        (k, C.c_uint32) for k in ("server_tgid", "actor_tgid", "user_hz", "max_events")
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


assert tuple(map(C.sizeof, (Configuration, Event, Counters))) == (64, 376, 96)
MAPS = {
    "config": (2, 4, 64, 1),
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
SOURCE = Path(__file__).resolve().parents[3] / "native/postconnect_copy_observer.bpf.c"


def _configuration(value):
    _fields(value, " ".join(k for k, _ in Configuration._fields_))
    for key, kind in Configuration._fields_:
        _int(value[key], 1, 2 ** (C.sizeof(kind) * 8) - 1)
    _need(
        value["server_tgid"] > 1
        and value["actor_tgid"] > 1
        and value["server_tgid"] != value["actor_tgid"]
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
        error = C.get_errno()
        if rc == 0:
            return value
        if rc == -1 and error == errno.ENOENT:
            return None
        raise PostconnectCopyBPFError("event lookup failed")

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
        schema_version="edge-postconnect-copy-probe/v1",
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
                elif C.get_errno() != errno.ENOENT:
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


def validate_kernel_prototype(raw):
    """Fixed build-time BTF assertion, not runtime provenance/authentication."""

    def pairs(items):
        out = {}
        for key, value in items:
            _need(key not in out, "duplicate BTF key")
            out[key] = value
        return out

    def invalid(_):
        raise PostconnectCopyBPFError("noninteger/nonfinite BTF number")

    try:
        _need(type(raw) is bytes and 0 < len(raw) <= 32 * 1024 * 1024, "BTF byte bound")
        data = json.loads(
            raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid
        )
        _fields(data, "types")
        rows = data["types"]
        _need(type(rows) is list and 0 < len(rows) <= 250000, "BTF row bound")
        types = {}
        for row in rows:
            _need(
                type(row) is dict
                and type(row.get("id")) is int
                and 0 < row["id"] < 2**32
                and row["id"] not in types
                and type(row.get("kind")) is str,
                "BTF unique type ID",
            )
            types[row["id"]] = row

        def get(key):
            _need(type(key) is int and key in types, "referenced type missing")
            return types[key]

        def resolve(key):
            seen = set()
            for _ in range(16):
                _need(
                    type(key) is int and key not in seen, "cyclic/wrong BTF reference"
                )
                seen.add(key)
                row = get(key)
                if row["kind"] not in ("TYPEDEF", "CONST", "VOLATILE", "RESTRICT"):
                    return row
                key = row.get("type_id")
            raise PostconnectCopyBPFError("BTF wrapper depth")

        def unique(kind, name):
            found = [r for r in rows if r["kind"] == kind and r.get("name") == name]
            _need(len(found) == 1, "unique fixed BTF symbol required: " + name)
            return found[0]

        def integer(key, size, encoding, name=None):
            row = resolve(key)
            _need(
                row["kind"] == "INT"
                and type(row.get("size")) is int
                and row["size"] == size
                and type(row.get("nr_bits")) is int
                and row["nr_bits"] == size * 8
                and type(row.get("bits_offset")) is int
                and row["bits_offset"] == 0
                and row.get("encoding") == encoding
                and (name is None or row.get("name") == name),
                "fixed integer representation",
            )

        def pointer(key, target):
            row = resolve(key)
            _need(row["kind"] == "PTR", "fixed pointer required")
            if target is None:
                _need(
                    type(row.get("type_id")) is int and row["type_id"] == 0,
                    "void pointer required",
                )
                return None
            row = resolve(row.get("type_id"))
            _need(
                row["kind"] == "STRUCT" and row.get("name") == target,
                "fixed pointee differs: " + target,
            )
            return row

        anon = ("", "(anon)")

        def layout(row, kind, size, names, offsets):
            members = row.get("members")
            _need(
                row["kind"] == kind
                and type(row.get("size")) is int
                and row["size"] == size
                and type(row.get("vlen")) is int
                and row["vlen"] == len(names)
                and type(members) is list
                and len(members) == len(names),
                "fixed aggregate size/count",
            )
            for m, name, offset in zip(members, names, offsets):
                _need(
                    type(m) is dict
                    and set(m) <= {"name", "type_id", "bits_offset", "bitfield_size"}
                    and (
                        m.get("name") in anon if name is None else m.get("name") == name
                    )
                    and type(m.get("bits_offset")) is int
                    and m["bits_offset"] == offset
                    and type(m.get("bitfield_size", 0)) is int
                    and m.get("bitfield_size", 0) == 0,
                    "fixed aggregate member/offset",
                )
            return members

        def member(row, name):
            _need(type(row.get("members")) is list, "required kernel aggregate")
            found = [
                m for m in row["members"] if type(m) is dict and m.get("name") == name
            ]
            _need(len(found) == 1, "required kernel member: " + name)
            m = found[0]
            _need(
                type(m.get("bits_offset")) is int
                and m["bits_offset"] >= 0
                and type(m.get("bitfield_size", 0)) is int
                and m.get("bitfield_size", 0) == 0,
                "required nonbitfield member",
            )
            return m

        def callback(proto, names):
            _need(
                proto["kind"] == "FUNC_PROTO"
                and type(proto.get("vlen")) is int
                and proto["vlen"] == 4
                and type(proto.get("params")) is list
                and len(proto["params"]) == 4,
                "exact four argument callback",
            )
            p = proto["params"]
            _need(
                all(type(x) is dict for x in p)
                and all(
                    x.get("name") in anon if name is None else x.get("name") == name
                    for x, name in zip(p, names)
                ),
                "fixed argument bindings",
            )
            integer(proto.get("ret_type_id"), 4, "SIGNED", "int")
            skb = pointer(p[0].get("type_id"), "sk_buff")
            integer(p[1].get("type_id"), 4, "SIGNED", "int")
            integer(p[2].get("type_id"), 4, "SIGNED", "int")
            state = pointer(p[3].get("type_id"), "unix_stream_read_state")
            return skb, state

        function = unique("FUNC", "unix_stream_read_actor")
        proto = get(function.get("type_id"))
        skb, state = callback(proto, ("skb", "skip", "chunk", "state"))
        members = layout(
            state,
            "STRUCT",
            48,
            ("recv_actor", "socket", "msg", "pipe", "size", "flags", "splice_flags"),
            (0, 64, 128, 192, 256, 320, 352),
        )
        cb = resolve(members[0]["type_id"])
        _need(cb["kind"] == "PTR", "callback function pointer")
        callback_skb, callback_state = callback(
            get(cb.get("type_id")), (None, None, None, None)
        )
        _need(
            callback_skb["id"] == skb["id"] and callback_state["id"] == state["id"],
            "callback structure identity differs",
        )
        socket = pointer(members[1]["type_id"], "socket")
        msg = pointer(members[2]["type_id"], "msghdr")
        pointer(members[3]["type_id"], "pipe_inode_info")
        integer(members[4]["type_id"], 8, "(none)")
        integer(members[5]["type_id"], 4, "SIGNED", "int")
        integer(members[6]["type_id"], 4, "(none)")
        for name in ("len", "data_len"):
            integer(member(skb, name)["type_id"], 4, "(none)")
        byteptr = resolve(member(skb, "data")["type_id"])
        _need(byteptr["kind"] == "PTR", "skb byte pointer")
        integer(byteptr.get("type_id"), 1, "(none)")
        cb = resolve(member(skb, "cb")["type_id"])
        _need(
            cb["kind"] == "ARRAY"
            and type(cb.get("nr_elems")) is int
            and cb["nr_elems"] == 48,
            "skb cb48",
        )
        char = resolve(cb.get("type_id"))
        _need(
            char["kind"] == "INT"
            and char.get("name") == "char"
            and type(char.get("size")) is int
            and char["size"] == 1
            and type(char.get("nr_bits")) is int
            and char["nr_bits"] == 8
            and char.get("encoding") in ("(none)", "SIGNED", "CHAR")
            and type(char.get("bits_offset")) is int
            and char["bits_offset"] == 0,
            "skb C char",
        )
        parms = unique("STRUCT", "unix_skb_parms")
        consumed = member(parms, "consumed")
        _need(
            type(parms.get("size")) is int
            and 4 <= parms["size"] <= 48
            and consumed["bits_offset"] % 8 == 0
            and consumed["bits_offset"] + 32 <= parms["size"] * 8,
            "randomized consumed range",
        )
        integer(consumed["type_id"], 4, "(none)")
        it = unique("STRUCT", "iov_iter")
        m = layout(
            it,
            "STRUCT",
            40,
            ("iter_type", "nofault", "data_source", "iov_offset", None, None),
            (0, 8, 16, 64, 128, 256),
        )
        integer(m[0]["type_id"], 1, "(none)")
        integer(m[1]["type_id"], 1, "BOOL")
        integer(m[2]["type_id"], 1, "BOOL")
        integer(m[3]["type_id"], 8, "(none)")
        u = resolve(m[4]["type_id"])
        _need(u.get("name") in anon, "anonymous count union")
        um = layout(u, "UNION", 16, ("__ubuf_iovec", None), (0, 0))
        iovec = resolve(um[0]["type_id"])
        _need(iovec.get("name") == "iovec", "iovec type")
        iv = layout(iovec, "STRUCT", 16, ("iov_base", "iov_len"), (0, 64))
        pointer(iv[0]["type_id"], None)
        integer(iv[1]["type_id"], 8, "(none)")
        nested = resolve(um[1]["type_id"])
        _need(nested.get("name") in anon, "anonymous count struct")
        nm = layout(nested, "STRUCT", 16, (None, "count"), (0, 64))
        integer(nm[1]["type_id"], 8, "(none)")
        views = resolve(nm[0]["type_id"])
        _need(
            views.get("name") in anon and type(views.get("members")) is list,
            "known iterator views",
        )
        names = tuple(x.get("name") for x in views["members"] if type(x) is dict)
        old = ("__iov", "kvec", "bvec", "xarray", "ubuf")
        new = ("__iov", "kvec", "bvec", "folioq", "xarray", "ubuf")
        _need(names in (old, new), "unknown iterator profile")
        vm = layout(views, "UNION", 8, names, (0,) * len(names))
        for v, name in zip(vm, names):
            pointer(
                v["type_id"],
                {
                    "__iov": "iovec",
                    "kvec": "kvec",
                    "bvec": "bio_vec",
                    "folioq": "folio_queue",
                    "xarray": "xarray",
                    "ubuf": None,
                }[name],
            )
        tail = resolve(m[5]["type_id"])
        _need(tail.get("name") in anon, "anonymous iterator tail")
        tn = (
            ("nr_segs", "xarray_start")
            if names == old
            else ("nr_segs", "folioq_slot", "xarray_start")
        )
        tm = layout(tail, "UNION", 8, tn, (0,) * len(tn))
        integer(tm[0]["type_id"], 8, "(none)")
        integer(tm[-1]["type_id"], 8, "SIGNED")
        if names == new:
            integer(tm[1]["type_id"], 1, "(none)")
        enum = unique("ENUM", "iter_type")
        values = enum.get("values")
        _need(
            type(values) is list and all(type(v) is dict for v in values),
            "iterator enum",
        )
        for name, value in (("ITER_UBUF", 0), ("ITER_IOVEC", 1)):
            chosen = [v for v in values if v.get("name") == name]
            _need(
                len(chosen) == 1
                and type(chosen[0].get("val")) is int
                and chosen[0]["val"] == value,
                "fixed USER iterator enum",
            )
        _need(
            resolve(member(msg, "msg_iter")["type_id"])["id"] == it["id"],
            "actual message iterator",
        )
        # Fixed direct field traversals only; CO-RE supplies kernel offsets.
        sk = pointer(member(socket, "sk")["type_id"], "sock")
        file = pointer(member(socket, "file")["type_id"], "file")
        inode = pointer(member(file, "f_inode")["type_id"], "inode")
        integer(member(inode, "i_ino")["type_id"], 8, "(none)")
        sb = pointer(member(inode, "i_sb")["type_id"], "super_block")
        integer(member(sb, "s_dev")["type_id"], 4, "(none)")
        integer(member(sk, "sk_type")["type_id"], 2, "(none)")
        pointer(member(sk, "sk_socket")["type_id"], "socket")
        common = resolve(member(sk, "__sk_common")["type_id"])
        integer(member(common, "skc_family")["type_id"], 2, "(none)")
        netref = resolve(member(common, "skc_net")["type_id"])
        net = pointer(member(netref, "net")["type_id"], "net")
        ns = resolve(member(net, "ns")["type_id"])
        integer(member(ns, "inum")["type_id"], 4, "(none)")
        unix = unique("STRUCT", "unix_sock")
        pointer(member(unix, "peer")["type_id"], "sock")
        path = resolve(member(unix, "path")["type_id"])
        dentry = pointer(member(path, "dentry")["type_id"], "dentry")
        pointer(member(dentry, "d_inode")["type_id"], "inode")
        task = unique("STRUCT", "task_struct")
        pointer(member(task, "group_leader")["type_id"], "task_struct")
        integer(member(task, "start_boottime")["type_id"], 8, "(none)")
        cred = pointer(member(task, "cred")["type_id"], "cred")
        for name in ("uid", "euid"):
            uid = resolve(member(cred, name)["type_id"])
            integer(member(uid, "val")["type_id"], 4, "(none)")
        return dict(
            function="unix_stream_read_actor",
            function_id=function["id"],
            prototype_id=proto["id"],
            arguments=4,
            iterator_profile="iov_iter_6_8" if names == old else "iov_iter_7_0",
            btf_sha256=hashlib.sha256(raw).hexdigest(),
        )
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        if isinstance(exc, PostconnectCopyBPFError):
            raise
        raise PostconnectCopyBPFError("invalid fixed kernel prototype/layout") from exc
