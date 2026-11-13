"""SYNTHETIC FFI/kernel metadata. No BPF load or measurement is performed."""

import ctypes as C
import errno
import hashlib
import os
import struct
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import authority_ingress_bpf as b


def config():
    return dict(
        pidns_device=4,
        pidns_inode=42,
        actor_start_ticks=5,
        started_ns=50,
        deadline_ns=200,
        actor_tgid=12,
        actor_uid=1000,
        user_hz=100,
        max_events=2,
    )


class OSProxy:
    def __getattr__(self, key):
        return getattr(os, key)

    def stat(self, path, *args, **kwargs):
        if path == "/proc/self/ns/pid":
            return SimpleNamespace(st_dev=4, st_ino=42)
        return os.stat(path, *args, **kwargs)


def environment(monkeypatch, tmp_path):
    source = tmp_path / "fixed.c"
    source.write_bytes(b"SYNTHETIC fixed source")
    monkeypatch.setattr(b, "SOURCE", source)
    monkeypatch.setattr(b, "os", OSProxy())
    monkeypatch.setattr(
        b, "_proc_bytes", lambda path, limit: b"monotonic 0 0\nboottime 0 0\n"
    )
    monkeypatch.setattr(b, "_role", lambda: None)
    return hashlib.sha256(source.read_bytes()).hexdigest()


def test_exact_ctypes_abi_and_field_offsets():
    assert tuple(C.sizeof(t) for t in (b.Configuration, b.Event, b.Counters)) == (
        56,
        176,
        40,
    )
    assert (
        b.Configuration.actor_tgid.offset == 40
        and b.Configuration.max_events.offset == 52
    )
    assert b.Event.path.offset == 64 and b.Event.reserved.offset == 172
    assert b.Counters.read_failure.offset == 32


def test_root_actor_is_explicitly_allowed(tmp_path, monkeypatch):
    environment(monkeypatch, tmp_path)
    value = config()
    value["actor_uid"] = 0
    assert b._configuration(value).actor_uid == 0


@pytest.mark.parametrize("fault", ["arch", "role"])
def test_unsupported_role_rejects_before_source_object_library(monkeypatch, fault):
    calls = []
    monkeypatch.setattr(
        b,
        "platform",
        SimpleNamespace(machine=lambda: "x86_64" if fault == "arch" else "aarch64"),
    )

    def role():
        calls.append("role")
        raise ValueError("SYNTHETIC denied role")

    monkeypatch.setattr(b, "_base_role", role)

    def forbidden(*args, **kwargs):
        raise AssertionError("guard reached object/library")

    monkeypatch.setattr(b, "_configuration", forbidden)
    monkeypatch.setattr(b, "_source_hash", forbidden)
    monkeypatch.setattr(b, "_Libbpf", forbidden)
    with pytest.raises(ValueError):
        b._capture_events(
            config(),
            b"object",
            expected_object_sha256="a" * 64,
            expected_source_sha256="b" * 64,
        )
    assert calls == ([] if fault == "arch" else ["role"])


@pytest.mark.parametrize("fault", ["source", "object"])
def test_external_pins_reject_before_library(tmp_path, monkeypatch, fault):
    sourcepin = environment(monkeypatch, tmp_path)

    def forbidden():
        raise AssertionError("library loaded before pins")

    monkeypatch.setattr(b, "_Libbpf", forbidden)
    with pytest.raises(
        b.AuthorityIngressBPFError, match="source pin differs|object pin differs"
    ):
        b._capture_events(
            config(),
            b"object",
            expected_object_sha256=hashlib.sha256(b"object").hexdigest()
            if fault == "source"
            else "a" * 64,
            expected_source_sha256="b" * 64 if fault == "source" else sourcepin,
        )


@pytest.mark.parametrize(
    "fault",
    [
        "bool",
        "overflow",
        "uid0",
        "tgid1",
        "hz",
        "events65",
        "too_long",
        "backwards",
        "namespace",
        "time_offset",
    ],
)
def test_actual_configuration_parser_refuses_unsafe_synthetic_inputs(
    tmp_path, monkeypatch, fault
):
    environment(monkeypatch, tmp_path)
    value = config()
    if fault == "bool":
        value["actor_uid"] = True
    elif fault == "overflow":
        value["actor_tgid"] = 2**32
    elif fault == "uid0":
        value["actor_uid"] = -1
    elif fault == "tgid1":
        value["actor_tgid"] = 1
    elif fault == "hz":
        value["user_hz"] = 1000
    elif fault == "events65":
        value["max_events"] = 65
    elif fault == "too_long":
        value["deadline_ns"] = value["started_ns"] + 5_000_000_001
    elif fault == "backwards":
        value["deadline_ns"] = value["started_ns"] - 1
    elif fault == "namespace":
        value["pidns_inode"] = 43
    elif fault == "time_offset":
        monkeypatch.setattr(
            b, "_proc_bytes", lambda *args: b"monotonic 0 1\nboottime 0 0\n"
        )
    with pytest.raises(ValueError):
        b._configuration(value)


def inspect_library(fault=None):
    maps = [
        dict(name=name.encode(), abi=shape, flags=0) for name, shape in b.MAPS.items()
    ]
    programs = [
        dict(
            name=b"authority_exit",
            section=b"fexit/unix_stream_connect",
            kind=26,
            attach=25,
        )
    ]
    if fault == "extra_map":
        maps.append(dict(name=b"foreign", abi=(2, 4, 8, 1), flags=0))
    elif fault == "missing_map":
        maps.pop()
    elif fault == "duplicate_map":
        maps.append(dict(maps[0]))
    elif fault == "map_flags":
        maps[0]["flags"] = 1
    elif fault == "map_abi":
        maps[0]["abi"] = (2, 4, 55, 1)
    elif fault == "extra_program":
        programs.append(dict(programs[0]))
    elif fault == "section":
        programs[0]["section"] = b"tracepoint/syscalls/sys_enter_execve"
    elif fault == "type":
        programs[0]["kind"] = 17
    elif fault == "attach":
        programs[0]["attach"] = 24

    def next_item(items, previous):
        index = 0 if previous is None else previous
        return index + 1 if index < len(items) else 0

    methods = dict(
        bpf_object__next_map=lambda obj, prev: next_item(maps, prev),
        bpf_map__name=lambda ptr: maps[ptr - 1]["name"],
        bpf_map__map_flags=lambda ptr: maps[ptr - 1]["flags"],
        bpf_object__next_program=lambda obj, prev: next_item(programs, prev),
        bpf_program__name=lambda ptr: programs[ptr - 1]["name"],
        bpf_program__section_name=lambda ptr: programs[ptr - 1]["section"],
        bpf_program__type=lambda ptr: programs[ptr - 1]["kind"],
        bpf_program__expected_attach_type=lambda ptr: programs[ptr - 1]["attach"],
    )
    for index, key in enumerate(("type", "key_size", "value_size", "max_entries")):
        methods["bpf_map__" + key] = lambda ptr, index=index: maps[ptr - 1]["abi"][
            index
        ]
    backend = object.__new__(b._Libbpf)
    backend.lib = SimpleNamespace(**methods)
    return backend


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "extra_map",
        "missing_map",
        "duplicate_map",
        "map_flags",
        "map_abi",
        "extra_program",
        "section",
        "type",
        "attach",
    ],
)
def test_fixed_map_and_program_abi_inspection(fault):
    backend = inspect_library(fault)
    if fault:
        with pytest.raises(b.AuthorityIngressBPFError):
            backend.inspect(100)
    else:
        maps, program = backend.inspect(100)
        assert set(maps) == set(b.MAPS) and program == 1


IDENTITY = dict(
    fd=7,
    type=2,
    link_id=8,
    prog_id=9,
    attach_type=25,
    target_obj_id=1,
    target_btf_id=100,
)
FDINFO = b"link_type:\ttracing\nlink_id:\t8\nprog_id:\t9\nattach_type:\t25\ntarget_obj_id:\t1\ntarget_btf_id:\t100\n"


@pytest.mark.parametrize(
    "state",
    [
        "retained",
        "changed_link",
        "changed_program",
        "kernel_ebadf",
        "kernel_ebadfd77",
        "proc_ebadfd77",
        "proc_ebadf",
        "invalid_foreign",
        "invalid_ambiguous",
    ],
)
def test_cached_link_identity_classification_separates_kernel_and_proc_failure(
    monkeypatch, state
):
    backend = object.__new__(b._Libbpf)

    def object_info(fd):
        if state.startswith("kernel_"):
            raise OSError(
                9 if state == "kernel_ebadf" else 77, "SYNTHETIC native missing FD"
            )
        if state.startswith("invalid_"):
            raise OSError(errno.EINVAL, "SYNTHETIC foreign FD")
        return struct.pack(
            "=7I",
            2,
            10 if state == "changed_link" else 8,
            10 if state == "changed_program" else 9,
            0,
            25,
            1,
            100,
        ) + bytes(36)

    backend._object_info = object_info
    backend._foreign_fd = lambda fd: state == "invalid_foreign"

    def proc(path, limit):
        if state in ("proc_ebadf", "proc_ebadfd77"):
            raise OSError(
                9 if state == "proc_ebadf" else 77,
                "SYNTHETIC proc inaccessible after kernel success",
            )
        if state.startswith("invalid_"):
            return b"pos:0\nflags:0100000\nmnt_id:1\nino:2\n"
        return (
            FDINFO.replace(b"link_id:\t8", b"link_id:\t10")
            if state == "changed_link"
            else FDINFO.replace(b"prog_id:\t9", b"prog_id:\t10")
            if state == "changed_program"
            else FDINFO
        )

    from azazel_edge.benchmark import udp_queue_bpf

    monkeypatch.setattr(udp_queue_bpf, "_proc_bytes", proc)
    expected = (
        "retained"
        if state == "retained"
        else "lost"
        if state
        in ("changed_link", "kernel_ebadf", "kernel_ebadfd77", "invalid_foreign")
        else "unknown"
    )
    assert backend.check_link(IDENTITY) == expected


def fake_backend(
    monkeypatch,
    *,
    health,
    fd,
    events,
    destroy_error=False,
    mutate=None,
    identical_rows=False,
):
    disconnected = []

    class Library:
        def bpf_object__open_mem(self, *args):
            return 100

        def bpf_object__load(self, obj):
            if mutate:
                mutate()
            return 0

        def bpf_map__fd(self, ptr):
            return ptr

        def bpf_map_update_elem(self, *args):
            events.append("config-write")
            return 0

        def bpf_program__attach(self, program):
            events.append("attach")
            return 200

        def bpf_link__disconnect(self, pointer):
            disconnected.append(pointer)
            events.append(("disconnect", pointer))

        def bpf_link__destroy(self, pointer):
            events.append(("destroy", pointer))
            if pointer not in disconnected:
                os.close(fd)
            return -1 if destroy_error else 0

        def bpf_object__close(self, obj):
            events.append(("object-close", obj))

    class Backend:
        lib = Library()

        def pointer(self, value, stage):
            return value

        def inspect(self, obj):
            return dict(config=10, events=12, stats=13), 20

        def link_identity(self, link, program, attach):
            return dict(IDENTITY, fd=fd)

        def check_link(self, identity):
            return health

        def lookup(self, fd, key, value):
            if isinstance(value, b.Counters):
                value.observed = value.emitted = 2
            else:
                index = 1 if identical_rows else key.value
                value.at_ns = 80 + index
                value.start_ns = 50_000_001
                value.tgid = value.tid = 12
                value.uid = 1000
                value.client_inode = 55
                value.peer_inode = 77 if index == 0 else 0
                value.peer_minor = 43 if index == 0 else 0
                value.netns_inode = 42
                value.ret = 0 if index == 0 else -13
                value.path = b"/tmp/control.sock"
                value.addr_len = len(value.path) + 3
            return value

    monkeypatch.setattr(b, "_Libbpf", Backend)


@pytest.mark.parametrize("health", ["lost", "unknown"])
@pytest.mark.parametrize("destroy_error", [False, True])
def test_lost_or_unknown_owned_pointer_cleanup_preserves_real_foreign_replacement_fd(
    tmp_path, monkeypatch, health, destroy_error
):
    sourcepin = environment(monkeypatch, tmp_path)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"foreign remains")
    fd = os.open(foreign, os.O_RDONLY)
    events = []
    fake_backend(
        monkeypatch, health=health, fd=fd, events=events, destroy_error=destroy_error
    )
    monkeypatch.setattr(
        b,
        "time",
        SimpleNamespace(
            monotonic_ns=lambda: 100,
            sleep=lambda value: pytest.fail("no sleep after link loss"),
        ),
    )
    try:
        before = os.fstat(fd)
        result = b._capture_events(
            config(),
            b"SYNTHETIC object",
            expected_object_sha256=hashlib.sha256(b"SYNTHETIC object").hexdigest(),
            expected_source_sha256=sourcepin,
        )
        assert os.fstat(fd) == before and os.read(fd, 64) == b"foreign remains"
        assert (
            events.count(("disconnect", 200))
            == events.count(("destroy", 200))
            == events.count(("object-close", 100))
            == 1
        )
        assert "observer_link_lost" in result["partial_reasons"]
        assert (
            len(result["events"]) == 2
        )  # Saved original own-map rows survive cleanup uncertainty.
        assert ("observer_cleanup_unverified" in result["partial_reasons"]) == (
            health == "unknown" or destroy_error
        )
    finally:
        os.close(fd)


def test_caller_configuration_alias_cannot_change_fixed_event_budget_after_load(
    tmp_path, monkeypatch
):
    sourcepin = environment(monkeypatch, tmp_path)
    original = config()
    fd = os.open(os.devnull, os.O_RDONLY)
    events = []
    fake_backend(
        monkeypatch,
        health="retained",
        fd=fd,
        events=events,
        mutate=lambda: original.update(max_events=1),
    )
    ticks = iter((100, 201, 202))
    monkeypatch.setattr(
        b,
        "time",
        SimpleNamespace(
            monotonic_ns=lambda: next(ticks),
            sleep=lambda value: pytest.fail(
                "capture already reached its original deadline"
            ),
        ),
    )
    try:
        result = b._capture_events(
            original,
            b"SYNTHETIC object",
            expected_object_sha256=hashlib.sha256(b"SYNTHETIC object").hexdigest(),
            expected_source_sha256=sourcepin,
        )
        assert result["configuration"]["max_events"] == 2
        assert (
            len(result["events"]) == 2
        )  # Do not lose the valid exec row to a caller alias.
        assert [row["ret"] for row in result["events"]] == [0, -13]
        assert events.count("config-write") == events.count("attach") == 1
    finally:
        try:
            os.close(fd)
        except OSError as exc:
            assert exc.errno == errno.EBADF


def test_identical_distinct_map_slots_preserved_once_across_snapshot_retry(
    tmp_path, monkeypatch
):
    sourcepin = environment(monkeypatch, tmp_path)
    fd = os.open(os.devnull, os.O_RDONLY)
    events = []
    fake_backend(monkeypatch, health="lost", fd=fd, events=events, identical_rows=True)
    calls = []

    def role():
        calls.append("role")
        if len(calls) == 2:
            raise ValueError(
                "SYNTHETIC post-snapshot role failure forces second snapshot"
            )

    monkeypatch.setattr(b, "_role", role)
    monkeypatch.setattr(
        b,
        "time",
        SimpleNamespace(
            monotonic_ns=lambda: 100,
            sleep=lambda value: pytest.fail("lost link must not sleep"),
        ),
    )
    try:
        result = b._capture_events(
            config(),
            b"SYNTHETIC object",
            expected_object_sha256=hashlib.sha256(b"SYNTHETIC object").hexdigest(),
            expected_source_sha256=sourcepin,
        )
        # Two real map INDEXES in this synthetic FFI each contain identical raw
        # values. Preserve both originals, while retrying the same slots adds none.
        assert len(result["events"]) == 2
        assert result["events"][0] == result["events"][1]
        assert result["events"][0]["ret"] == -13
        assert "acquisition_error" in result["partial_reasons"]
        assert calls == ["role", "role"]
        assert events.count(("disconnect", 200)) == events.count(("destroy", 200)) == 1
    finally:
        os.close(fd)


def prototype():
    """SYNTHETIC minimal bpftool graph, not a kernel availability claim."""
    return dict(
        types=[
            dict(
                id=1,
                kind="INT",
                name="int",
                size=4,
                nr_bits=32,
                bits_offset=0,
                encoding="SIGNED",
            ),
            dict(id=2, kind="STRUCT", name="socket"),
            dict(id=3, kind="PTR", type_id=2),
            dict(id=4, kind="STRUCT", name="sockaddr"),
            dict(id=5, kind="PTR", type_id=4),
            dict(
                id=6,
                kind="FUNC_PROTO",
                ret_type_id=1,
                vlen=4,
                params=[
                    dict(name="sock", type_id=3),
                    dict(name="uaddr", type_id=5),
                    dict(name="addr_len", type_id=1),
                    dict(name="flags", type_id=1),
                ],
            ),
            dict(id=7, kind="FUNC", name="unix_stream_connect", type_id=6),
        ]
    )


def test_fixed_kernel_prototype_accepts_exact_graph_and_qualified_pointers():
    import json

    value = prototype()
    proof = b.validate_kernel_prototype(json.dumps(value).encode())
    assert (
        proof["function_id"] == 7
        and proof["prototype_id"] == 6
        and proof["arguments"] == 4
    )
    value["types"].append(dict(id=8, kind="CONST", type_id=4))
    value["types"][4]["type_id"] = 8
    assert b.validate_kernel_prototype(json.dumps(value).encode())["arguments"] == 4


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate_function",
        "extra_argument",
        "missing_argument",
        "reordered",
        "ret_void",
        "ret_pointer",
        "unsigned",
        "wide_int",
        "bool_size",
        "bool_vlen",
        "offset",
        "wrong_socket",
        "wrong_address",
        "nonpointer",
        "missing_type",
        "wrapper_cycle",
        "not_proto",
    ],
)
def test_fixed_kernel_prototype_rejects_changed_or_ambiguous_graph(fault):
    import json
    from copy import deepcopy

    value = prototype()
    rows = value["types"]
    proto = rows[5]
    if fault == "missing":
        rows.pop()
    elif fault == "duplicate_function":
        rows.append(dict(rows[6], id=8))
    elif fault == "extra_argument":
        proto["params"].append(dict(name="new_arg", type_id=1))
        proto["vlen"] = 5
    elif fault == "missing_argument":
        proto["params"].pop()
        proto["vlen"] = 3
    elif fault == "reordered":
        proto["params"][0], proto["params"][1] = proto["params"][1], proto["params"][0]
    elif fault == "ret_void":
        proto["ret_type_id"] = 0
    elif fault == "ret_pointer":
        proto["ret_type_id"] = 3
    elif fault == "unsigned":
        rows[0]["encoding"] = "(none)"
    elif fault == "wide_int":
        rows[0].update(size=8, nr_bits=64)
    elif fault == "bool_size":
        rows[0]["size"] = True
    elif fault == "bool_vlen":
        proto["vlen"] = True
    elif fault == "offset":
        rows[0]["bits_offset"] = 1
    elif fault == "wrong_socket":
        rows[1]["name"] = "sock"
    elif fault == "wrong_address":
        rows[3]["name"] = "sockaddr_un"
    elif fault == "nonpointer":
        proto["params"][0]["type_id"] = 2
    elif fault == "missing_type":
        proto["params"][1]["type_id"] = 99
    elif fault == "wrapper_cycle":
        rows[4].update(kind="TYPEDEF", type_id=5)
    elif fault == "not_proto":
        rows[5]["kind"] = "STRUCT"
    before = deepcopy(value)
    with pytest.raises(b.AuthorityIngressBPFError):
        b.validate_kernel_prototype(json.dumps(value).encode())
    assert value == before


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b'{"types":[],"types":[]}',
        b'{"types":NaN}',
        b"null",
        b'{"types":[true]}',
    ],
)
def test_fixed_kernel_prototype_rejects_bad_wire(raw):
    with pytest.raises(b.AuthorityIngressBPFError):
        b.validate_kernel_prototype(raw)
