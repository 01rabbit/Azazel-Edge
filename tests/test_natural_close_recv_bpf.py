"""SYNTHETIC FFI/BTF only; no actual kernel load or measurement."""

import ctypes as C
import errno
import hashlib
import json
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark import natural_close_recv_bpf as b
from test_authority_ingress_bpf import OSProxy


def configuration():
    return dict(
        pidns_device=4,
        pidns_inode=42,
        server_start_ticks=5,
        actor_start_ticks=6,
        started_ns=50,
        deadline_ns=250,
        server_tgid=12,
        actor_tgid=13,
        user_hz=100,
        max_events=2,
        server_uid=65534,
        actor_uid=65534,
    )


def environment(monkeypatch, tmp_path):
    source = tmp_path / "fixed.c"
    source.write_bytes(b"SYNTHETIC fixed source")
    monkeypatch.setattr(b, "SOURCE", source)
    monkeypatch.setattr(b, "os", OSProxy())
    monkeypatch.setattr(b, "_role", lambda: None)
    monkeypatch.setattr(b, "_proc_bytes", lambda *a: b"monotonic 0 0\nboottime 0 0\n")
    return hashlib.sha256(source.read_bytes()).hexdigest()


def test_fixed_abi_and_offsets():
    assert tuple(map(C.sizeof, (b.Configuration, b.Event, b.Counters))) == (
        72,
        416,
        128,
    )
    assert (
        b.Configuration.server_tgid.offset == 48
        and b.Configuration.max_events.offset == 60
    )
    assert (
        b.Configuration.server_uid.offset == 64
        and b.Configuration.actor_uid.offset == 68
    )
    assert b.MAPS["config"] == (2, 4, 72, 1)
    assert b.Event.data.offset == 160 and b.Event.ret.offset == 64
    assert b.Counters.unmatched_exit.offset == 88
    assert b.MAPS["copy_pending"] == b.MAPS["recv_pending"] == (1, 8, 416, 2)


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor_tgid", 12),
        ("server_tgid", 1),
        ("user_hz", 1000),
        ("max_events", 33),
        ("pidns_inode", 43),
        ("started_ns", True),
        ("deadline_ns", 49),
        ("actor_start_ticks", 0),
        ("server_uid", 0),
        ("actor_uid", 0),
        ("server_uid", 65533),
        ("actor_uid", 65533),
        ("server_uid", True),
    ],
)
def test_configuration_refuses_unsafe(monkeypatch, tmp_path, field, value):
    environment(monkeypatch, tmp_path)
    cfg = configuration()
    cfg[field] = value
    with pytest.raises(ValueError):
        b._configuration(cfg)


class FakeNative:
    def __init__(self, mode, original):
        self.mode, self.original, self.destroyed, self.disconnected, self.attached = (
            mode,
            original,
            [],
            [],
            [],
        )
        self.lib = SimpleNamespace(
            bpf_object__open_mem=lambda *a: 1,
            bpf_object__load=self.load,
            bpf_map__fd=lambda p: p,
            bpf_map_update_elem=self.update,
            bpf_program__attach=self.attach,
            bpf_link__destroy=self.destroy,
            bpf_link__disconnect=lambda p: self.disconnected.append(p),
            bpf_object__close=lambda p: self.destroyed.append("object"),
            bpf_map_get_next_key=self.next,
        )

    def pointer(self, p, *a):
        return p

    def inspect(self, obj):
        return {k: k for k in b.MAPS}, {
            "recv_entry": 101,
            "recv_exit": 102,
            "copy_entry": 103,
            "copy_exit": 104,
        }

    def load(self, obj):
        if self.mode == "alias":
            self.original["max_events"] = 1
        return 0

    def update(self, fd, key, cfg, flags):
        self.written = C.cast(cfg, C.POINTER(b.Configuration)).contents.max_events
        return 0

    def attach(self, p):
        self.attached.append(p)
        return p

    def link_identity(self, link, program, attach):
        return dict(
            fd=link,
            type=2,
            link_id=link,
            prog_id=100 + link,
            attach_type=attach,
            target_obj_id=1,
            target_btf_id=77,
        )

    def check_link(self, identity):
        if self.mode == "lost" and identity["fd"] == 103:
            return "lost"
        if self.mode == "unknown" and identity["fd"] == 102:
            return "unknown"
        return "retained"

    def lookup_optional(self, fd, key, value):
        if key.value >= 2:
            return None
        return self.lookup(fd, key, value)

    def lookup(self, fd, key, value):
        if fd == "stats":
            value.selected_entries = value.pending_inserted = (
                value.successful_copies
            ) = value.emitted = 2
            return value
        if self.mode == "slot_error" and key.value == 1:
            raise OSError("SYNTHETIC later slot unavailable")
        value.kind = 1
        value.token = 90
        value.entered_ns = 100
        value.exited_ns = 110
        value.chunk = 1
        value.ret = 1
        value.data[0] = 65
        return value

    def destroy(self, p):
        self.destroyed.append(p)
        return -1 if self.mode == "destroy_error" and p == 103 else 0

    def next(self, *a):
        C.set_errno(errno.ENOENT)
        return -errno.ENOENT


@pytest.mark.parametrize(
    "mode", ["healthy", "lost", "unknown", "destroy_error", "alias", "slot_error"]
)
def test_actual_provider_orchestration_preserves_indexed_known_rows_and_closes_once(
    monkeypatch, tmp_path, mode
):
    pin = environment(monkeypatch, tmp_path)
    cfg = configuration()
    native = FakeNative(mode, cfg)
    monkeypatch.setattr(b, "_Libbpf", lambda: native)
    clock = iter(range(100, 2000, 50))
    monkeypatch.setattr(
        b,
        "time",
        SimpleNamespace(monotonic_ns=lambda: next(clock), sleep=lambda _: None),
    )
    result = b._capture_events(
        cfg,
        b"object",
        expected_object_sha256=hashlib.sha256(b"object").hexdigest(),
        expected_source_sha256=pin,
    )
    assert result["schema_version"] == "edge-natural-close-probe/v1"
    assert (
        result["configuration"]["server_uid"]
        == result["configuration"]["actor_uid"]
        == 65534
    )
    assert native.attached == [102, 104, 103, 101] and native.destroyed == [
        101,
        103,
        104,
        102,
        "object",
    ]
    assert native.written == result["configuration"]["max_events"] == 2
    assert len(result["events"]) == (1 if mode == "slot_error" else 2)
    assert all(r["data_hex"] == "41" for r in result["events"])
    if mode in ("lost", "unknown"):
        assert "observer_link_lost" in result["partial_reasons"]
    if mode in ("unknown", "destroy_error"):
        assert "observer_cleanup_unverified" in result["partial_reasons"]
    if mode == "slot_error":
        assert "acquisition_error" in result["partial_reasons"]
    if mode in ("healthy", "alias"):
        assert result["partial_reasons"] == []
    assert native.disconnected == (
        [103] if mode == "lost" else [102] if mode == "unknown" else []
    )


@pytest.mark.parametrize(
    "rc,error,expected",
    [
        (0, 0, "value"),
        (-errno.ENOENT, 0, "vacant"),
        (-errno.ENOENT, errno.ENOENT, "vacant"),
        (-errno.ENOENT, errno.EPERM, "vacant"),
        (-1, errno.ENOENT, "error"),
        (-13, errno.ENOENT, "error"),
        (-77, errno.ENOENT, "error"),
        (-1, errno.EPERM, "error"),
        (-1, 0, "error"),
        (1, errno.ENOENT, "error"),
    ],
)
def test_optional_hash_lookup_only_exact_enoent_is_vacancy(rc, error, expected):
    native = object.__new__(b._Libbpf)

    def lookup(*args):
        assert C.get_errno() == 0
        C.set_errno(error)
        return rc

    native.lib = SimpleNamespace(bpf_map_lookup_elem=lookup)
    C.set_errno(errno.ENOENT)
    if expected == "error":
        with pytest.raises(b.NaturalCloseRecvBPFError):
            native.lookup_optional(10, C.c_uint32(), b.Event())
    else:
        value = native.lookup_optional(10, C.c_uint32(), b.Event())
        assert (value is None) == (expected == "vacant")


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing_zero",
        "writable_zero",
        "flags_events",
        "array_events",
        "pending64",
        "missing_recv_pending",
        "missing_recv_hook",
        "legacy_config64",
        "extra_map",
        "extra_program",
        "missing_entry",
        "wrong_section",
        "wrong_attach",
        "wrong_program_type",
    ],
)
def test_exact_five_maps_and_two_programs_before_load(fault):
    maps = [
        dict(name=n, shape=shape, flags=b.MAP_FLAGS[n]) for n, shape in b.MAPS.items()
    ]
    programs = [
        dict(name=n, section=section, kind=26, attach=attach)
        for n, (section, attach) in b.PROGRAMS.items()
    ]
    if fault == "missing_zero":
        maps = [r for r in maps if r["name"] != "zero_template"]
    elif fault == "writable_zero":
        next(r for r in maps if r["name"] == "zero_template")["flags"] = 0
    elif fault == "flags_events":
        next(r for r in maps if r["name"] == "events")["flags"] = 128
    elif fault == "array_events":
        next(r for r in maps if r["name"] == "events")["shape"] = (2, 4, 376, 16)
    elif fault == "pending64":
        next(r for r in maps if r["name"] == "copy_pending")["shape"] = (1, 8, 416, 64)
    elif fault == "missing_recv_pending":
        maps = [r for r in maps if r["name"] != "recv_pending"]
    elif fault == "missing_recv_hook":
        programs = [r for r in programs if r["name"] != "recv_entry"]
    elif fault == "legacy_config64":
        next(r for r in maps if r["name"] == "config")["shape"] = (2, 4, 64, 1)
    elif fault == "extra_map":
        maps.append(dict(name="foreign", shape=(2, 4, 8, 1), flags=0))
    elif fault == "extra_program":
        programs.append(dict(programs[0]))
    elif fault == "missing_entry":
        programs.pop(0)
    elif fault == "wrong_section":
        programs[0]["section"] = b"fentry/foreign"
    elif fault == "wrong_attach":
        programs[0]["attach"] = 25
    elif fault == "wrong_program_type":
        programs[0]["kind"] = 17

    def next_item(items, previous):
        index = previous or 0
        return index + 1 if index < len(items) else 0

    methods = dict(
        bpf_object__next_map=lambda obj, prev: next_item(maps, prev),
        bpf_map__name=lambda p: maps[p - 1]["name"].encode(),
        bpf_map__map_flags=lambda p: maps[p - 1]["flags"],
        bpf_object__next_program=lambda obj, prev: next_item(programs, prev),
        bpf_program__name=lambda p: programs[p - 1]["name"].encode(),
        bpf_program__section_name=lambda p: programs[p - 1]["section"],
        bpf_program__type=lambda p: programs[p - 1]["kind"],
        bpf_program__expected_attach_type=lambda p: programs[p - 1]["attach"],
    )
    for j, k in enumerate(("type", "key_size", "value_size", "max_entries")):
        methods["bpf_map__" + k] = lambda p, j=j: maps[p - 1]["shape"][j]
    native = object.__new__(b._Libbpf)
    native.lib = SimpleNamespace(**methods)
    if fault:
        with pytest.raises(b.NaturalCloseRecvBPFError):
            native.inspect(1)
    else:
        actual, progs = native.inspect(1)
        assert set(actual) == set(b.MAPS) and set(progs) == set(b.PROGRAMS)


@pytest.mark.parametrize(
    "stage,number", [("kernel", 9), ("kernel", 77), ("proc", 9), ("proc", 77)]
)
def test_inherited_cached_link_health_distinguishes_query_and_proc_errors(
    monkeypatch, stage, number
):
    import struct
    from azazel_edge.benchmark import udp_queue_bpf

    native = object.__new__(b._Libbpf)
    identity = dict(
        fd=7,
        type=2,
        link_id=8,
        prog_id=9,
        attach_type=25,
        target_obj_id=1,
        target_btf_id=100,
    )

    def info(fd):
        if stage == "kernel":
            raise OSError(number, "SYNTHETIC missing ownedFD")
        return struct.pack("=7I", 2, 8, 9, 0, 25, 1, 100) + bytes(36)

    native._object_info = info

    def proc(*a):
        raise OSError(number, "SYNTHETIC unreadable proc AFTERsuccessfulkernelquery")

    monkeypatch.setattr(udp_queue_bpf, "_proc_bytes", proc)
    assert native.check_link(identity) == ("lost" if stage == "kernel" else "unknown")


def wrapper_graph():
    """SYNTHETIC new wrapper/FD graph extending shared read-actor fixture."""
    from test_postconnect_copy_bpf import graph

    value = graph()
    rows = value["types"]

    def add(kind, **fields):
        key = len(rows) + 1
        rows.append(dict(id=key, kind=kind, **fields))
        return key

    def pointer(key):
        return add("PTR", name="(anon)", type_id=key)

    def aggregate(name, size, members, kind="STRUCT"):
        return add(
            kind,
            name=name,
            size=size,
            vlen=len(members),
            members=[dict(name=n, type_id=t, bits_offset=o) for n, t, o in members],
        )

    named = {r.get("name"): r for r in rows if r["kind"] == "STRUCT"}
    unsigned = next(
        r["id"]
        for r in rows
        if r["kind"] == "INT" and r["size"] == 8 and r["encoding"] == "(none)"
    )
    u32 = next(
        r["id"]
        for r in rows
        if r["kind"] == "INT" and r["size"] == 4 and r["encoding"] == "(none)"
    )
    u16 = next(
        r["id"]
        for r in rows
        if r["kind"] == "INT" and r["size"] == 2 and r["encoding"] == "(none)"
    )
    signed = add(
        "INT", name="long int", size=8, bits_offset=0, nr_bits=64, encoding="SIGNED"
    )
    array = add(
        "ARRAY", name="(anon)", type_id=unsigned, index_type_id=u32, nr_elems=31
    )
    regfields = [
        ("regs", array, 0),
        ("sp", unsigned, 1984),
        ("pc", unsigned, 2048),
        ("pstate", unsigned, 2112),
    ]
    user = aggregate("user_pt_regs", 272, regfields)
    anon = aggregate("(anon)", 272, regfields)
    overlay = aggregate(
        "(anon)", 272, [("user_regs", user, 0), ("(anon)", anon, 0)], "UNION"
    )
    regs = aggregate(
        "pt_regs", 336, [("(anon)", overlay, 0), ("orig_x0", unsigned, 2176)]
    )
    const = add("CONST", name="(anon)", type_id=regs)
    proto = add(
        "FUNC_PROTO",
        name="(anon)",
        vlen=1,
        ret_type_id=signed,
        params=[dict(name="regs", type_id=pointer(const))],
    )
    add("FUNC", name="__arm64_sys_recvfrom", type_id=proto)
    file = named["file"]
    fdptr = pointer(pointer(file["id"]))
    table = aggregate(
        "fdtable",
        56,
        [
            ("max_fds", u32, 0),
            ("fd", fdptr, 64),
            ("close_on_exec", fdptr, 128),
            ("open_fds", fdptr, 192),
            ("full_fds_bits", fdptr, 256),
            ("rcu", unsigned, 320),
        ],
    )
    files = aggregate("files_struct", 704, [("fdt", pointer(table), 256)])
    for name, field, kind, offset in (
        ("task_struct", "files", pointer(files), 192),
        ("file", "private_data", pointer(0), 128),
        ("inode", "i_mode", u16, 128),
    ):
        named[name]["members"].append(
            dict(name=field, type_id=kind, bits_offset=offset)
        )
        named[name]["vlen"] += 1
    return value


def test_exact_native_wrapper_and_copy_graph():
    result = b.validate_kernel_prototype(json.dumps(wrapper_graph()).encode())
    assert result["function"] == "unix_stream_read_actor"
    assert result["recv_function_id"] > 0
    assert result["recvfrom_profile"] == "aarch64_const_pt_regs_336_fdtable_56"


@pytest.mark.parametrize(
    "fault",
    [
        "wrapper_missing",
        "wrapper_duplicate",
        "argument_extra",
        "argument_not_const",
        "return_unsigned",
        "regs_size",
        "array_count",
        "array_signed",
        "pstate_offset",
        "fdtable_size",
        "fd_not_pointer",
        "fd_not_file",
        "file_private_not_void",
        "inode_mode_wide",
        "files_missing",
        "offset_bool",
    ],
)
def test_wrapper_graph_rejects_ambiguous_or_unsafe_layout(fault):
    value = wrapper_graph()
    rows = value["types"]
    named = {r.get("name"): r for r in rows if r["kind"] == "STRUCT"}
    func = next(r for r in rows if r.get("name") == "__arm64_sys_recvfrom")
    proto = rows[func["type_id"] - 1]
    if fault == "wrapper_missing":
        func["name"] = "wrong"
    elif fault == "wrapper_duplicate":
        rows.append(dict(func, id=len(rows) + 1))
    elif fault == "argument_extra":
        proto["params"].append(dict(proto["params"][0]))
        proto["vlen"] = 2
    elif fault == "argument_not_const":
        pointer = rows[proto["params"][0]["type_id"] - 1]
        pointer["type_id"] = named["pt_regs"]["id"]
    elif fault == "return_unsigned":
        rows[proto["ret_type_id"] - 1]["encoding"] = "(none)"
    elif fault == "regs_size":
        named["pt_regs"]["size"] = 344
    elif fault in ("array_count", "array_signed"):
        array = next(
            r for r in rows if r["kind"] == "ARRAY" and r.get("nr_elems") == 31
        )
        if fault == "array_count":
            array["nr_elems"] = 32
        else:
            array["type_id"] = proto["ret_type_id"]
    elif fault == "pstate_offset":
        aggregate = next(
            r
            for r in rows
            if r["kind"] == "STRUCT"
            and r.get("name") == "(anon)"
            and any(m.get("name") == "pstate" for m in r.get("members", []))
        )
        next(m for m in aggregate["members"] if m["name"] == "pstate")[
            "bits_offset"
        ] = 2104
    elif fault == "fdtable_size":
        named["fdtable"]["size"] = 64
    elif fault in ("fd_not_pointer", "fd_not_file"):
        field = next(m for m in named["fdtable"]["members"] if m["name"] == "fd")
        if fault == "fd_not_pointer":
            field["type_id"] = proto["ret_type_id"]
        else:
            outer = rows[field["type_id"] - 1]
            inner = rows[outer["type_id"] - 1]
            inner["type_id"] = named["inode"]["id"]
    elif fault == "file_private_not_void":
        field = next(m for m in named["file"]["members"] if m["name"] == "private_data")
        rows[field["type_id"] - 1]["type_id"] = named["file"]["id"]
    elif fault == "inode_mode_wide":
        next(m for m in named["inode"]["members"] if m["name"] == "i_mode")[
            "type_id"
        ] = proto["ret_type_id"]
    elif fault == "files_missing":
        next(m for m in named["task_struct"]["members"] if m["name"] == "files")[
            "name"
        ] = "wrong"
    elif fault == "offset_bool":
        next(m for m in named["fdtable"]["members"] if m["name"] == "fd")[
            "bits_offset"
        ] = True
    with pytest.raises(ValueError):
        b.validate_kernel_prototype(json.dumps(value).encode())


@pytest.mark.parametrize("status", [0, 2, 3])
def test_unavailable_identity_is_explicit_null_never_cached(status):
    event = b.Event(
        kind=2,
        token=100,
        entered_ns=100,
        exited_ns=110,
        peer_inode=1234,
        endpoint_inode=5678,
        endpoint_major=1,
        endpoint_minor=2,
        peer_status=status,
        endpoint_status=status,
    )
    row = b._dict(event)
    assert (
        row["peer_inode"]
        is row["endpoint_inode"]
        is row["endpoint_major"]
        is row["endpoint_minor"]
        is None
    )
    assert row["data_hex"] == ""


def test_entry_with_no_exit_is_retained_by_snapshot(monkeypatch, tmp_path):
    pin = environment(monkeypatch, tmp_path)
    cfg = configuration()
    native = FakeNative("healthy", cfg)
    original = native.lookup

    def lookup(fd, key, value):
        if fd == "stats":
            value.recv_selected = value.recv_inflight = value.emitted = 1
            return value
        original(fd, key, value)
        value.kind = 0
        value.chunk = value.ret = value.exited_ns = 0
        return value

    native.lookup = lookup
    native.lookup_optional = (
        lambda fd, key, val: lookup(fd, key, val) if key.value == 0 else None
    )
    monkeypatch.setattr(b, "_Libbpf", lambda: native)
    clock = iter(range(100, 2000, 50))
    monkeypatch.setattr(
        b,
        "time",
        SimpleNamespace(monotonic_ns=lambda: next(clock), sleep=lambda _: None),
    )
    result = b._capture_events(
        cfg,
        b"object",
        expected_object_sha256=hashlib.sha256(b"object").hexdigest(),
        expected_source_sha256=pin,
    )
    assert len(result["events"]) == 1
    assert result["events"][0]["kind"] == 0 and result["events"][0]["exited_ns"] == 0
    assert result["partial_reasons"] == ["pending_not_empty"]
