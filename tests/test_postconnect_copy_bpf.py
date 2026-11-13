"""SYNTHETIC FFI/BTF only; no actual kernel load or measurement."""

import ctypes as C
import errno
import hashlib
import json
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark import postconnect_copy_bpf as b
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
    assert tuple(map(C.sizeof, (b.Configuration, b.Event, b.Counters))) == (64, 376, 96)
    assert (
        b.Configuration.server_tgid.offset == 48
        and b.Configuration.max_events.offset == 60
    )
    assert b.Event.data.offset == 120 and b.Event.ret.offset == 112
    assert b.Counters.unmatched_exit.offset == 88
    assert b.MAPS["pending"] == (1, 8, 376, 2)


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor_tgid", 12),
        ("server_tgid", 1),
        ("user_hz", 1000),
        ("max_events", 17),
        ("pidns_inode", 43),
        ("started_ns", True),
        ("deadline_ns", 49),
        ("actor_start_ticks", 0),
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
        return {k: k for k in b.MAPS}, {"copy_entry": 24, "copy_exit": 25}

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
        if self.mode == "lost" and identity["attach_type"] == 24:
            return "lost"
        if self.mode == "unknown" and identity["attach_type"] == 25:
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
        value.entered_ns = 100
        value.exited_ns = 110
        value.chunk = 1
        value.ret = 1
        value.data[0] = 65
        return value

    def destroy(self, p):
        self.destroyed.append(p)
        return -1 if self.mode == "destroy_error" and p == 24 else 0

    def next(self, *a):
        C.set_errno(errno.ENOENT)
        return -1


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
    assert native.attached == [25, 24] and native.destroyed == [24, 25, "object"]
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
        [24] if mode == "lost" else [25] if mode == "unknown" else []
    )


def graph(profile="old"):
    """Explicit synthetic native64 graph; not a kernel availability claim."""
    rows = []

    def add(kind, **kw):
        rows.append(dict(id=len(rows) + 1, kind=kind, **kw))
        return len(rows)

    def integer(name, size, encoding):
        return add(
            "INT",
            name=name,
            size=size,
            nr_bits=size * 8,
            bits_offset=0,
            encoding=encoding,
        )

    i = integer("int", 4, "SIGNED")
    u = integer("unsigned int", 4, "(none)")
    u64 = integer("long unsigned int", 8, "(none)")
    s64 = integer("long int", 8, "SIGNED")
    u8 = integer("unsigned char", 1, "(none)")
    boolean = integer("_Bool", 1, "BOOL")
    char = integer("char", 1, "(none)")

    def aggregate(name, kind="STRUCT", size=128):
        return add(kind, name=name, size=size, vlen=0, members=[])

    def setmembers(key, items):
        r = rows[key - 1]
        r["members"] = [dict(name=n, type_id=t, bits_offset=o) for n, t, o in items]
        r["vlen"] = len(items)

    def ptr(key):
        return add("PTR", type_id=key)

    void = ptr(0)
    names = [
        "sk_buff",
        "unix_stream_read_state",
        "socket",
        "msghdr",
        "pipe_inode_info",
        "iovec",
        "kvec",
        "bio_vec",
        "folio_queue",
        "xarray",
        "file",
        "inode",
        "super_block",
        "sock",
        "sock_common",
        "possible_net_t",
        "net",
        "ns_common",
        "unix_sock",
        "path",
        "dentry",
        "task_struct",
        "cred",
        "kuid_t",
    ]
    ids = {n: aggregate(n) for n in names}
    p = {n: ptr(k) for n, k in ids.items()}

    def fields(name, items, size=None):
        setmembers(ids[name], [(n, t, o) for n, t, o in items])
        if size is not None:
            rows[ids[name] - 1]["size"] = size

    fields("iovec", [("iov_base", void, 0), ("iov_len", u64, 64)], 16)
    viewnames = (
        ["__iov", "kvec", "bvec"]
        + (["folioq"] if profile == "new" else [])
        + ["xarray", "ubuf"]
    )
    view = aggregate("(anon)", "UNION", 8)
    setmembers(
        view,
        [
            (
                n,
                {
                    "__iov": p["iovec"],
                    "kvec": p["kvec"],
                    "bvec": p["bio_vec"],
                    "folioq": p["folio_queue"],
                    "xarray": p["xarray"],
                    "ubuf": void,
                }[n],
                0,
            )
            for n in viewnames
        ],
    )
    count = aggregate("(anon)", size=16)
    setmembers(count, [("(anon)", view, 0), ("count", u64, 64)])
    overlay = aggregate("(anon)", "UNION", 16)
    setmembers(overlay, [("__ubuf_iovec", ids["iovec"], 0), ("(anon)", count, 0)])
    tail = aggregate("(anon)", "UNION", 8)
    setmembers(
        tail,
        [("nr_segs", u64, 0)]
        + ([("folioq_slot", u8, 0)] if profile == "new" else [])
        + [("xarray_start", s64, 0)],
    )
    it = aggregate("iov_iter", size=40)
    setmembers(
        it,
        [
            ("iter_type", u8, 0),
            ("nofault", boolean, 8),
            ("data_source", boolean, 16),
            ("iov_offset", u64, 64),
            ("(anon)", overlay, 128),
            ("(anon)", tail, 256),
        ],
    )
    add(
        "ENUM",
        name="iter_type",
        size=4,
        vlen=2,
        values=[dict(name="ITER_UBUF", val=0), dict(name="ITER_IOVEC", val=1)],
    )
    fields("msghdr", [("msg_iter", it, 0)])
    cbarray = add("ARRAY", type_id=char, index_type_id=i, nr_elems=48)
    fields(
        "sk_buff",
        [
            ("len", u, 0),
            ("data_len", u, 32),
            ("data", ptr(u8), 64),
            ("cb", cbarray, 128),
        ],
    )
    parms = aggregate("unix_skb_parms", size=32)
    setmembers(parms, [("consumed", u, 224)])
    fields("socket", [("sk", p["sock"], 0), ("file", p["file"], 64)])
    fields("file", [("f_inode", p["inode"], 0)])
    fields("inode", [("i_ino", u64, 0), ("i_sb", p["super_block"], 64)])
    fields("super_block", [("s_dev", u, 0)])
    fields(
        "sock",
        [
            ("sk_type", integer("short unsigned int", 2, "(none)"), 0),
            ("sk_socket", p["socket"], 64),
            ("__sk_common", ids["sock_common"], 128),
        ],
    )
    fields(
        "sock_common",
        [
            ("skc_family", integer("short unsigned int", 2, "(none)"), 0),
            ("skc_net", ids["possible_net_t"], 64),
        ],
    )
    fields("possible_net_t", [("net", p["net"], 0)])
    fields("net", [("ns", ids["ns_common"], 0)])
    fields("ns_common", [("inum", u, 0)])
    fields("unix_sock", [("peer", p["sock"], 0), ("path", ids["path"], 64)])
    fields("path", [("dentry", p["dentry"], 0)])
    fields("dentry", [("d_inode", p["inode"], 0)])
    fields(
        "task_struct",
        [
            ("group_leader", p["task_struct"], 0),
            ("start_boottime", u64, 64),
            ("cred", p["cred"], 128),
        ],
    )
    fields("cred", [("uid", ids["kuid_t"], 0), ("euid", ids["kuid_t"], 32)])
    fields("kuid_t", [("val", u, 0)], 4)

    def proto(names):
        return add(
            "FUNC_PROTO",
            vlen=4,
            ret_type_id=i,
            params=[
                dict(name=n, type_id=t)
                for n, t in zip(
                    names, [p["sk_buff"], i, i, p["unix_stream_read_state"]]
                )
            ],
        )

    callback = proto(["(anon)"] * 4)
    fields(
        "unix_stream_read_state",
        [
            ("recv_actor", ptr(callback), 0),
            ("socket", p["socket"], 64),
            ("msg", p["msghdr"], 128),
            ("pipe", p["pipe_inode_info"], 192),
            ("size", u64, 256),
            ("flags", i, 320),
            ("splice_flags", u, 352),
        ],
        48,
    )
    add(
        "FUNC",
        name="unix_stream_read_actor",
        type_id=proto(["skb", "skip", "chunk", "state"]),
    )
    return dict(types=rows)


@pytest.mark.parametrize("profile", ["old", "new"])
def test_exact_known_iterator_profiles(profile):
    result = b.validate_kernel_prototype(json.dumps(graph(profile)).encode())
    assert result["iterator_profile"] == (
        "iov_iter_6_8" if profile == "old" else "iov_iter_7_0"
    )


@pytest.mark.parametrize(
    "fault",
    [
        "extraarg",
        "reordered",
        "return",
        "callback",
        "state_size",
        "state_offset",
        "bool_offset",
        "consumed_range",
        "consumed_signed",
        "cb_array",
        "iter_enum",
        "iter_bool",
        "count_offset",
        "count_direct",
        "count_union_size",
        "view_extra",
        "tail_wrong",
        "missing_peer",
        "missing_member",
        "duplicate_function",
        "cycle",
        "unknown_anon",
    ],
)
def test_changed_or_ambiguous_btf_refuses(fault):
    value = graph()
    rows = value["types"]
    by = {r.get("name"): r for r in rows if r["kind"] == "STRUCT"}
    function = rows[-1]
    proto = rows[function["type_id"] - 1]
    state = by["unix_stream_read_state"]
    it = by["iov_iter"]
    if fault == "extraarg":
        proto["params"].append(proto["params"][0])
        proto["vlen"] = 5
    elif fault == "reordered":
        proto["params"][0], proto["params"][1] = proto["params"][1], proto["params"][0]
    elif fault == "return":
        proto["ret_type_id"] = 0
    elif fault == "callback":
        rows[rows[state["members"][0]["type_id"] - 1]["type_id"] - 1]["vlen"] = 3
    elif fault == "state_size":
        state["size"] = 49
    elif fault == "state_offset":
        state["members"][1]["bits_offset"] = 65
    elif fault == "bool_offset":
        state["members"][1]["bits_offset"] = True
    elif fault == "consumed_range":
        by["unix_skb_parms"]["members"][0]["bits_offset"] = 256
    elif fault == "consumed_signed":
        by["unix_skb_parms"]["members"][0]["type_id"] = 1
    elif fault == "cb_array":
        next(r for r in rows if r["kind"] == "ARRAY")["nr_elems"] = 47
    elif fault == "iter_enum":
        next(r for r in rows if r["kind"] == "ENUM")["values"][0]["val"] = True
    elif fault == "iter_bool":
        it["members"][2]["type_id"] = it["members"][0]["type_id"]
    elif fault in (
        "count_offset",
        "count_direct",
        "count_union_size",
        "view_extra",
        "unknown_anon",
    ):
        outer = rows[it["members"][4]["type_id"] - 1]
        nested = rows[outer["members"][1]["type_id"] - 1]
        if fault == "count_offset":
            nested["members"][1]["bits_offset"] = 0
        elif fault == "count_direct":
            it["members"][4]["name"] = "count"
        elif fault == "count_union_size":
            outer["size"] = 24
        elif fault == "unknown_anon":
            outer["name"] = "guess"
        else:
            rows[nested["members"][0]["type_id"] - 1]["members"].append(
                dict(name="foreign", type_id=1, bits_offset=0)
            )
    elif fault == "tail_wrong":
        rows[it["members"][5]["type_id"] - 1]["members"].append(
            dict(name="folioq_slot", type_id=5, bits_offset=0)
        )
    elif fault == "missing_peer":
        by["unix_sock"]["members"].pop(0)
    elif fault == "missing_member":
        by["task_struct"]["members"].pop()
    elif fault == "duplicate_function":
        rows.append(dict(function, id=len(rows) + 1))
    elif fault == "cycle":
        rows[proto["params"][0]["type_id"] - 1].update(
            kind="TYPEDEF", type_id=proto["params"][0]["type_id"]
        )
    with pytest.raises(b.PostconnectCopyBPFError):
        b.validate_kernel_prototype(json.dumps(value).encode())


@pytest.mark.parametrize(
    "rc,error,expected",
    [
        (0, 0, "value"),
        (-1, errno.ENOENT, "vacant"),
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
        with pytest.raises(b.PostconnectCopyBPFError):
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
        next(r for r in maps if r["name"] == "pending")["shape"] = (1, 8, 376, 64)
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
        with pytest.raises(b.PostconnectCopyBPFError):
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


def test_fault_worker_resolves_loaded_map_and_waits_for_both_original_frames():
    """Execute only the real fault-shim class with SYNTHETIC libbpf; no actor/load."""
    import ast
    from test_postconnect_refusal_linux import SENSOR

    request = b'{"action":"sot_devices_patch","params":{"devices":"not-a-list"}}\n'
    response = b'{"ok":false,"error":"devices_must_be_list","ts":1.0}\n'
    state = dict(loaded=False, rows=[None, None], fd_calls=[], closed=[])

    class Base:
        def __init__(self):
            self.lib = SimpleNamespace(bpf_map__fd=self.fd)

        def fd(self, ptr):
            assert state["loaded"] is True and ptr == 101
            state["fd_calls"].append(ptr)
            return 1001

        def inspect(self, obj):
            return {"events": 101}, {"copy_entry": 24, "copy_exit": 25}

        def lookup_optional(self, fd, key, value):
            assert fd == 1001
            return state["rows"][key.value]

        def check_link(self, identity):
            return "retained"

    control = dict(closed_own_link=False)
    namespace = dict(
        b=SimpleNamespace(_Libbpf=Base, Event=b.Event),
        ctypes=C,
        control=control,
        fault_request=request.decode(),
        fault_configuration=dict(server_tgid=12, actor_tgid=13),
        os=SimpleNamespace(close=lambda fd: state["closed"].append(fd)),
        json=json,
    )
    tree = ast.parse(SENSOR)
    cls = next(
        n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "Fault"
    )
    exec(
        compile(
            ast.Module(body=[cls], type_ignores=[]), "<actual fault class>", "exec"
        ),
        namespace,
    )
    shim = namespace["Fault"]()
    shim.inspect(1)
    assert state["fd_calls"] == []  # Inspect is BEFORE load; no FD(-1) caching.
    state["loaded"] = True
    identity = dict(fd=25, attach_type=25)
    assert shim.check_link(identity) == "retained" and state["closed"] == []

    def row(role, data, entered, exited):
        e = b.Event(
            role=role,
            tgid=12 + role,
            tid=12 + role,
            entered_ns=entered,
            exited_ns=exited,
            receiver_inode=100 + role,
            peer_inode=101 - role,
            chunk=len(data),
            ret=len(data),
            skb_len=len(data),
        )
        e.data[: len(data)] = data
        return e

    state["rows"][0] = row(0, request, 10, 11)
    shim.check_link(identity)
    assert state["closed"] == []  # Request alone is not the required fault fence.
    state["rows"][1] = row(1, response, 12, 13)
    shim.check_link(dict(fd=24, attach_type=24))
    assert state["closed"] == []  # Only the original EXIT link may be closed.
    state["rows"][1].tgid = 99
    shim.check_link(identity)
    assert state["closed"] == []
    state["rows"][1].tgid = 13
    shim.check_link(identity)
    assert state["closed"] == [25] and control["closed_own_link"] is True
    calls = list(state["fd_calls"])
    shim.check_link(identity)
    assert state["closed"] == [25] and state["fd_calls"] == calls
