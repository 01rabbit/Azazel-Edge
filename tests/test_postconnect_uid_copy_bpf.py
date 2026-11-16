"""SYNTHETIC FFI/BTF only; no actual kernel load or measurement."""

import ctypes as C
import errno
import hashlib
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark import postconnect_uid_copy_bpf as b
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
    assert tuple(map(C.sizeof, (b.Configuration, b.Event, b.Counters))) == (72, 376, 96)
    assert (
        b.Configuration.server_tgid.offset == 48
        and b.Configuration.max_events.offset == 60
    )
    assert (
        b.Configuration.server_uid.offset == 64
        and b.Configuration.actor_uid.offset == 68
    )
    assert b.MAPS["config"] == (2, 4, 72, 1)
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
    assert result["schema_version"] == "edge-postconnect-uid-copy-probe/v1"
    assert (
        result["configuration"]["server_uid"]
        == result["configuration"]["actor_uid"]
        == 65534
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
        with pytest.raises(b.PostconnectUIDCopyBPFError):
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
        next(r for r in maps if r["name"] == "pending")["shape"] = (1, 8, 376, 64)
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
        with pytest.raises(b.PostconnectUIDCopyBPFError):
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


def test_explicit_source_schema_and_shared_checked_btf_validator():
    from azazel_edge.benchmark import postconnect_copy_bpf as old

    assert b.validate_kernel_prototype is old.validate_kernel_prototype
    assert b.SOURCE.name == "postconnect_uid_copy_observer.bpf.c"
    raw = b.SOURCE.read_text()
    assert "c->server_uid!=65534||c->actor_uid!=65534" in raw
    assert "e->uid!=(role==0?c->server_uid:c->actor_uid)" in raw
    assert "e->euid!=(role==0?c->server_uid:c->actor_uid)" in raw


def test_old_configuration_cannot_be_implicitly_reinterpreted(monkeypatch, tmp_path):
    environment(monkeypatch, tmp_path)
    cfg = configuration()
    cfg.pop("server_uid")
    cfg.pop("actor_uid")
    with pytest.raises(ValueError):
        b._configuration(cfg)
