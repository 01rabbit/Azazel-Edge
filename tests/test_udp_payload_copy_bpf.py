"""SYNTHETIC libbpf/clock/role boundaries, real backend ABI and orchestration.

These tests execute no BPF instructions and establish no kernel copy observation.
Actual attachment, packet, iterator and syscall controls belong to Linux tests.
"""

from copy import deepcopy
import ctypes as C
import errno
import socket
import struct
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark import udp_payload_copy_bpf as b


MAPS = {
    "config": (2, 4, 152, 1),
    "pending": (1, 16, 160, 64),
    "events": (2, 4, 160, 16),
    "stats": (2, 4, 48, 1),
}
PROGRAMS = {
    "copy_entry": ("fentry/udp_recvmsg", 26, 24),
    "copy_consume": ("fentry/skb_consume_udp", 26, 24),
    "copy_exit": ("fexit/udp_recvmsg", 26, 25),
}
START, END = 1_000_000_000, 1_100_000_000


def configuration():
    return dict(
        socket_inode=100,
        socket_cookie=200,
        netns_cookie=300,
        netns_inode=400,
        socket_uid=61002,
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=40001,
        dst_port=18080,
        payload_hex=bytes(range(64)).hex(),
        started_ns=START,
        deadline_ns=END,
        max_events=16,
        pidns_device=4,
        pidns_inode=500,
    )


def object_bytes():
    raw = bytearray(64)
    raw[:6] = b"\x7fELF\x02\x01"
    raw[18:20] = b"\xf7\x00"
    return bytes(raw)


def event(config):
    row = b.Event()
    for key in (
        "socket_inode",
        "socket_cookie",
        "netns_cookie",
        "netns_inode",
        "socket_uid",
        "src_port",
        "dst_port",
    ):
        setattr(row, key, config[key])
    row.entered_ns, row.consumed_ns, row.exited_ns = START + 1, START + 2, START + 3
    row.receiver_real_uid = row.receiver_effective_uid = config["socket_uid"]
    row.receiver_tgid, row.receiver_tid = 700, 701
    row.receiver_start_boottime_ns = 123456789
    for key in ("src_ip", "dst_ip"):
        setattr(row, key, struct.unpack("=I", socket.inet_aton(config[key]))[0])
    row.payload[:] = bytes.fromhex(config["payload_hex"])
    return row


class Library:
    """Owned fake handles only; full real inspect/lookup paths remain exercised."""

    def __init__(self):
        self.calls = []
        self.maps = dict(enumerate(MAPS, 10))
        self.programs = dict(enumerate(PROGRAMS, 20))
        self.map_specs, self.program_specs = dict(MAPS), dict(PROGRAMS)
        self.flags = 0
        self.load_rc = self.config_rc = 0
        self.fail_attach = None
        self.fail_destroy = set()
        self.raise_destroy = set()
        self.fail_close = False
        self.pending = 0
        self.enumeration_error = errno.ENOENT
        self.accepted, self.loss, self.overflow = 1, 0, 0
        self.rows = [event(configuration())]

    def libbpf_get_error(self, value):
        return 0

    def bpf_object__open_mem(self, raw, size, opts):
        assert C.string_at(raw, size) == object_bytes() and opts is None
        self.calls.append("open")
        return 1000

    def bpf_object__load(self, obj):
        self.calls.append("load")
        return self.load_rc

    @staticmethod
    def next_item(items, previous):
        keys = list(items)
        return (
            keys[0]
            if previous is None
            else (keys[keys.index(previous) + 1] if previous != keys[-1] else 0)
        )

    def bpf_object__next_map(self, obj, previous):
        return self.next_item(self.maps, previous)

    def bpf_object__next_program(self, obj, previous):
        return self.next_item(self.programs, previous)

    def bpf_map__name(self, item):
        return self.maps[item].encode()

    def bpf_map__map_flags(self, item):
        return self.flags

    def bpf_map__type(self, item):
        return self.map_specs[self.maps[item]][0]

    def bpf_map__key_size(self, item):
        return self.map_specs[self.maps[item]][1]

    def bpf_map__value_size(self, item):
        return self.map_specs[self.maps[item]][2]

    def bpf_map__max_entries(self, item):
        return self.map_specs[self.maps[item]][3]

    def bpf_map__fd(self, item):
        return item

    def bpf_program__name(self, item):
        return self.programs[item].encode()

    def bpf_program__section_name(self, item):
        return self.program_specs[self.programs[item]][0].encode()

    def bpf_program__type(self, item):
        return self.program_specs[self.programs[item]][1]

    def bpf_program__expected_attach_type(self, item):
        return self.program_specs[self.programs[item]][2]

    def bpf_map_update_elem(self, fd, key, value, flags):
        assert fd == 10 and C.cast(key, C.POINTER(C.c_uint32)).contents.value == 0
        self.calls.append(
            ("config", bytes(C.cast(value, C.POINTER(b.Configuration)).contents))
        )
        return self.config_rc

    def bpf_program__attach(self, program):
        name = self.programs[program]
        self.calls.append(("attach", name))
        return None if self.fail_attach == name else program * 10

    def bpf_link__disconnect(self, link):
        self.calls.append(("disconnect", link))

    def bpf_link__destroy(self, link):
        # Destroy consumes the pointer even on nonzero return; tests prohibit retry.
        assert ("destroy", link) not in self.calls
        self.calls.append(("destroy", link))
        if link in self.raise_destroy:
            raise OSError("synthetic destroy failure")
        return -1 if link in self.fail_destroy else 0

    def bpf_object__close(self, obj):
        self.calls.append(("close", obj))
        if self.fail_close:
            raise OSError("synthetic close failure")

    def bpf_map_lookup_elem(self, fd, key, out):
        # No own-map result may be read until every owned link was released.
        assert (
            len([x for x in self.calls if isinstance(x, tuple) and x[0] == "destroy"])
            == 3
        )
        self.calls.append(("lookup", fd))
        if fd == 13:
            value = b.Counters(1, 1, self.accepted, 0, self.loss, self.overflow)
        else:
            assert fd == 12
            index = C.cast(key, C.POINTER(C.c_uint32)).contents.value
            value = self.rows[index]
        C.memmove(out, C.byref(value), C.sizeof(value))
        return 0

    def bpf_map_get_next_key(self, fd, previous, out):
        assert fd == 11
        if self.pending and previous is None:
            C.memmove(out, C.byref(b.Invocation(1, 2)), C.sizeof(b.Invocation))
            return 0
        C.set_errno(self.enumeration_error)
        return -1


def install(monkeypatch, lib=None, states=None, identity_fault=None):
    lib = Library() if lib is None else lib
    backend = object.__new__(b._Libbpf)
    backend.lib = lib

    def identity(link, program, attach):
        value = dict(
            fd=link + 1000,
            type=2,
            link_id=link,
            prog_id=program,
            attach_type=attach,
            target_obj_id=1,
            target_btf_id=98 if program == 21 else 99,
        )
        if identity_fault == "outer" and program == 20:
            value["target_btf_id"] = 97
        if identity_fault == "consume" and program == 21:
            value["target_btf_id"] = 99
        return value

    backend.link_identity = identity
    backend.check_link = lambda value: (states or {}).get(value["link_id"], "retained")
    monkeypatch.setattr(b, "_Libbpf", lambda: backend)
    monkeypatch.setattr(b, "_role", lambda: lib.calls.append("role"))
    clock = SimpleNamespace(now=START)

    def sleep(seconds):
        assert 0 < seconds <= 0.01
        clock.now = END

    monkeypatch.setattr(
        b, "time", SimpleNamespace(monotonic_ns=lambda: clock.now, sleep=sleep)
    )
    return lib, clock


def capture():
    return b._capture_events(configuration(), object_bytes())


def test_frozen_abi_offsets_and_internal_key_do_not_export_cpu_or_pointers():
    assert tuple(
        C.sizeof(x) for x in (b.Configuration, b.Event, b.Invocation, b.Counters)
    ) == (152, 160, 16, 48)
    assert b.Configuration.pidns_device.offset == 48
    assert b.Configuration.payload.offset == 88
    assert b.Event.receiver_start_boottime_ns.offset == 56
    assert b.Event.receiver_tgid.offset == 76
    assert b.Event.payload.offset == 96
    assert [name for name, _ in b.Invocation._fields_] == ["pid_tgid", "sk"]
    assert b._MAPS == MAPS and b._PROGRAMS == PROGRAMS
    row = b._event(event(configuration()))
    assert row["receiver_tgid"] == 700 and row["receiver_tid"] == 701
    assert row["payload_hex"] == configuration()["payload_hex"]
    assert not {"sk", "skb", "pid_tgid", "cpu"} & row.keys()


def test_three_hook_order_single_config_and_final_reads_after_all_teardown(monkeypatch):
    lib, _ = install(monkeypatch)
    original = configuration()
    result = b._capture_events(original, object_bytes())
    assert original == configuration()
    assert [x for x in lib.calls if isinstance(x, tuple) and x[0] == "attach"] == [
        ("attach", "copy_exit"),
        ("attach", "copy_consume"),
        ("attach", "copy_entry"),
    ]
    assert [x for x in lib.calls if isinstance(x, tuple) and x[0] == "destroy"] == [
        ("destroy", 200),
        ("destroy", 210),
        ("destroy", 220),
    ]
    assert lib.calls.count(("close", 1000)) == 1
    assert len([x for x in lib.calls if isinstance(x, tuple) and x[0] == "config"]) == 1
    assert result["events"] == [b._event(lib.rows[0])]
    assert result["started_ns"] == START and result["finished_ns"] == END


@pytest.mark.parametrize(
    "fault",
    [
        "map-value",
        "map-flags",
        "missing-map",
        "extra-map",
        "wrong-section",
        "wrong-attach",
        "missing-program",
        "extra-program",
    ],
)
def test_unapproved_map_or_program_is_refused_before_kernel_load(monkeypatch, fault):
    lib, _ = install(monkeypatch)
    if fault == "map-value":
        lib.map_specs["events"] = (2, 4, 128, 16)
    elif fault == "map-flags":
        lib.flags = 1
    elif fault == "missing-map":
        del lib.maps[13]
    elif fault == "extra-map":
        lib.maps[14] = "foreign"
    elif fault == "wrong-section":
        lib.program_specs["copy_consume"] = ("fentry/udp_recvmsg", 26, 24)
    elif fault == "wrong-attach":
        lib.program_specs["copy_exit"] = ("fexit/udp_recvmsg", 26, 24)
    elif fault == "missing-program":
        del lib.programs[21]
    else:
        lib.programs[23] = "foreign"
    with pytest.raises(b.UDPPayloadCopyBPFError):
        capture()
    assert "load" not in lib.calls
    assert lib.calls.count(("close", 1000)) == 1


@pytest.mark.parametrize("name", ["copy_exit", "copy_consume", "copy_entry"])
def test_partial_attach_failure_releases_only_acquired_links_once(monkeypatch, name):
    lib, _ = install(monkeypatch)
    lib.fail_attach = name
    with pytest.raises(b.UDPPayloadCopyBPFError):
        capture()
    expected = {"copy_exit": [], "copy_consume": [220], "copy_entry": [210, 220]}[name]
    assert [
        x[1] for x in lib.calls if isinstance(x, tuple) and x[0] == "destroy"
    ] == expected
    assert lib.calls.count(("close", 1000)) == 1
    assert not any(isinstance(x, tuple) and x[0] == "lookup" for x in lib.calls)


@pytest.mark.parametrize("link", [200, 210, 220])
@pytest.mark.parametrize("raises", [False, True])
def test_destroy_failure_is_sticky_and_other_links_and_object_are_attempted(
    monkeypatch, link, raises
):
    lib, _ = install(monkeypatch)
    (lib.raise_destroy if raises else lib.fail_destroy).add(link)
    with pytest.raises(b.UDPPayloadCopyBPFError):
        capture()
    assert [x[1] for x in lib.calls if isinstance(x, tuple) and x[0] == "destroy"] == [
        200,
        210,
        220,
    ]
    assert lib.calls.count(("close", 1000)) == 1
    assert not any(isinstance(x, tuple) and x[0] == "lookup" for x in lib.calls)


@pytest.mark.parametrize("fault", ["outer", "consume"])
def test_actual_link_target_metadata_must_match_all_three_fixed_hooks(
    monkeypatch, fault
):
    lib, _ = install(monkeypatch, identity_fault=fault)
    with pytest.raises(b.UDPPayloadCopyBPFError):
        capture()
    assert [x[1] for x in lib.calls if isinstance(x, tuple) and x[0] == "destroy"] == [
        200,
        210,
        220,
    ]
    assert not any(isinstance(x, tuple) and x[0] == "lookup" for x in lib.calls)


@pytest.mark.parametrize("state", ["lost", "unknown"])
def test_lost_fd_is_disconnected_without_foreign_close_unknown_blocks_result(
    monkeypatch, state
):
    lib, _ = install(monkeypatch, states={210: state})
    if state == "unknown":
        with pytest.raises(b.UDPPayloadCopyBPFError):
            capture()
    else:
        result = capture()
        assert result["events"] and "observer_link_lost" in result["partial_reasons"]
    assert lib.calls.count(("disconnect", 210)) == 1
    assert lib.calls.index(("disconnect", 210)) < lib.calls.index(("destroy", 210))
    assert lib.calls.count(("close", 1000)) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "receiver-real",
        "receiver-effective",
        "receiver-tid",
        "receiver-start",
        "consume-before-entry",
        "exit-before-consume",
        "late",
        "payload",
        "socket",
    ],
)
def test_invalid_event_never_erases_earlier_bound_positive_or_becomes_a_positive(
    monkeypatch, fault
):
    lib, _ = install(monkeypatch)
    bad = event(configuration())
    if fault == "receiver-real":
        bad.receiver_real_uid += 1
    elif fault == "receiver-effective":
        bad.receiver_effective_uid += 1
    elif fault == "receiver-tid":
        bad.receiver_tid = 0
    elif fault == "receiver-start":
        bad.receiver_start_boottime_ns = 0
    elif fault == "consume-before-entry":
        bad.consumed_ns = START
    elif fault == "exit-before-consume":
        bad.exited_ns = START + 1
    elif fault == "late":
        bad.exited_ns = END + 1
    elif fault == "payload":
        bad.payload[0] ^= 1
    else:
        bad.socket_cookie += 1
    lib.accepted, lib.rows, lib.pending, lib.overflow = 2, [lib.rows[0], bad], 1, 1
    result = capture()
    assert result["events"] == [b._event(lib.rows[0])]
    assert result["counters"]["correlation_loss"] == 2
    assert {"correlation_loss", "event_overflow"} <= set(result["partial_reasons"])


@pytest.mark.parametrize("failure", [OSError, b.old.UDPQueueBPFError])
def test_later_unavailable_slot_preserves_already_verified_positive(
    monkeypatch, failure
):
    lib, _ = install(monkeypatch)
    lib.accepted = 2
    original = lib.bpf_map_lookup_elem

    def lookup(fd, key, out):
        if fd == 12 and C.cast(key, C.POINTER(C.c_uint32)).contents.value == 1:
            raise failure("synthetic later own-map slot unavailable")
        return original(fd, key, out)

    lib.bpf_map_lookup_elem = lookup
    result = capture()
    assert result["events"] == [b._event(lib.rows[0])]
    assert result["counters"]["correlation_loss"] == 1
    assert "correlation_loss" in result["partial_reasons"]
    assert lib.calls[-1] == ("close", 1000)


def test_valid_positive_cannot_hide_object_cleanup_failure(monkeypatch):
    lib, _ = install(monkeypatch)
    lib.fail_close = True
    with pytest.raises(b.UDPPayloadCopyBPFError, match="object close"):
        capture()
    assert lib.calls.count(("close", 1000)) == 1
    assert (
        len([x for x in lib.calls if isinstance(x, tuple) and x[0] == "destroy"]) == 3
    )


def test_role_alias_preserves_original_sensor_capability_restrictions(monkeypatch):
    assert b._role is b.old._role
    status = "Uid:\t0 0 0 0\nNoNewPrivs:\t1\nCapInh:\t0\nCapAmb:\t0\n"
    monkeypatch.setattr(b.old, "os", SimpleNamespace(geteuid=lambda: 0))
    monkeypatch.setattr(
        b.old, "sys", SimpleNamespace(platform="linux", byteorder="little")
    )
    for mask, accepted in (
        ((1 << 38) | (1 << 39), True),
        (0, False),
        ((1 << 38) | (1 << 39) | (1 << 21), False),
    ):
        raw = status + "".join(
            f"{key}:\t{mask:016x}\n" for key in ("CapEff", "CapPrm", "CapBnd")
        )
        monkeypatch.setattr(b.old, "_proc_bytes", lambda *args, raw=raw: raw.encode())
        if accepted:
            b._role()
        else:
            with pytest.raises(ValueError):
                b._role()


def test_expired_original_deadline_refuses_before_backend_creation(monkeypatch):
    lib, clock = install(monkeypatch)
    clock.now = END
    with pytest.raises(b.UDPPayloadCopyBPFError):
        capture()
    assert lib.calls == ["role"]


@pytest.mark.parametrize(
    "fault", ["bool-namespace", "negative-uid", "oversized-events", "extended-window"]
)
def test_configuration_is_strict_before_any_backend_action(monkeypatch, fault):
    lib, _ = install(monkeypatch)
    value = deepcopy(configuration())
    if fault == "bool-namespace":
        value["pidns_inode"] = True
    elif fault == "negative-uid":
        value["socket_uid"] = -1
    elif fault == "oversized-events":
        value["max_events"] = 17
    else:
        value["deadline_ns"] = START + 5_000_000_001
    with pytest.raises(ValueError):
        b._capture_events(value, object_bytes())
    assert lib.calls == []
