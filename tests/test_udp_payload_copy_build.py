"""SYNTHETIC bpftool JSON prototypes; no compile/attach or host BTF claims."""

from copy import deepcopy
import json
from unittest.mock import patch

import pytest
from udp_payload_copy_build import select_recvmsg_arguments, UDPPayloadCopyBuildError


def prototype(arguments=5):
    types = [
        dict(
            id=1,
            kind="INT",
            name="int",
            size=4,
            bits_offset=0,
            nr_bits=32,
            encoding="SIGNED",
        ),
        dict(
            id=2,
            kind="INT",
            name="long unsigned int",
            size=8,
            bits_offset=0,
            nr_bits=64,
            encoding="(none)",
        ),
        dict(id=3, kind="TYPEDEF", name="size_t", type_id=2),
        dict(id=4, kind="STRUCT", name="sock", size=128, vlen=0, members=[]),
        dict(id=5, kind="PTR", name="(anon)", type_id=4),
        dict(id=6, kind="STRUCT", name="msghdr", size=56, vlen=0, members=[]),
        dict(id=7, kind="PTR", name="(anon)", type_id=6),
        dict(id=8, kind="STRUCT", name="sk_buff", size=128, vlen=0, members=[]),
        dict(id=9, kind="PTR", name="(anon)", type_id=8),
        dict(id=10, kind="PTR", name="(anon)", type_id=1),
        dict(
            id=11,
            kind="FUNC_PROTO",
            name="(anon)",
            ret_type_id=1,
            vlen=arguments,
            params=[
                dict(name=name, type_id=kind)
                for name, kind in [
                    ("sk", 5),
                    ("msg", 7),
                    ("len", 3),
                    ("flags", 1),
                    ("addr_len", 10),
                ][:arguments]
            ],
        ),
        dict(id=12, kind="FUNC", name="udp_recvmsg", type_id=11, linkage="static"),
        dict(
            id=13,
            kind="FUNC_PROTO",
            name="(anon)",
            ret_type_id=0,
            vlen=3,
            params=[
                dict(name="sk", type_id=5),
                dict(name="skb", type_id=9),
                dict(name="len", type_id=1),
            ],
        ),
        dict(id=14, kind="FUNC", name="skb_consume_udp", type_id=13, linkage="static"),
    ]
    return dict(types=types)


def raw(value):
    # bpftool JSON is not a canonical journal wire, whitespace is permitted.
    return json.dumps(value, indent=2).encode()


def node(value, id):
    return next(row for row in value["types"] if row["id"] == id)


@pytest.mark.parametrize("arguments", [4, 5])
def test_only_frozen_recvmsg_argument_profiles(arguments):
    value = prototype(arguments)
    before = deepcopy(value)
    assert select_recvmsg_arguments(raw(value)) == arguments
    assert value == before


@pytest.mark.parametrize("kind", ["TYPEDEF", "CONST", "VOLATILE", "RESTRICT"])
def test_supported_unambiguous_qualifier_or_typedef_chain(kind):
    value = prototype()
    wrapper = dict(
        id=15,
        kind=kind,
        name="synthetic_alias" if kind == "TYPEDEF" else "(anon)",
        type_id=7,
    )
    value["types"].append(wrapper)
    node(value, 11)["params"][1]["type_id"] = 15
    assert select_recvmsg_arguments(raw(value)) == 5


@pytest.mark.parametrize(
    "kind",
    [
        "recv_count3",
        "recv_count6",
        "recv_return_unsigned",
        "recv_return_long",
        "recv_return_void",
        "sock_not_pointer",
        "sock_wrong_struct",
        "msg_wrong_struct",
        "len_not_size_t",
        "len_signed",
        "len_32bit",
        "flags_unsigned",
        "flags_pointer",
        "addr_not_int_pointer",
        "addr_unsigned_pointer",
        "consume_count",
        "consume_return",
        "consume_sock",
        "consume_skb",
        "consume_len",
        "recv_param_name",
        "consume_param_name",
        "not_proto",
        "missing_recv",
        "missing_consume",
        "duplicate_recv",
        "duplicate_consume",
        "duplicate_id",
        "bool_id",
        "unknown_type",
        "cycle",
        "qualifier_cycle",
        "unsupported_wrapper",
        "return_bool",
        "param_bool",
        "nonfunc_name",
    ],
)
def test_prototype_type_count_name_or_graph_ambiguity_refuses(kind):
    value = prototype()
    recv = node(value, 11)
    consume = node(value, 13)
    if kind == "recv_count3":
        recv["params"] = recv["params"][:3]
        recv["vlen"] = 3
    elif kind == "recv_count6":
        recv["params"].append(dict(name="extra", type_id=1))
        recv["vlen"] = 6
    elif kind == "recv_return_unsigned":
        recv["ret_type_id"] = 2
    elif kind == "recv_return_long":
        node(value, 1).update(size=8, nr_bits=64)
    elif kind == "recv_return_void":
        recv["ret_type_id"] = 0
    elif kind == "sock_not_pointer":
        recv["params"][0]["type_id"] = 4
    elif kind == "sock_wrong_struct":
        node(value, 4)["name"] = "socket"
    elif kind == "msg_wrong_struct":
        node(value, 6)["name"] = "user_msghdr"
    elif kind == "len_not_size_t":
        recv["params"][2]["type_id"] = 2
    elif kind == "len_signed":
        node(value, 3)["type_id"] = 1
    elif kind == "len_32bit":
        node(value, 2).update(size=4, nr_bits=32)
    elif kind == "flags_unsigned":
        recv["params"][3]["type_id"] = 2
    elif kind == "flags_pointer":
        recv["params"][3]["type_id"] = 10
    elif kind == "addr_not_int_pointer":
        recv["params"][4]["type_id"] = 1
    elif kind == "addr_unsigned_pointer":
        node(value, 10)["type_id"] = 2
    elif kind == "consume_count":
        consume["params"].pop()
        consume["vlen"] = 2
    elif kind == "consume_return":
        consume["ret_type_id"] = 1
    elif kind == "consume_sock":
        consume["params"][0]["type_id"] = 7
    elif kind == "consume_skb":
        consume["params"][1]["type_id"] = 5
    elif kind == "consume_len":
        consume["params"][2]["type_id"] = 2
    elif kind == "recv_param_name":
        recv["params"][0]["name"] = "not_sk"
    elif kind == "consume_param_name":
        consume["params"][2]["name"] = "copied"
    elif kind == "not_proto":
        node(value, 12)["type_id"] = 1
    elif kind == "missing_recv":
        value["types"].remove(node(value, 12))
    elif kind == "missing_consume":
        value["types"].remove(node(value, 14))
    elif kind in ("duplicate_recv", "duplicate_consume"):
        extra = deepcopy(node(value, 12 if kind == "duplicate_recv" else 14))
        extra["id"] = 15
        value["types"].append(extra)
    elif kind == "duplicate_id":
        value["types"].append(deepcopy(node(value, 1)))
    elif kind == "bool_id":
        node(value, 1)["id"] = True
    elif kind == "unknown_type":
        recv["params"][0]["type_id"] = 99999
    elif kind == "cycle":
        node(value, 3)["type_id"] = 3
    elif kind == "qualifier_cycle":
        value["types"].extend(
            [
                dict(id=15, kind="CONST", type_id=16),
                dict(id=16, kind="VOLATILE", type_id=15),
            ]
        )
        recv["params"][1]["type_id"] = 15
    elif kind == "unsupported_wrapper":
        value["types"].append(dict(id=15, kind="TYPE_TAG", name="unknown", type_id=7))
        recv["params"][1]["type_id"] = 15
    elif kind == "return_bool":
        recv["ret_type_id"] = True
    elif kind == "param_bool":
        recv["params"][0]["type_id"] = True
    else:
        node(value, 12)["kind"] = "VAR"
    with pytest.raises(UDPPayloadCopyBuildError):
        select_recvmsg_arguments(raw(value))


@pytest.mark.parametrize(
    "kind",
    [
        "missing_types",
        "types_not_list",
        "duplicate_json",
        "nonbytes",
        "invalid_json",
        "nonfinite",
        "oversize",
        "deep",
        "empty",
    ],
)
def test_original_btf_input_framing_and_bounds(kind):
    data = raw(prototype())
    if kind == "missing_types":
        data = b"{}"
    elif kind == "types_not_list":
        data = b'{"types":{}}'
    elif kind == "duplicate_json":
        data = b'{"types":[],"types":[]}'
    elif kind == "nonbytes":
        data = data.decode()
    elif kind == "invalid_json":
        data = data[:-1]
    elif kind == "nonfinite":
        data = b'{"types":[],"bad":NaN}'
    elif kind == "oversize":
        data = b" " * (32 * 1024 * 1024 + 1)
    elif kind == "deep":
        data = b'{"types":' + b"[" * 1001 + b"0" + b"]" * 1001 + b"}"
    else:
        data = b""
    with pytest.raises(UDPPayloadCopyBuildError):
        select_recvmsg_arguments(data)


def test_excessive_qualifier_chain_refuses_instead_of_unbounded_walk():
    value = prototype()
    for id in range(15, 80):
        value["types"].append(
            dict(id=id, kind="TYPEDEF", name="alias", type_id=id + 1 if id < 79 else 7)
        )
    node(value, 11)["params"][1]["type_id"] = 15
    with pytest.raises(UDPPayloadCopyBuildError):
        select_recvmsg_arguments(raw(value))


def test_selector_is_pure_and_original_raw_bytes_unchanged():
    data = raw(prototype(4))
    original = data
    with (
        patch("builtins.open", side_effect=AssertionError("I/O")),
        patch("os.open", side_effect=AssertionError("I/O")),
        patch("subprocess.Popen", side_effect=AssertionError("command")),
        patch("socket.socket", side_effect=AssertionError("network")),
    ):
        assert select_recvmsg_arguments(data) == 4
    assert data == original
