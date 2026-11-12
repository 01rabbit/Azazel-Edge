"""Root test-build selection from actual BTF; never used by runtime capture.

Only the two reviewed prototypes are supported. This is not a verifier-error
fallback and does not compile, attach, fetch or alter privileges itself.
"""

import json


class UDPPayloadCopyBuildError(ValueError):
    """Missing, malformed or unsupported kernel attachment prototype."""


def _need(condition, message):
    if not condition:
        raise UDPPayloadCopyBuildError(message)


def _integer(value):
    _need(type(value) is int and 0 < value <= 2**32 - 1, "positive BTF type ID")
    return value


def select_recvmsg_arguments(raw):
    """Return exact allowed argument count4/5 from bounded bpftool JSON bytes."""

    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "duplicate BTF JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise UDPPayloadCopyBuildError("nonfinite BTF JSON")

    try:
        _need(
            type(raw) is bytes and 0 < len(raw) <= 32 * 1024 * 1024,
            "BTF JSON byte bound",
        )
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
        _need(type(value) is dict and set(value) == {"types"}, "BTF JSON envelope")
        rows = value["types"]
        _need(type(rows) is list and 0 < len(rows) <= 250000, "BTF type count")
        types = {}
        for row in rows:
            _need(type(row) is dict, "BTF type record")
            identity = _integer(row.get("id"))
            _need(
                identity not in types and type(row.get("kind")) is str,
                "duplicate/malformed BTF type",
            )
            types[identity] = row

        def get(identity):
            _integer(identity)
            _need(identity in types, "BTF referenced type missing")
            return types[identity]

        def resolve(identity):
            seen = set()
            for _ in range(16):
                _need(identity not in seen, "cyclic BTF wrappers")
                seen.add(identity)
                row = get(identity)
                if row["kind"] not in ("TYPEDEF", "CONST", "VOLATILE", "RESTRICT"):
                    return row
                identity = row.get("type_id")
            raise UDPPayloadCopyBuildError("BTF wrapper depth")

        def integer(identity, signed, size):
            row = resolve(identity)
            _need(
                row["kind"] == "INT"
                and type(row.get("size")) is int
                and row["size"] == size
                and type(row.get("nr_bits")) is int
                and row["nr_bits"] == size * 8
                and type(row.get("bits_offset")) is int
                and row["bits_offset"] == 0
                and row.get("encoding") == ("SIGNED" if signed else "(none)"),
                "BTF integer type differs",
            )

        def pointer(identity, structure=None):
            row = resolve(identity)
            _need(row["kind"] == "PTR", "BTF pointer required")
            if structure is None:
                integer(row.get("type_id"), True, 4)
            else:
                target = resolve(row.get("type_id"))
                _need(
                    target["kind"] == "STRUCT" and target.get("name") == structure,
                    "BTF pointed structure differs",
                )

        def prototype(name, names):
            found = [
                row
                for row in rows
                if row.get("kind") == "FUNC" and row.get("name") == name
            ]
            _need(len(found) == 1, "unique fixed BTF function required")
            proto = get(found[0].get("type_id"))
            _need(
                proto["kind"] == "FUNC_PROTO" and type(proto.get("params")) is list,
                "BTF prototype required",
            )
            params = proto["params"]
            _need(
                type(proto.get("vlen")) is int
                and proto["vlen"] == len(params)
                and [row.get("name") if type(row) is dict else None for row in params]
                in names,
                "BTF parameter bindings differ",
            )
            return proto, params

        recv, params = prototype(
            "udp_recvmsg",
            [["sk", "msg", "len", "flags"], ["sk", "msg", "len", "flags", "addr_len"]],
        )
        integer(recv.get("ret_type_id"), True, 4)
        pointer(params[0].get("type_id"), "sock")
        pointer(params[1].get("type_id"), "msghdr")
        size = get(params[2].get("type_id"))
        _need(
            size["kind"] == "TYPEDEF" and size.get("name") == "size_t",
            "exact size_t binding required",
        )
        integer(size["id"], False, 8)
        integer(params[3].get("type_id"), True, 4)
        if len(params) == 5:
            pointer(params[4].get("type_id"))
        consume, cp = prototype("skb_consume_udp", [["sk", "skb", "len"]])
        _need(
            type(consume.get("ret_type_id")) is int and consume["ret_type_id"] == 0,
            "consume must return void",
        )
        pointer(cp[0].get("type_id"), "sock")
        pointer(cp[1].get("type_id"), "sk_buff")
        integer(cp[2].get("type_id"), True, 4)
        return len(params)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        if isinstance(exc, UDPPayloadCopyBuildError):
            raise
        raise UDPPayloadCopyBuildError("invalid BTF prototype data") from exc
