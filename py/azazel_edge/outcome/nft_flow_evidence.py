"""Strict data-only interpretation of native owned nft flow-limit evidence."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import shlex
from collections.abc import Mapping, Sequence

QUERY = ("nft", "-j", "list", "chain", "inet", "azazel_edge", "throttle")
SCOPE_KIND = "nft_flow_limit"
UNKNOWN_SCOPE = "unverified_throttle"
_OWNER = re.compile(r"azazel-edge:release-[A-Za-z0-9:-]+\Z", re.ASCII)
_TASK = re.compile(r"release-[0-9a-f]{16}\Z", re.ASCII)


def owner_token(value):
    # Historical rendered argv can retain nft's own quoted comment after the
    # shell-quoting layer is parsed. Decode only a complete JSON string token.
    if type(value) is str and value.startswith('"'):
        value = json.loads(value)
    if type(value) is not str or len(value) > 96 or not _OWNER.fullmatch(value):
        raise ValueError("invalid nft owner token")
    return value


def _one(values):
    if (
        not isinstance(values, Sequence)
        or isinstance(values, (str, bytes))
        or len(values) != 1
        or type(values[0]) is not str
    ):
        raise ValueError("exactly one grounded command required")
    if len(values[0]) > 4096:
        raise ValueError("command evidence bound")
    return shlex.split(values[0])


def _positive(value):
    if (
        type(value) is not str
        or re.fullmatch(r"[1-9][0-9]{0,9}", value) is None
        or int(value) > 2**32 - 1
    ):
        raise ValueError("native bounded positive integer required")
    return int(value)


def _task(trace, resource):
    if type(trace) is not str or not 0 < len(trace) <= 256:
        raise ValueError("provider trace required")
    value = 0xCBF29CE484222325
    for byte in f"{trace}|throttle|{resource}".encode():
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"release-{value:016x}"


def _address(value):
    if type(value) is not str:
        raise ValueError("literal IP address required")
    address = ipaddress.ip_address(value)
    if getattr(address, "scope_id", None) is not None:
        raise ValueError("scoped IPv6 address is not a native flow literal")
    return address


def flow_scope(commands, rollback, metadata, trace, *, normalized=None):
    parts = _one(commands)
    if len(parts) != 26 or parts[:6] != [
        "nft",
        "insert",
        "rule",
        "inet",
        "azazel_edge",
        "throttle",
    ]:
        raise ValueError("unsupported native flow-limit plan")
    family = parts[6]
    if (
        family not in ("ip", "ip6")
        or parts[7] != "saddr"
        or parts[9:11] != [family, "daddr"]
    ):
        raise ValueError("complete address selectors required")
    source, destination = (
        _address(parts[8]),
        _address(parts[11]),
    )
    if source.version != destination.version or family != (
        "ip" if source.version == 4 else "ip6"
    ):
        raise ValueError("address family mismatch")
    if parts[12] in ("tcp", "udp") and parts[13] == "dport":
        protocol = parts[12]
        port = _positive(parts[14])
        if port > 65535:
            raise ValueError("port out of range")
    elif parts[12:14] == ["meta", "l4proto"] and parts[14] in ("icmp", "ipv6-icmp"):
        protocol = parts[14]
        port = 0
        if (protocol == "icmp") != (source.version == 4):
            raise ValueError("ICMP family mismatch")
    else:
        raise ValueError("explicit supported protocol required")
    if (
        parts[15:18] != ["limit", "rate", "over"]
        or parts[19:21] != ["kbytes/second", "burst"]
        or parts[22:25] != ["kbytes", "drop", "comment"]
    ):
        raise ValueError("exact inverted byte-limit/drop plan required")
    rate, burst = _positive(parts[18]), _positive(parts[21])
    owner = owner_token(parts[25])
    if not isinstance(metadata, Mapping):
        raise ValueError("release metadata required")
    resource = f"nft:inet:azazel_edge:throttle:{parts[8]}>{parts[11]}:{protocol}:{port}"
    task = metadata.get("release_task_id")
    due = metadata.get("release_due_epoch")
    if (
        type(task) is not str
        or not _TASK.fullmatch(task)
        or task != _task(trace, resource)
        or metadata.get("release_owner_token") != owner
        or owner != "azazel-edge:" + task
        or metadata.get("release_resource_key") != resource
        or metadata.get("release_tc_handle") != ""
        or metadata.get("release_ledger_state")
        not in ("active", "prepared", "uncertain", "planned_only")
        or type(due) not in (int, float)
        or not math.isfinite(due)
        or due < 0
    ):
        raise ValueError("owner/task/resource metadata mismatch")
    if _one(rollback) != [
        "nft",
        "delete",
        "rule",
        "inet",
        "azazel_edge",
        "throttle",
        "handle",
        f"<owned:{owner}>",
    ]:
        raise ValueError("owned rollback binding mismatch")
    if normalized is not None:
        aliases = {"icmpv6": "ipv6-icmp", "icmp6": "ipv6-icmp"}
        actual_protocol = str(normalized.get("protocol", "")).lower()
        actual_protocol = aliases.get(actual_protocol, actual_protocol)
        if (
            _ip(normalized.get("src_ip")) != str(source)
            or _ip(normalized.get("dst_ip")) != str(destination)
            or actual_protocol != protocol
            or (
                port
                and (
                    type(normalized.get("target_port")) is not int
                    or normalized["target_port"] != port
                )
            )
        ):
            raise ValueError("requested selectors disagree with normalized event")
    return dict(
        scope_kind=SCOPE_KIND,
        family=family,
        source_ip=str(source),
        destination_ip=str(destination),
        protocol=protocol,
        destination_port=port,
        rate_bytes_per_second=rate * 1024,
        burst_bytes=burst * 1024,
        owner_token=owner,
        release_task_id=task,
        release_resource_key=resource,
    )


def legacy_tbf_interface(commands):
    parts = _one(commands)
    if (
        len(parts) < 7
        or parts[:4] != ["tc", "qdisc", "replace", "dev"]
        or parts[5] != "root"
        or re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", parts[4]) is None
    ):
        raise ValueError("not a legacy root TBF plan")
    tail = parts[6:]
    if tail[:1] == ["handle"]:
        if (
            len(tail) < 3
            or re.fullmatch(r"[0-9a-fA-F]{1,4}:", tail[1]) is None
            or int(tail[1][:-1], 16) == 0
        ):
            raise ValueError("invalid legacy handle")
        tail = tail[2:]
    if len(tail) != 7 or (tail[0], tail[1], tail[3], tail[5]) != (
        "tbf",
        "rate",
        "burst",
        "latency",
    ):
        raise ValueError("not an exact legacy TBF plan")
    return parts[4]


def _ip(value):
    if type(value) is not str:
        raise ValueError("literal IP readback required")
    return str(_address(value))


def _match(expression, selector):
    if type(expression) is not dict or set(expression) != {"match"}:
        raise ValueError("unknown or reordered match expression")
    value = expression["match"]
    if (
        type(value) is not dict
        or set(value) != {"op", "left", "right"}
        or value["op"] != "=="
        or value["left"] != selector
    ):
        raise ValueError("unsupported or reordered selector")
    return value["right"]


def parse_readback(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate nft JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite nft JSON")

    def floating(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite nft JSON")
        return result

    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=floating
    )


def readback_matches(payload, scope):
    if (
        type(payload) is not dict
        or set(payload) != {"nftables"}
        or type(payload["nftables"]) is not list
        or len(payload["nftables"]) > 4096
    ):
        raise ValueError("bounded complete nft JSON required")
    chains = []
    owned = []
    handles = set()
    for entry in payload["nftables"]:
        if type(entry) is not dict or len(entry) != 1:
            raise ValueError("ambiguous nft entry")
        if "metainfo" in entry:
            if type(entry["metainfo"]) is not dict:
                raise ValueError("malformed nft metadata")
            continue
        if "chain" in entry:
            chain = entry["chain"]
            if type(chain) is not dict:
                raise ValueError("malformed chain")
            if set(chain) - {
                "family",
                "table",
                "name",
                "handle",
                "type",
                "hook",
                "prio",
                "policy",
                "flags",
            }:
                raise ValueError("unknown chain layout")
            chains.append(chain)
        elif "rule" in entry:
            rule = entry["rule"]
            if type(rule) is not dict or any(
                rule.get(k) != v
                for k, v in (
                    ("family", "inet"),
                    ("table", "azazel_edge"),
                    ("chain", "throttle"),
                )
            ):
                raise ValueError("readback contains another chain")
            handle = rule.get("handle")
            if type(handle) is not int or handle <= 0 or handle in handles:
                raise ValueError("ambiguous rule identity")
            handles.add(handle)
            if rule.get("comment") == scope["owner_token"]:
                if set(rule) - {
                    "family",
                    "table",
                    "chain",
                    "handle",
                    "expr",
                    "comment",
                }:
                    raise ValueError("unknown owned rule layout")
                owned.append(rule)
        else:
            raise ValueError("unknown nft entry")
    if len(chains) != 1:
        raise ValueError("one complete chain header required")
    chain = chains[0]
    if (
        any(
            chain.get(k) != v
            for k, v in (
                ("family", "inet"),
                ("table", "azazel_edge"),
                ("name", "throttle"),
                ("type", "filter"),
                ("hook", "prerouting"),
                ("policy", "accept"),
            )
        )
        or type(chain.get("prio")) is not int
        or chain["prio"] != -150
        or chain.get("flags", []) != []
        or type(chain.get("handle")) is not int
        or chain["handle"] <= 0
    ):
        raise ValueError("wrong or unverifiable chain attachment")
    if len(owned) > 1:
        raise ValueError("duplicate owned rules")
    if not owned:
        return False
    rule = owned[0]
    if type(rule.get("handle")) is not int or rule["handle"] <= 0:
        raise ValueError("owned rule handle unavailable")
    expr = rule.get("expr")
    if type(expr) is not list or len(expr) != 5:
        raise ValueError("extra or missing owned expressions")
    family = scope["family"]
    source = _ip(_match(expr[0], {"payload": {"protocol": family, "field": "saddr"}}))
    destination = _ip(
        _match(expr[1], {"payload": {"protocol": family, "field": "daddr"}})
    )
    proto = scope["protocol"]
    if proto in ("tcp", "udp"):
        port = _match(expr[2], {"payload": {"protocol": proto, "field": "dport"}})
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("literal port required")
        protocol_matches = port == scope["destination_port"]
    else:
        protocol = _match(expr[2], {"meta": {"key": "l4proto"}})
        if type(protocol) is not str or protocol not in ("icmp", "ipv6-icmp"):
            raise ValueError("literal ICMP protocol required")
        protocol_matches = protocol == proto
    if (
        type(expr[3]) is not dict
        or set(expr[3]) != {"limit"}
        or expr[4] != {"drop": None}
    ):
        raise ValueError("wrong expression order or verdict")
    limit = expr[3]["limit"]
    if type(limit) is not dict or set(limit) != {
        "rate",
        "rate_unit",
        "burst",
        "burst_unit",
        "per",
        "inv",
    }:
        raise ValueError("complete unambiguous byte limit required")
    if (
        type(limit["rate"]) is not int
        or type(limit["burst"]) is not int
        or min(limit["rate"], limit["burst"]) <= 0
    ):
        raise ValueError("positive integer byte limit required")
    units = {"bytes": 1, "kbytes": 1024, "mbytes": 1024 * 1024}
    if (
        limit["rate_unit"] not in units
        or limit["burst_unit"] not in units
        or type(limit["inv"]) is not bool
    ):
        raise ValueError("unknown byte limit units")
    return (
        source == scope["source_ip"]
        and destination == scope["destination_ip"]
        and protocol_matches
        and limit["per"] == "second"
        and limit["inv"] is True
        and limit["rate"] * units[limit["rate_unit"]] == scope["rate_bytes_per_second"]
        and limit["burst"] * units[limit["burst_unit"]] == scope["burst_bytes"]
    )
