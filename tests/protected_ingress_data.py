"""Synthetic challenge/frame data only; public TEST key, no traffic or file writes."""

from copy import deepcopy
import hashlib
import ipaddress
import struct

from azazel_edge.outcome.journal import _json
from safety_observation_data import KEYS, frozen, wire, digest

KEY = KEYS[0]  # PUBLIC deterministic test seed, never actual enrollment.
BOOT = "00000000-0000-4000-8000-000000000001"
PAYLOAD = b"synthetic-ingress-challenge-1"


def make_inputs(
    namespace_device,
    namespace_inode,
    boot_id,
    source_port,
    destination_port,
    start_ns,
    end_ns,
    payload,
):
    contract = deepcopy(frozen()[0])
    contract["scope"]["kernel_boot_id"] = boot_id
    contract["scope"]["interval"] = dict(start_ns=start_ns, end_ns=end_ns)
    for descriptor in contract["channels"].values():
        descriptor["collector_boot_id"] = boot_id
    for category in contract["opportunities"]:
        if category != "protected_escape":
            contract["opportunities"][category] = []
    opportunity = contract["opportunities"]["protected_escape"][0]
    protected = dict(
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        protocol="UDP",
        src_port=source_port,
        dst_port=destination_port,
        namespace_device=namespace_device,
        namespace_inode=namespace_inode,
    )
    opportunity.update(
        start_ns=start_ns,
        end_ns=end_ns,
        challenge_sha256=hashlib.sha256(payload).hexdigest(),
        reference_sha256=digest(
            _json(
                dict(
                    observation_layer="interface_ingress",
                    interface="lo",
                    protected_tuple=protected,
                )
            )
        ),
        predicate=dict(protected_tuple=protected, forbidden_delivery=True),
    )
    contract_raw = wire(contract)
    plan = dict(
        schema_version="edge-protected-ingress-plan/v1",
        contract_sha256=digest(contract_raw),
        opportunity_id=opportunity["id"],
        interface="lo",
        observation_layer="interface_ingress",
        challenge_payload_hex=payload.hex(),
        max_packets=4,
        max_matches=1,
        max_duration_ns=min(end_ns - start_ns, 5_000_000_000),
    )
    plan_raw = wire(plan)
    return (
        contract_raw,
        plan_raw,
        dict(
            expected_contract_sha256=digest(contract_raw),
            expected_plan_sha256=digest(plan_raw),
        ),
    )


def ethernet_udp(payload=PAYLOAD, source_port=40001, destination_port=18080):
    """Complete Ethernet/IPv4/UDP bytes; checksum0 intentionally no validity claim."""
    ethernet = bytes(12) + struct.pack("!H", 0x0800)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + 8 + len(payload),
        1,
        0,
        64,
        17,
        0,
        ipaddress.ip_address("127.0.0.1").packed,
        ipaddress.ip_address("127.0.0.1").packed,
    )
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    return ethernet + ipv4 + udp + payload
