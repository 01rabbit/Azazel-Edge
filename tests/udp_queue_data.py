"""PUBLIC synthetic enrollment bytes only: no object, traffic, key files or capture."""

from copy import deepcopy

from azazel_edge.outcome.journal import _json
from safety_observation_data import KEYS, frozen, wire, digest

KEY = KEYS[0]  # PUBLIC deterministic TEST-ONLY seed; never production enrollment.
BOOT = "00000000-0000-4000-8000-000000000001"
PAYLOAD = b"synthetic-udp-queue-challenge-" + bytes(range(34))
assert len(PAYLOAD) == 64
TARGET = dict(
    pid=1234,
    start_ticks=100,
    uid=61003,
    fd=3,
    socket_inode=42042,
    socket_cookie=71,
    netns_cookie=81,
)


def make_inputs(
    namespace_device,
    namespace_inode,
    boot_id,
    source_port,
    destination_port,
    start_ns,
    end_ns,
    payload,
    target,
    kernel_release,
    btf_sha256,
    object_sha256,
):
    assert len(payload) == 64
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
    reference = dict(
        observation_layer="udp_socket_queue_admission",
        protected_tuple=protected,
        target=deepcopy(target),
    )
    opportunity.update(
        start_ns=start_ns,
        end_ns=end_ns,
        challenge_sha256=digest(payload),
        reference_sha256=digest(_json(reference)),
        predicate=dict(protected_tuple=protected, forbidden_delivery=True),
    )
    contract_raw = wire(contract)
    plan = dict(
        schema_version="edge-udp-queue-plan/v1",
        contract_sha256=digest(contract_raw),
        observation_layer="udp_socket_queue_admission",
        opportunity_id=opportunity["id"],
        kernel_release=kernel_release,
        btf_sha256=btf_sha256,
        object_sha256=object_sha256,
        target=deepcopy(target),
        challenge_payload_hex=payload.hex(),
        max_duration_ns=min(end_ns - start_ns, 5_000_000_000),
        max_events=16,
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
