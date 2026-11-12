"""PUBLIC synthetic copy-layer enrollment; no kernel or operational key claim."""

import json
from azazel_edge.outcome.journal import _json
from udp_queue_data import make_inputs as queue_inputs
from udp_queue_data import KEY as KEY, BOOT as BOOT, PAYLOAD as PAYLOAD, TARGET as TARGET
from safety_observation_data import digest, wire

LAYER = "udp_protocol_userspace_payload_copy"
DOMAIN = b"azazel-edge:udp-protocol-userspace-payload-copy:v1\x00"
PIDNS = dict(device=4, inode=51)
TIMENS = dict(device=4, inode=52, monotonic_offset_ns=0, boottime_offset_ns=0)


def make_inputs(*args, pidns=None, timens=None):
    contract, oldplan, _ = queue_inputs(*args)
    c, p = json.loads(contract), json.loads(oldplan)
    target = p.pop("target")
    p.update(
        schema_version="edge-udp-payload-copy-plan/v1",
        observation_layer=LAYER,
        socket_identity=dict(
            inode=target["socket_inode"],
            cookie=target["socket_cookie"],
            uid=target["uid"],
            netns_cookie=target["netns_cookie"],
        ),
        locator={k: target[k] for k in ("pid", "start_ticks", "fd")},
        receiver_pid_namespace=pidns or PIDNS,
        observer_time_namespace=timens or TIMENS,
    )
    op = c["opportunities"]["protected_escape"][0]
    ref = {
        k: p[k]
        for k in (
            "observation_layer",
            "socket_identity",
            "locator",
            "receiver_pid_namespace",
            "observer_time_namespace",
        )
    }
    ref["protected_tuple"] = op["predicate"]["protected_tuple"]
    op["reference_sha256"] = digest(_json(ref))
    contract = wire(c)
    p["contract_sha256"] = digest(contract)
    plan = wire(p)
    return (
        contract,
        plan,
        dict(
            expected_contract_sha256=digest(contract), expected_plan_sha256=digest(plan)
        ),
    )
