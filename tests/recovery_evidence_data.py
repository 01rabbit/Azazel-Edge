"""PUBLIC SYNTHETIC recovery fixtures; never actual kernel teardown evidence."""

from azazel_edge.benchmark import recovery_evidence as recovery
from azazel_edge.outcome.input_auth import public_hex, sign
from azazel_edge.outcome.journal import _json
from safety_observation_data import KEYS, wire, digest

BOOT = "00000000-0000-4000-8000-000000000001"


def synthetic_identity(kind, identifier, index=0):
    """Selected kernel-info SHAPE only, with deliberately synthetic values."""
    value = dict(kind=kind, id=identifier, type=2 if kind != "program" else 26)
    if kind == "link":
        value.update(
            program_id=21 + index,
            attach_type=24 + index,
            target_object_id=1,
            target_btf_id=29236,
        )
    elif kind == "program":
        value.update(tag="0102030405060708", load_time_ns=700_000_000 + index)
    else:
        names = ("config", "pending", "events", "stats")
        dimensions = ((4, 136, 1), (32, 128, 64), (4, 128, 16), (4, 40, 1))
        key_size, value_size, max_entries = dimensions[index]
        value.update(
            type=1 if index == 1 else 2,
            key_size=key_size,
            value_size=value_size,
            max_entries=max_entries,
            map_flags=0,
            name_hex=names[index].encode().ljust(16, b"\0").hex(),
        )
    return value


def make_recovery(
    *,
    contract_sha256="a" * 64,
    queue_plan_sha256="b" * 64,
    queue_report_sha256="c" * 64,
    kernel_boot_id=BOOT,
    kernel_release="synthetic-kernel",
    not_before_ns=1_000_000_000,
    deadline_ns=2_000_000_000,
):
    """Return plan and UNSIGNED report dictionaries: synthetic eight-object sample."""
    resources = [
        dict(
            kind=kind,
            id=base + index,
            identity_sha256=digest(
                _json(synthetic_identity(kind, base + index, index))
            ),
        )
        for kind, base, count in (("link", 11, 2), ("program", 21, 2), ("map", 31, 4))
        for index in range(count)
    ]
    plan = dict(
        schema_version="edge-observer-recovery-plan/v1",
        contract_sha256=contract_sha256,
        queue_plan_sha256=queue_plan_sha256,
        queue_report_sha256=queue_report_sha256,
        kernel_boot_id=kernel_boot_id,
        kernel_release=kernel_release,
        observer_public_key=public_hex(KEYS[0]),
        not_before_ns=not_before_ns,
        deadline_ns=deadline_ns,
        resources=resources,
    )
    # All times fit any legal nonempty window, including a one-nanosecond window.
    rows = [
        dict(
            kind=r["kind"],
            id=r["id"],
            started_ns=not_before_ns,
            finished_ns=not_before_ns,
            state="absent",
            identity_sha256=None,
            reason="not_found",
        )
        for r in resources
    ]
    report = dict(
        schema_version="edge-observer-recovery-report/v1",
        plan_sha256=digest(wire(plan)),
        kernel_boot_id=kernel_boot_id,
        kernel_release=kernel_release,
        observation_layer="observer_object_id_lookup",
        started_ns=not_before_ns,
        finished_ns=deadline_ns,
        context_stable=True,
        resources=rows,
    )
    return plan, report


def signed_wire(report, key=KEYS[0], domain=recovery.DOMAIN):
    """Sign a public synthetic assertion; key custody/actual sampling unproved."""
    core = {k: v for k, v in report.items() if k != "signature"}
    return wire(dict(**core, signature=sign(key, domain, core)))


def materialize(plan, report, *, key=KEYS[0], domain=recovery.DOMAIN):
    """Return (plan_raw, report_raw, external keyword pins) for evaluator calls."""
    plan_raw, report_raw = wire(plan), signed_wire(report, key, domain)
    return (
        plan_raw,
        report_raw,
        dict(
            expected_plan_sha256=digest(wire(plan)),
            expected_report_sha256=digest(report_raw),
        ),
    )
