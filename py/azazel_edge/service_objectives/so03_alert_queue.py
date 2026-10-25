"""SO-03: P0 visual/voice alert queued after decision (every sample <= 2 s).

Definition (assignment section 3, SO-03):

* start -- the arbiter's decision record is durable (its audit-chain entry
  committed);
* end -- the alert is *enqueued* into the visual/voice delivery queue with a
  durable record naming the decision id;
* clock -- the Edge node's monotonic clock;
* samples -- 200 synthetic P0 decisions under nominal load;
* pass -- every sample <= 2 seconds.

The path measured (owner decisions on Edge#414, 2026-10-25)
-----------------------------------------------------------
The harness drives the product code unmodified: ``ActionArbiter.decide``,
``P0AuditLogger.log_action_decision`` and the P0 alert path in
``azazel_edge.notify.p0_alert`` attached to that logger with
``attach_p0_alert_relay``:

* **start** -- ``action_decision`` is a durable kind: ``log()`` fsyncs the
  chained file, then hands the record to its durable-record listeners with
  ``CLOCK_MONOTONIC`` read after the fsync. That Edge-recorded instant is the
  start; it must lie inside the harness's window around the call.
* **path** -- the listener only queues the audit-chain record for the relay
  thread, which classifies it with ``classify_p0`` (P0 = throttle, redirect,
  isolate, or SOC ``critical``) and enqueues one entry per channel (visual,
  voice) into ``P0AlertQueue``, the one durable JSONL queue.
* **end** -- the enqueue: both channel entries are written in one append and
  the file fsynced; the relay reports the enqueue after that fsync and the
  harness reads the end instant there. The harness then reads the entries
  back from the queue file and checks that they name the decision, its
  audit-chain record (chain hash) and its start, and were stamped inside the
  window, and watches ``os.fsync`` (observation only) for the inodes synced.

The validator recomputes every record prerequisite, each sample's end, the
P0 class (from the decision's action and SOC label, by the owner's rule,
written independently) and the closure of the two former gaps
(``SO03-NO-VISUAL-VOICE-QUEUE``, ``SO03-NO-P0-ALERT-PATH``) from the samples.
If any sample does not show its durable enqueue record, the gaps stay.

Why this row is still ``not_measurable``: the relay is attached when an
``OpenCanaryRedirectController`` is built (to its decision logger), and no
Edge service builds that controller yet. The Rust core's
throttle/redirect/isolate decisions are not written as ``action_decision``
records through ``P0AuditLogger`` (``release.rs`` writes rollback audit only),
so they never reach the P0 queue, and which decision path is authoritative is
Edge#412. The blocking gap ``SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS`` is
not closable by samples; SO-03 is never a pass until that path is wired.

Out of scope: rendering and speaking the queued alerts (no output device is
added), and which Edge service builds the controller or attaches the path.
"""

from __future__ import annotations

import json
import os
import random
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from .record import (
    GAP_CLOSERS,
    RULE_EVERY_SAMPLE_MAX,
    build_part,
    build_record,
    gap,
    prerequisite,
    so03_end_observed,
    so03_observed_prerequisites,
    spec_for,
    utc_now,
)

OBJECTIVE_ID = "SO-03"
TITLE = "P0 visual/voice alert queued after decision (within 2 seconds)"
SPEC = spec_for("SO-03", "decision_durable_to_alert_enqueued")
BOUND_MS = SPEC["bound_ms"]
REQUIRED_SAMPLES = SPEC["required_samples"]


# How long a sample waits for its enqueue before it is recorded as unfinished.
# Far above the bound, so a slow enqueue is measured (and fails), not dropped.
END_WAIT_S = 10.0

QUEUE_RECORD_KEYS = (
    "channel", "schema", "record_type", "seq", "decision_id", "decision_chain_hash", "p0_class", "p0_basis",
    "p0_rule", "enqueued_monotonic_ns", "decision_durable_monotonic_ns", "decision_record_durable",
)

# The P0 kinds the 200 decisions cycle through: the three enforcement-bearing
# actions, and a SOC-critical decision the arbiter answers with notify.
P0_KINDS = ("isolate", "redirect", "throttle", "soc_critical")


def _synthetic_p0_inputs(rng: random.Random, i: int, mapping: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any], str]:
    """NOC/SOC inputs for which the real arbiter takes a P0 decision of kind
    ``P0_KINDS[i % 4]``, with scores drawn at or above that action's policy
    thresholds and below the next stronger action's."""

    kind = P0_KINDS[i % len(P0_KINDS)]
    noc = {
        "availability": {"label": "good", "evidence_ids": [f"noc-a-{i}"]},
        "path_health": {"label": "good", "evidence_ids": [f"noc-p-{i}"]},
        "device_health": {"label": "good", "evidence_ids": [f"noc-d-{i}"]},
        "client_health": {"label": "good"},
        "summary": {"status": "good"},
        "evidence_ids": [f"noc-{i}"],
    }
    iso, red, thr = mapping["isolate"], mapping["redirect"], mapping["throttle"]
    label = rng.choice(["high", "critical"])
    if kind == "isolate":
        susp = rng.randint(iso["suspicion_min"], 100)
        conf = rng.randint(max(iso["confidence_min"], mapping["strong_soc"]["confidence_min"]), 100)
        blast = rng.randint(iso["blast_min"], 100)
    elif kind == "redirect":
        susp = rng.randint(red["suspicion_min"], iso["suspicion_min"] - 1)
        conf = rng.randint(max(red["confidence_min"], mapping["strong_soc"]["confidence_min"]), 100)
        blast = rng.randint(red["blast_min"], 100)
    elif kind == "throttle":
        susp = rng.randint(50, red["suspicion_min"] - 1)
        conf = rng.randint(max(thr["confidence_min"], mapping["strong_soc"]["confidence_min"]), 100)
        blast = rng.randint(thr["blast_min"], 100)
    else:
        # SOC critical on a fragile NOC: the arbiter notifies; P0 by the SOC label.
        label = "critical"
        noc[("availability", "path_health", "device_health")[i % 3]]["label"] = rng.choice(["poor", "critical"])
        noc["summary"]["status"] = "degraded"
        susp = rng.randint(80, 100)
        conf = rng.randint(mapping["strong_soc"]["confidence_min"], 100)
        blast = rng.randint(0, 100)
    soc = {
        "suspicion": {"label": label, "score": susp, "evidence_ids": [f"soc-s-{i}"]},
        "confidence": {"score": conf},
        "technique_likelihood": {"score": rng.randint(50, 100)},
        "blast_radius": {"score": blast, "evidence_ids": [f"soc-b-{i}"]},
        "summary": {"status": "alert"},
        "evidence_ids": [f"soc-{i}"],
    }
    return noc, soc, kind


@contextmanager
def _watch_fsync():
    """Observe which inodes os.fsync is called on (any thread). Observation
    only: every call goes through to the real fsync, result or error unchanged."""

    real = os.fsync
    synced: List[tuple] = []

    def watching(fd):  # type: ignore[no-untyped-def]
        try:
            st = os.fstat(fd)
            key = (st.st_dev, st.st_ino)
        except OSError:
            key = None
        result = real(fd)
        if key is not None:
            synced.append(key)
        return result

    os.fsync = watching  # type: ignore[assignment]
    try:
        yield synced
    finally:
        os.fsync = real  # type: ignore[assignment]


def _inode(path: Path) -> Optional[tuple]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def _queue_records_for(queue_path: Path, decision_id: str) -> List[Dict[str, Any]]:
    """The queue entries naming ``decision_id``, read back from the file."""

    out: List[Dict[str, Any]] = []
    try:
        lines = queue_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict) and row.get("record_type") == "alert" and row.get("decision_id") == decision_id:
            out.append({k: row.get(k) for k in QUEUE_RECORD_KEYS})
    return out


def _full_queue_enqueue_latency() -> Dict[str, Any]:
    """Diagnostic: one enqueue into a queue already at its bound (plain
    append), and one that triggers the 2x-bound compaction."""

    from azazel_edge.notify.p0_alert import DEFAULT_MAX_ENTRIES, P0AlertQueue, build_p0_alerts

    def alerts(i: int) -> List[Dict[str, Any]]:
        rec_ = {"kind": "action_decision", "trace_id": f"fill-{i}", "chain_hash": f"{i:064x}", "action": "throttle"}
        return build_p0_alerts(rec_, "enforcement:throttle", "fsynced", 1)

    with tempfile.TemporaryDirectory(prefix="so03-full-") as tmp:
        q = P0AlertQueue(Path(tmp) / "q.jsonl", max_entries=DEFAULT_MAX_ENTRIES)
        i = 0
        while i * 2 < DEFAULT_MAX_ENTRIES:
            q.enqueue(alerts(i))
            i += 1
        t0 = time.monotonic_ns()
        q.enqueue(alerts(i))
        append_ms = (time.monotonic_ns() - t0) / 1e6
        i += 1
        while (i + 1) * 2 <= q.max_lines:
            q.enqueue(alerts(i))
            i += 1
        before = q.compactions
        t0 = time.monotonic_ns()
        q.enqueue(alerts(i))
        compact_ms = (time.monotonic_ns() - t0) / 1e6
        if q.compactions != before + 1:
            raise RuntimeError("the full-queue enqueue did not compact")
    return {"max_entries": DEFAULT_MAX_ENTRIES, "append_ms": append_ms, "compact_ms": compact_ms}


def run(*, samples: int = REQUIRED_SAMPLES, seed: Optional[int] = None) -> Dict[str, Any]:
    from azazel_edge.arbiter import ActionArbiter
    from azazel_edge.audit import P0AuditLogger
    from azazel_edge.notify.p0_alert import P0_RULE, QUEUE_SCHEMA, attach_p0_alert_relay

    spec = spec_for("SO-03", "decision_durable_to_alert_enqueued")
    started_ns = time.monotonic_ns()
    started_at = utc_now()
    rng = random.Random(seed)
    arbiter = ActionArbiter()
    mapping = arbiter.policy["action_mapping"]
    rows: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="so03-") as tmp, _watch_fsync() as synced:
        work = Path(tmp)
        audit_path = work / "decision-audit.jsonl"
        queue_path = work / "p0-alert-queue.jsonl"
        audit = P0AuditLogger(audit_path)

        enqueued: Dict[str, tuple] = {}
        enqueued_cv = threading.Condition()

        def on_relayed(decision_id: str, result: Dict[str, Any]) -> None:
            # Called by the relay thread once per relayed decision record,
            # after any enqueue (and its fsync) returned.
            now = time.monotonic_ns()
            with enqueued_cv:
                enqueued[decision_id] = (now, result)
                enqueued_cv.notify_all()

        relay = attach_p0_alert_relay(audit, queue_path, on_relayed=on_relayed)
        relay.ready.wait(END_WAIT_S)  # startup reconcile done (nothing to replay here)
        try:
            for i in range(int(samples)):
                noc, soc, kind = _synthetic_p0_inputs(rng, i, mapping)
                decision = arbiter.decide(noc, soc, client_impact={"score": 0, "critical_client_count": 0})
                decision_id = f"so03-decision-{i:04d}"
                trace = decision.get("decision_trace") if isinstance(decision.get("decision_trace"), dict) else {}
                del synced[:]
                call_ns = time.monotonic_ns()
                logged = audit.log_action_decision(
                    trace_id=decision_id,
                    source="so03_harness_arbiter",
                    action=str(decision.get("action") or ""),
                    reason=str(decision.get("reason") or ""),
                    release_condition=str(decision.get("release_condition") or ""),
                    policy_profile=str((decision.get("policy") or {}).get("version") or ""),
                    config_hash=str((decision.get("policy") or {}).get("hash") or ""),
                    evidence_ids=list(decision.get("chosen_evidence_ids") or []),
                    target_ip=f"192.0.2.{(i % 250) + 1}",
                    decision_trace=trace,
                )
                returned_ns = time.monotonic_ns()
                decision_fsynced = _inode(audit_path) in synced
                deadline = time.monotonic() + END_WAIT_S
                with enqueued_cv:
                    while decision_id not in enqueued and time.monotonic() < deadline:
                        enqueued_cv.wait(timeout=max(0.0, deadline - time.monotonic()))
                    got = enqueued.pop(decision_id, None)
                end_ns, result = got if got is not None else (None, {})
                queue_records = _queue_records_for(queue_path, decision_id)
                durable_ns = queue_records[0].get("decision_durable_monotonic_ns") if queue_records else None
                row = {
                    "sample_id": decision_id,
                    "start_monotonic_ns": durable_ns if isinstance(durable_ns, int) and not isinstance(durable_ns, bool) else returned_ns,
                    "end_monotonic_ns": end_ns,
                    "elapsed_ms": None,
                    "start_event": "action_decision audit record fsynced (Edge CLOCK_MONOTONIC read after the fsync, handed to the durable-record listener)",
                    "end_event": "P0AlertQueue enqueue of the visual and voice entries naming the decision, fsynced (relay reported after the fsync)",
                    "action": decision.get("action"),
                    "reason": decision.get("reason"),
                    "decision_suspicion_label": trace.get("suspicion_label"),
                    "decision_chain_hash": str(logged.get("chain_hash") or ""),
                    "harness_log_call_monotonic_ns": call_ns,
                    "harness_log_returned_monotonic_ns": returned_ns,
                    "edge_decision_durable_monotonic_ns": durable_ns if isinstance(durable_ns, int) and not isinstance(durable_ns, bool) else None,
                    "queue_records": queue_records,
                    "enqueue_result_durability": result.get("durability"),
                    "decision_record_fsynced": bool(decision_fsynced),
                    "enqueue_record_fsynced": bool(result.get("p0")) and _inode(queue_path) in synced,
                }
                if result.get("ok") and result.get("p0") and so03_end_observed(row):
                    row["elapsed_ms"] = round((row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e6, 3)
                else:
                    # No durable enqueue record for this decision was observed:
                    # the end event never happened; the sample is unfinished.
                    row["end_monotonic_ns"] = None
                rows.append(row)
        finally:
            relay.stop()
        chain = P0AuditLogger.verify_chain(audit_path)
        counters = relay.metrics()
    try:
        full_queue = _full_queue_enqueue_latency()
    except Exception as exc:  # diagnostic only; never part of the verdict
        full_queue = {"max_entries": 0, "append_ms": float("nan"), "compact_ms": float("nan"), "error": str(exc)}

    observed = so03_observed_prerequisites(rows)
    ended = sum(1 for r in rows if so03_end_observed(r))
    kinds = sorted({str(r.get("action")) for r in rows})
    candidates = [
        prerequisite(
            "visual_voice_delivery_queue_declared",
            observed["visual_voice_delivery_queue_declared"],
            f"P0AlertQueue ({QUEUE_SCHEMA}), channels visual+voice; samples with one entry per channel: "
            f"{sum(1 for r in rows if len(r.get('queue_records') or []) == 2)}/{len(rows)}",
        ),
        prerequisite(
            "enqueue_record_names_decision_id",
            observed["enqueue_record_names_decision_id"],
            f"samples whose two queue entries name the decision, its chain hash and its durable instant, "
            f"stamped inside the sample window: {ended}/{len(rows)}",
        ),
        prerequisite(
            "enqueue_record_classifies_p0",
            observed["enqueue_record_classifies_p0"],
            f"queue entries classified P0 under {P0_RULE}, recomputed from action and SOC label; actions sampled: {', '.join(kinds)}",
        ),
        prerequisite(
            "decision_and_enqueue_records_fsynced",
            observed["decision_and_enqueue_records_fsynced"],
            f"samples whose decision record and queue file were fsynced before the event was taken; relay counters {counters}",
        ),
        prerequisite(
            "alert_audit_chain_verifies",
            bool(chain.get("ok")) and int(chain.get("entries") or 0) == len(rows) and bool(rows),
            f"verify_chain: ok={chain.get('ok')} entries={chain.get('entries')} (expected {len(rows)}) {chain.get('error') or ''}".strip(),
        ),
    ]
    prerequisites = [p for p in candidates if p["id"] in spec["prerequisites"]]
    all_gaps = [
        gap(
            "SO03-NO-VISUAL-VOICE-QUEUE",
            "Not every sample ended on a durable P0AlertQueue enqueue record on both the visual and voice channel.",
            refs=["py/azazel_edge/notify/p0_alert.py"],
        ),
        gap(
            "SO03-NO-P0-ALERT-PATH",
            "Not every sample's alert was built from its audit-chain decision record and classified P0 by "
            + P0_RULE + ".",
            refs=["py/azazel_edge/notify/p0_alert.py", "py/azazel_edge/audit/logger.py"],
        ),
        gap(
            "SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS",
            "The P0 relay is attached when an OpenCanaryRedirectController is built (no Edge service builds one yet). The Rust core's "
            "throttle/redirect/isolate decisions are not written as action_decision records through P0AuditLogger "
            "(release.rs writes rollback audit only), so they never reach the P0 queue. Which decision path is "
            "authoritative is Edge#412. No sample closes this gap: SO-03 stays not_measurable until it is wired.",
            refs=["Edge#412", "py/azazel_edge/opencanary_redirect.py", "rust/azazel-edge-core/src/release.rs"],
        ),
    ]
    # A gap is left out only when the validator's own recomputation closes it.
    gaps = [
        g for g in all_gaps
        if g["id"] in spec["gaps"]
        and not (g["id"] in spec.get("gaps_closed_by_samples", ()) and g["id"] in GAP_CLOSERS and GAP_CLOSERS[g["id"]](rows))
    ]
    part = build_part(
        name="decision_durable_to_alert_enqueued",
        pass_rule={
            "kind": RULE_EVERY_SAMPLE_MAX,
            "bound_ms": spec["bound_ms"],
            "description": "every sample <= 2 seconds; behaviour under hostile load is SO-11's, not a relaxation here",
        },
        required_samples=spec["required_samples"],
        samples=rows,
        prerequisites=prerequisites,
        gaps=gaps,
    )
    return build_record(
        objective_id=OBJECTIVE_ID,
        title=TITLE,
        started_monotonic_ns=started_ns,
        started_at=started_at,
        product_configuration={
            "product": "azazel-edge",
            "arbiter_policy": {"version": arbiter.policy["version"], "hash": arbiter.policy_hash},
            "alert_path": {
                "composed_by": "azazel_edge.notify.p0_alert.attach_p0_alert_relay on the decision P0AuditLogger",
                "queue": QUEUE_SCHEMA,
                "channels": ["visual", "voice"],
                "p0_rule": P0_RULE,
                "output_devices": "none: rendering and speaking are downstream of the queue and out of scope",
            },
            "load": "nominal: decisions issued sequentially, no other load",
            "interface_identity": "not_applicable: no interface is involved in this row",
        },
        clock={
            "name": "CLOCK_MONOTONIC",
            "source": "time.monotonic_ns() on the Edge host: the audit logger stamps the durable decision, the harness reads the end after the queue fsync",
            "note": "one host, one process; the Edge durable stamp is checked to lie inside the harness's call window and the queue stamp inside the sample window",
        },
        sample_rule={"required_samples": spec["required_samples"], "taken": len(rows), "load": "nominal"},
        parts=[part],
        method="real ActionArbiter + P0AuditLogger + P0AlertRelay/P0AlertQueue, start stamped by the logger, end after the queue fsync",
        notes=[
            "action_decision records are fsynced (DURABLE_KINDS); the P0 queue append is fsynced before the relay reports it.",
            "the relay is attached when an OpenCanaryRedirectController is built, and no Edge service builds one yet; Rust core decisions do not reach it "
            "(gap SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS, Edge#412), so this row is never a pass today.",
            "diagnostic, not a sample: enqueue latency on a full queue (max_entries=%d): append at the bound %.3f ms, "
            "append that compacts at 2x the bound %.3f ms" % (full_queue["max_entries"], full_queue["append_ms"], full_queue["compact_ms"]),
            "the P0 path is observation and notification only: it never changes the decision, and its failure never reaches log().",
        ],
    )
