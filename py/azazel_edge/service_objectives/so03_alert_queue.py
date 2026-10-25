"""SO-03: P0 visual/voice alert queued after decision (every sample <= 2 s).

Definition (assignment section 3, SO-03):

* start -- the arbiter's decision record is durable (its audit-chain entry
  committed);
* end -- the alert is *enqueued* into the visual/voice delivery queue with a
  durable record naming the decision id;
* clock -- the Edge node's monotonic clock;
* samples -- 200 synthetic P0 decisions under nominal load;
* pass -- every sample <= 2 seconds.

What Edge records, and why this row is still ``not_measurable``
---------------------------------------------------------------
The harness drives the library code unmodified: ``ActionArbiter.decide``,
``P0AuditLogger.log_action_decision`` and ``DecisionNotifier.notify`` into
``OfflineQueueNotifier`` -- the only durable delivery queue Edge has.

Edge#414 added the records the definition's two events need:

* **start** -- ``action_decision`` is one of ``DURABLE_KINDS``: ``log()``
  fsyncs the chained file (and, for a new file, its directory) before it
  returns. The start instant is read on ``CLOCK_MONOTONIC`` after it returns.
* **end** -- the enqueue record names the decision (``decision_id``), carries
  the record-only alert class (``alert_class``, rule ``ALERT_CLASS_RULE``) and
  the Edge-recorded ``enqueued_monotonic_ns``; the queue file is replaced
  durably (temp file fsynced, renamed, directory fsynced). The ``notification``
  audit record (also fsynced) names the same decision. The end instant is read
  after ``notify`` returns, so it is never earlier than the durable record.

Each of these is observed on every sample, not assumed: the harness reads the
enqueue record and the notification record back and compares their decision
id with the sample's, checks the class, checks that the Edge stamp lies in the
sample's window, and watches ``os.fsync`` (observation only) for the inodes it
synced. The validator recomputes those prerequisites from the sample fields.

What still does not exist (new function, not a record; the owner decides):

1. **No visual/voice delivery queue.** No adapter is a visual or voice output
   device queue, and no output device is declared.
2. **No configured P0 alert path.** No Edge runtime composes arbiter -> audit
   -> notifier; the harness composes it. Decisions other than ``notify``
   (throttle/redirect/isolate) are not alerted at all.

The 200 samples are still taken through the real code paths and their timings
are reported as a regression signal (``evidence_class: diagnostic_only``).
"""

from __future__ import annotations

import json
import os
import random
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from .record import (
    RULE_EVERY_SAMPLE_MAX,
    build_part,
    build_record,
    gap,
    prerequisite,
    so03_enqueue_observed,
    so03_observed_prerequisites,
    spec_for,
    utc_now,
)

OBJECTIVE_ID = "SO-03"
TITLE = "P0 visual/voice alert queued after decision (within 2 seconds)"
SPEC = spec_for("SO-03", "decision_durable_to_alert_enqueued")
BOUND_MS = SPEC["bound_ms"]
REQUIRED_SAMPLES = SPEC["required_samples"]

# Edge declares no visual/voice output device queue. A change that adds one
# must name it here *and* wire the end event to it; until then the
# prerequisite below is unmet by construction.
DECLARED_VISUAL_VOICE_QUEUES: tuple[str, ...] = ()


def _synthetic_p0_inputs(rng: random.Random, i: int) -> tuple[Dict[str, Any], Dict[str, Any]]:
    fragile_key = ("availability", "path_health", "device_health")[i % 3]
    noc = {
        "availability": {"label": "good", "evidence_ids": [f"noc-a-{i}"]},
        "path_health": {"label": "good", "evidence_ids": [f"noc-p-{i}"]},
        "device_health": {"label": "good", "evidence_ids": [f"noc-d-{i}"]},
        "client_health": {"label": "good"},
        "summary": {"status": "degraded"},
        "evidence_ids": [f"noc-{i}"],
    }
    noc[fragile_key]["label"] = rng.choice(["poor", "critical"])
    soc = {
        "suspicion": {"label": rng.choice(["high", "critical"]), "score": rng.randint(80, 100), "evidence_ids": [f"soc-s-{i}"]},
        "confidence": {"score": rng.randint(60, 100)},
        "technique_likelihood": {"score": rng.randint(50, 100)},
        "blast_radius": {"score": rng.randint(0, 100), "evidence_ids": [f"soc-b-{i}"]},
        "summary": {"status": "alert"},
        "evidence_ids": [f"soc-{i}"],
    }
    return noc, soc


@contextmanager
def _watch_fsync():
    """Observe which inodes os.fsync is called on. Observation only: every call
    goes through to the real fsync and its result or error is unchanged."""

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


def _last_json_line(path: Path) -> Dict[str, Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[-1]) if lines else {}
    except Exception:
        return {}
    return row if isinstance(row, dict) else {}


def run(*, samples: int = REQUIRED_SAMPLES, seed: Optional[int] = None) -> Dict[str, Any]:
    from azazel_edge.arbiter import ActionArbiter
    from azazel_edge.audit import P0AuditLogger
    from azazel_edge.notify import DecisionNotifier, OfflineQueueNotifier
    from azazel_edge.notify.delivery import ALERT_CLASS_P0, ALERT_CLASS_RULE
    import azazel_edge.notify as notify_pkg

    spec = spec_for("SO-03", "decision_durable_to_alert_enqueued")
    started_ns = time.monotonic_ns()
    started_at = utc_now()
    rng = random.Random(seed)
    arbiter = ActionArbiter()
    rows: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="so03-") as tmp, _watch_fsync() as synced:
        work = Path(tmp)
        audit_path = work / "decision-audit.jsonl"
        queue_path = work / "alert-queue.jsonl"
        audit = P0AuditLogger(audit_path)
        queue = OfflineQueueNotifier(queue_path, delegate=None)
        notifier = DecisionNotifier([queue], audit)
        for i in range(int(samples)):
            noc, soc = _synthetic_p0_inputs(rng, i)
            decision = arbiter.decide(noc, soc, client_impact={"score": 0, "critical_client_count": 0})
            decision_id = f"so03-decision-{i:04d}"
            target = f"192.0.2.{(i % 250) + 1}"
            del synced[:]
            audit.log_action_decision(
                trace_id=decision_id,
                source="so03_harness_arbiter",
                action=str(decision.get("action") or ""),
                reason=str(decision.get("reason") or ""),
                release_condition=str(decision.get("release_condition") or ""),
                policy_profile=str((decision.get("policy") or {}).get("version") or ""),
                config_hash=str((decision.get("policy") or {}).get("hash") or ""),
                evidence_ids=list(decision.get("chosen_evidence_ids") or []),
            )
            # log() has returned: the decision record is written, closed and
            # fsynced. This is the instant the decision record is durable.
            start_ns = time.monotonic_ns()
            decision_fsynced = _inode(audit_path) in synced
            del synced[:]
            result = notifier.notify(
                decision, {"operator_wording": "synthetic P0 decision"}, target=target, decision_id=decision_id
            )
            end_ns = time.monotonic_ns()
            queue_row = _last_json_line(queue_path)
            audit_row = _last_json_line(audit_path)
            enqueue_fsynced = _inode(queue_path) in synced and _inode(audit_path) in synced
            stamp = queue_row.get("enqueued_monotonic_ns")
            row = {
                "sample_id": decision_id,
                "start_monotonic_ns": start_ns,
                "end_monotonic_ns": end_ns,
                "elapsed_ms": None,
                "start_event": "action_decision audit record written, closed and fsynced (P0AuditLogger.log returned)",
                "end_event": "DecisionNotifier.notify returned after the fsynced enqueue record and notification audit record naming the decision",
                "action": decision.get("action"),
                "reason": decision.get("reason"),
                "level": (result.get("payload") or {}).get("level"),
                "enqueue_record_decision_id": queue_row.get("decision_id"),
                "notification_audit_decision_id": audit_row.get("decision_id") if audit_row.get("kind") == "notification" else None,
                "enqueue_record_alert_class": queue_row.get("alert_class"),
                "edge_enqueued_monotonic_ns": stamp if isinstance(stamp, int) and not isinstance(stamp, bool) else None,
                "decision_record_fsynced": bool(decision_fsynced),
                "enqueue_record_fsynced": bool(enqueue_fsynced),
            }
            if result.get("ok") and so03_enqueue_observed(row):
                row["elapsed_ms"] = round((end_ns - start_ns) / 1e6, 3)
            else:
                # No durable record naming this decision was observed: the end
                # event never happened, and the sample counts as unfinished.
                row["end_monotonic_ns"] = None
            rows.append(row)
        chain = P0AuditLogger.verify_chain(audit_path)

    observed = so03_observed_prerequisites(rows)
    named = sum(1 for r in rows if so03_enqueue_observed(r))
    classified = sum(1 for r in rows if r.get("enqueue_record_alert_class") == ALERT_CLASS_P0)
    fsynced = sum(1 for r in rows if r.get("decision_record_fsynced") is True and r.get("enqueue_record_fsynced") is True)
    adapters = sorted(n for n in getattr(notify_pkg, "__all__", []) if n.endswith("Notifier") and n != "DecisionNotifier")
    candidates = [
        prerequisite(
            "visual_voice_delivery_queue_declared",
            bool(DECLARED_VISUAL_VOICE_QUEUES),
            "declared: " + (", ".join(DECLARED_VISUAL_VOICE_QUEUES) or "none")
            + f"; Edge notify adapters present: {', '.join(adapters)}",
        ),
        prerequisite(
            "enqueue_record_names_decision_id",
            observed["enqueue_record_names_decision_id"],
            f"samples whose enqueue record and notification audit record both name the decision, "
            f"stamped inside the sample window: {named}/{len(rows)}",
        ),
        prerequisite(
            "enqueue_record_classifies_p0",
            observed["enqueue_record_classifies_p0"],
            f"enqueue records classified {ALERT_CLASS_P0} under {ALERT_CLASS_RULE}: {classified}/{len(rows)}",
        ),
        prerequisite(
            "decision_and_enqueue_records_fsynced",
            observed["decision_and_enqueue_records_fsynced"],
            f"samples whose decision record and enqueue records were fsynced before the event was taken: {fsynced}/{len(rows)}",
        ),
        prerequisite(
            "alert_audit_chain_verifies",
            bool(chain.get("ok")) and int(chain.get("entries") or 0) == 2 * len(rows) and bool(rows),
            f"verify_chain: ok={chain.get('ok')} entries={chain.get('entries')} (expected {2 * len(rows)}) {chain.get('error') or ''}".strip(),
        ),
    ]
    prerequisites = [p for p in candidates if p["id"] in spec["prerequisites"]]
    all_gaps = [
        gap(
            "SO03-NO-VISUAL-VOICE-QUEUE",
            "Edge has no visual/voice alert delivery queue and declares no output device. The only durable "
            "queue is OfflineQueueNotifier (a delivery fallback file), used here as a proxy end event.",
            refs=["py/azazel_edge/notify/delivery.py"],
        ),
        gap(
            "SO03-NO-P0-ALERT-PATH",
            "No Edge runtime composes arbiter -> audit -> notifier for P0 decisions, so the 'configured P0 alert "
            "path' the definition measures does not exist; the harness composes the library pieces. Only arbiter "
            "'notify' decisions reach a notifier, and the P0 rule (" + ALERT_CLASS_RULE + ") awaits the owner.",
            refs=["py/azazel_edge/arbiter/action.py", "py/azazel_edge/notify/delivery.py"],
        ),
    ]
    gaps = [g for g in all_gaps if g["id"] in spec["gaps"]]
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
                "composed_by": "harness (Edge has no runtime composition of this path)",
                "adapters": ["OfflineQueueNotifier"],
                "declared_output_devices": list(DECLARED_VISUAL_VOICE_QUEUES),
                "alert_class_rule": ALERT_CLASS_RULE,
            },
            "load": "nominal: decisions issued sequentially, no other load",
            "interface_identity": "not_applicable: no interface is involved in this row",
        },
        clock={
            "name": "CLOCK_MONOTONIC",
            "source": "time.monotonic_ns() on the Edge host: the harness reads both events, and the enqueue record carries the Edge stamp",
            "note": "both events are recorded on one host by one process; the Edge stamp is checked to lie inside each window",
        },
        sample_rule={"required_samples": spec["required_samples"], "taken": len(rows), "load": "nominal"},
        parts=[part],
        method="real ActionArbiter + P0AuditLogger + DecisionNotifier/OfflineQueueNotifier, timed around the calls",
        notes=[
            "action_decision and notification records are fsynced (DURABLE_KINDS); the enqueue file is replaced durably.",
            "alert_class is record-only: it does not change routing, level or adapters.",
        ],
    )

