"""SO-03: P0 visual/voice alert queued after decision (every sample <= 2 s).

Definition (assignment section 3, SO-03):

* start -- the arbiter's decision record is durable (its audit-chain entry
  committed);
* end -- the alert is *enqueued* into the visual/voice delivery queue with a
  durable record naming the decision id;
* clock -- the Edge node's monotonic clock;
* samples -- 200 synthetic P0 decisions under nominal load;
* pass -- every sample <= 2 seconds.

What Edge has today, and why this row is ``not_measurable``
-----------------------------------------------------------
The pieces exist as library code and this harness drives them unmodified:
``ActionArbiter.decide`` (``py/azazel_edge/arbiter/action.py``),
``P0AuditLogger.log_action_decision`` (``py/azazel_edge/audit/logger.py``),
and ``DecisionNotifier.notify`` into ``OfflineQueueNotifier`` -- the only
durable delivery queue Edge has (``py/azazel_edge/notify/delivery.py``).

Three things the definition needs do not exist, so the run cannot be gate
evidence and the harness says so instead of passing:

1. **No visual/voice delivery queue.** Edge's adapters are ntfy, Mattermost,
   webhook, SMTP, syslog-CEF and the offline file queue. None is a visual or
   voice output device queue, and no output device is declared.
2. **The enqueue record does not name the decision.** The offline-queue entry
   carries action, reason, target, level, incident id, wording and time; the
   ``notification`` audit record is keyed by the *target*. Neither names the
   decision's ``trace_id``. This is probed on every run, not assumed: if a
   later change makes the enqueue record name the decision, that prerequisite
   flips on its own.
3. **No P0 class and no configured P0 alert path.** Edge has no P0
   classification and no runtime that composes arbiter -> audit -> notifier.
   The harness uses an arbiter ``notify`` decision at ``critical`` level as
   the synthetic stand-in and composes the path itself.

The 200 samples are still taken through those real code paths and their
timings are reported as a regression signal (``evidence_class:
diagnostic_only``).
"""

from __future__ import annotations

import json
import random
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .record import (
    RULE_EVERY_SAMPLE_MAX,
    build_part,
    build_record,
    gap,
    prerequisite,
    utc_now,
)

OBJECTIVE_ID = "SO-03"
TITLE = "P0 visual/voice alert queued after decision (within 2 seconds)"
BOUND_MS = 2000.0
REQUIRED_SAMPLES = 200

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


def _names_decision(obj: Any, decision_id: str) -> bool:
    return decision_id in json.dumps(obj, ensure_ascii=True)


def run(*, samples: int = REQUIRED_SAMPLES, seed: Optional[int] = None) -> Dict[str, Any]:
    from azazel_edge.arbiter import ActionArbiter
    from azazel_edge.audit import P0AuditLogger
    from azazel_edge.notify import DecisionNotifier, OfflineQueueNotifier
    import azazel_edge.notify as notify_pkg

    started_ns = time.monotonic_ns()
    started_at = utc_now()
    rng = random.Random(seed)
    arbiter = ActionArbiter()
    rows: List[Dict[str, Any]] = []
    stand_in_failures = 0
    queue_names_decision = 0
    audit_names_decision = 0
    with tempfile.TemporaryDirectory(prefix="so03-") as tmp:
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
            # log() has returned: the chained file is written and closed. This
            # is the instant the decision record exists.
            start_ns = time.monotonic_ns()
            result = notifier.notify(decision, {"operator_wording": "synthetic P0 stand-in"}, target=target)
            end_ns = time.monotonic_ns()
            is_p0_stand_in = decision.get("action") == "notify" and ((result.get("payload") or {}).get("level") == "critical")
            if not is_p0_stand_in or not result.get("ok"):
                stand_in_failures += 1
            last_queue = queue_path.read_text(encoding="utf-8").splitlines()[-1] if queue_path.exists() else "{}"
            last_audit = audit_path.read_text(encoding="utf-8").splitlines()[-1]
            q_named = _names_decision(json.loads(last_queue), decision_id)
            a_named = _names_decision(json.loads(last_audit), decision_id)
            queue_names_decision += int(q_named)
            audit_names_decision += int(a_named)
            rows.append(
                {
                    "sample_id": decision_id,
                    "start_monotonic_ns": start_ns,
                    "end_monotonic_ns": end_ns if result.get("ok") else None,
                    "elapsed_ms": round((end_ns - start_ns) / 1e6, 3) if result.get("ok") else None,
                    "start_event": "action_decision audit record written and closed (P0AuditLogger.log returned)",
                    "end_event": "DecisionNotifier.notify returned after OfflineQueueNotifier wrote the queue entry and the notification audit record",
                    "action": decision.get("action"),
                    "reason": decision.get("reason"),
                    "level": (result.get("payload") or {}).get("level"),
                    "enqueue_record_names_decision": q_named,
                    "notification_audit_names_decision": a_named,
                }
            )

    adapters = sorted(n for n in getattr(notify_pkg, "__all__", []) if n.endswith("Notifier") and n != "DecisionNotifier")
    prerequisites = [
        prerequisite(
            "visual_voice_delivery_queue_declared",
            bool(DECLARED_VISUAL_VOICE_QUEUES),
            "declared: " + (", ".join(DECLARED_VISUAL_VOICE_QUEUES) or "none")
            + f"; Edge notify adapters present: {', '.join(adapters)}",
        ),
        prerequisite(
            "enqueue_record_names_decision_id",
            bool(rows) and queue_names_decision == len(rows),
            f"queue entries naming the decision: {queue_names_decision}/{len(rows)}; "
            f"notification audit records naming the decision: {audit_names_decision}/{len(rows)}",
        ),
        prerequisite(
            "synthetic_decisions_are_p0_stand_ins",
            bool(rows) and stand_in_failures == 0,
            f"{len(rows) - stand_in_failures}/{len(rows)} decisions were arbiter 'notify' at level 'critical' and enqueued",
        ),
    ]
    gaps = [
        gap(
            "SO03-NO-VISUAL-VOICE-QUEUE",
            "Edge has no visual/voice alert delivery queue and declares no output device. The only durable "
            "queue is OfflineQueueNotifier (a delivery fallback file), used here as a proxy end event.",
            refs=["py/azazel_edge/notify/delivery.py"],
        ),
        gap(
            "SO03-ENQUEUE-RECORD-LACKS-DECISION-ID",
            "No durable enqueue record names the decision id: OfflineQueueNotifier._summary_payload carries no "
            "trace/decision id and DecisionNotifier logs its notification audit record under trace_id=target.",
            refs=["py/azazel_edge/notify/delivery.py"],
        ),
        gap(
            "SO03-NO-P0-CLASS-OR-PATH",
            "Edge has no P0 alert classification and no runtime that composes arbiter -> audit -> notifier; "
            "the harness composes the library pieces and uses arbiter notify at level critical as the stand-in.",
            refs=["py/azazel_edge/arbiter/action.py", "py/azazel_edge/notify/delivery.py"],
        ),
    ]
    part = build_part(
        name="decision_durable_to_alert_enqueued",
        pass_rule={
            "kind": RULE_EVERY_SAMPLE_MAX,
            "bound_ms": BOUND_MS,
            "description": "every sample <= 2 seconds; behaviour under hostile load is SO-11's, not a relaxation here",
        },
        required_samples=REQUIRED_SAMPLES,
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
            },
            "load": "nominal: decisions issued sequentially, no other load",
            "interface_identity": "not_applicable: no interface is involved in this row",
        },
        clock={
            "name": "CLOCK_MONOTONIC",
            "source": "time.monotonic_ns() in the harness process on the Edge host",
            "note": "both events are recorded on one host by one process",
        },
        sample_rule={"required_samples": REQUIRED_SAMPLES, "taken": len(rows), "load": "nominal"},
        parts=[part],
        method="real ActionArbiter + P0AuditLogger + DecisionNotifier/OfflineQueueNotifier, timed around the calls",
        notes=[
            "P0AuditLogger closes but does not fsync; 'durable' here is the process-kill sense (see SO-07).",
        ],
    )
