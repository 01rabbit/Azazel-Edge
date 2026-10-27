"""v2 decision explanations of the Rust core's live decisions (Edge#477).

The Rust ``azazel-edge-core`` is the authoritative decision and enforcement
path (owner decision on Edge#412); it forwards every decision event to the AI
agent. The agent's second pass (``DecisionLayers``) adds the SOC evaluation of
the same event. This module puts the two into the v2 explanation that
``DecisionExplainer`` writes and that the Web UI (Booth Focus) and
``audit_review`` read, in the same format as the scenario replay.

Display and audit only: nothing here decides, scores, classifies P0,
enforces or notifies. The explanation states what the core decided and did
(``enforcement.selected_action``, the action the P0 rule also reads) and the
second pass's evidence; it never re-decides. There is no ``ActionArbiter``
in the live path, so the "arbiter" handed to ``DecisionExplainer`` is a
projection of the core's decision:

* ``trace_id`` -- the core decision chain's trace id for this event
  (``core_decisions.core_decision_payload``), so ``audit_review --trace-id``
  finds the same decision in ``core-decision-audit.jsonl`` when it is a P0
  one. The core's own trace id is kept in ``machine.arbiter``.
* ``policy_profile`` -- ``azazel-edge-core/<pipeline>``: the core's fixed
  severity ladder. ``config_hash`` -- sha256 of the enforcement settings the
  core reported with the event (``enforcement_status``) and its redirect
  policy source; the core reports no policy file hash of its own, so
  ``machine.arbiter.policy.hash_basis`` is ``enforcement_settings``
  (``audit_review`` prints it; Booth Focus returns it as
  ``audit.config_hash_basis``).
* ``why_not_others`` -- only when the core's effective action differs from the
  one it decided (a redirect fallback): the decided action, with the core's
  policy reason. The core reports no other alternatives.
* ``release_condition`` -- the core's lease due time only for an action it
  applied (result ``applied``/``partial_failure``, ledger ``active``/
  ``uncertain``); for a planned action (``planned_not_applied``: dry_run,
  policy_gated, release_guard_failed) ``NOT APPLIED - planned only (<mode>)``,
  and the same label is added to ``reason`` (and so to the operator
  wording), so a planned action never reads as applied.
* nothing of the core's command plan, rollback plan or release metadata
  (owner tokens, resource keys) is copied.

Booth Focus shows the newest record (unchanged): observe and notify records
that follow an enforcement-bearing one replace it on the screen, by design
(privilege-inventory §12 item 6); the enforcement-bearing ones stay in this
file, in the core decision chain and in the P0 alerts.

The file is bounded: rotated to ``<name>.1`` at ``DEFAULT_MAX_BYTES`` (one
rotated file kept, as the core decision chain), together with the Fabric
projections ``DecisionExplainer`` writes beside it. A failure is logged and
counted, never raised into the agent's event handling.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from azazel_edge._util import stable_json
from azazel_edge.notify.core_decisions import core_decision_payload

from .decision import LIVE_DECISION_EXPLANATIONS_PATH, DecisionExplainer

logger = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_KEEP = 1
CORE_POLICY_PREFIX = 'azazel-edge-core'
# Log the first failure, then every this many.
_LOG_EVERY = 100

# The second pass's SOC fields that DecisionExplainer reads as state blocks
# (top level of its ``soc`` argument); the rest form ``soc['summary']``.
_SOC_STATE_KEYS = (
    'security_visibility_state',
    'suppression_exception_state',
    'asset_target_criticality',
    'exposure_change_state',
    'confidence_provenance',
    'behavior_sequence_state',
    'triage_priority_state',
    'incident_campaign_state',
    'entity_risk_state',
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def second_pass_soc(advisory: Mapping[str, Any]) -> Dict[str, Any]:
    """The advisory's second-pass SOC result in ``DecisionExplainer``'s shape
    (``{'summary': ..., <state blocks>, 'evidence_ids': [...]}``). Empty when
    the second pass did not complete."""

    second_pass = _mapping(advisory.get('second_pass'))
    soc = _mapping(second_pass.get('soc'))
    if str(second_pass.get('status') or '') != 'completed' or not soc:
        return {}
    summary = {k: v for k, v in soc.items() if k not in _SOC_STATE_KEYS and k not in ('evidence_ids', 'policy')}
    out: Dict[str, Any] = {'summary': summary, 'evidence_ids': [str(x) for x in soc.get('evidence_ids') or [] if str(x)]}
    for key in _SOC_STATE_KEYS:
        if isinstance(soc.get(key), Mapping):
            out[key] = dict(soc[key])
    return out


def core_config_hash(event: Mapping[str, Any]) -> str:
    """sha256 of the enforcement settings the core reported with the event."""

    enforcement = _mapping(event.get('enforcement'))
    material = {
        'pipeline': str(event.get('pipeline') or ''),
        'enforcement_status': dict(_mapping(event.get('enforcement_status'))),
        'redirect_policy_source': str(_mapping(enforcement.get('metadata')).get('redirect_policy_source') or ''),
    }
    return hashlib.sha256(stable_json(material).encode('utf-8')).hexdigest()


# The core's enforcement results (rust main.rs maybe_enforce): only these
# changed the device. Every other result planned or blocked the action.
APPLIED_RESULTS = ('applied', 'partial_failure')
# Release ledger states of an applied action whose lease the core runs.
LEASED_LEDGER_STATES = ('active', 'uncertain')
NOT_APPLIED_RESULT = 'planned_not_applied'


def applied_state(enforcement: Mapping[str, Any]) -> str:
    """``applied``, ``not_applied`` (planned only: dry_run, policy_gated,
    release_guard_failed) or ``none`` (nothing disruptive to apply)."""

    result = str(enforcement.get('result') or '')
    executed = enforcement.get('executed_count')
    if result in APPLIED_RESULTS and isinstance(executed, int) and not isinstance(executed, bool) and executed > 0:
        return 'applied'
    if result == NOT_APPLIED_RESULT:
        return 'not_applied'
    return 'none'


def _not_applied_label(enforcement: Mapping[str, Any]) -> str:
    return f"NOT APPLIED - planned only ({str(enforcement.get('mode') or 'unknown')})"


def _release_condition(enforcement: Mapping[str, Any]) -> str:
    """The core's lease time only for an action it applied and whose release
    it scheduled; a planned (not applied) action has no lease."""

    state = applied_state(enforcement)
    if state == 'not_applied':
        return _not_applied_label(enforcement)
    if state != 'applied':
        return ''
    metadata = _mapping(enforcement.get('metadata'))
    if str(metadata.get('release_ledger_state') or '') not in LEASED_LEDGER_STATES:
        return ''
    due = metadata.get('release_due_epoch')
    if isinstance(due, (int, float)) and not isinstance(due, bool) and due > 0:
        try:
            when = datetime.fromtimestamp(float(due), timezone.utc).isoformat(timespec='seconds')
        except (OverflowError, OSError, ValueError):
            return ''
        return f'core lease expires at {when}'
    return ''


def _reason(defense: Mapping[str, Any], enforcement: Mapping[str, Any], policy_reason: str) -> str:
    """The core's reason; for a planned (not applied) action it says so, so
    the selected action never reads as applied (Booth Focus, operator wording)."""

    reason = str(defense.get('reason') or policy_reason or 'unspecified')
    if applied_state(enforcement) == 'not_applied':
        reason = f'{reason} [{_not_applied_label(enforcement)}]'
    return reason


def core_decision_arbiter(event: Mapping[str, Any], soc: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """``{'trace_id', 'arbiter', 'target'}`` for a core decision event: the
    arbiter-shaped projection of what the core decided. None for any other
    event."""

    built = core_decision_payload(event)
    if built is None:
        return None
    trace_id, payload = built
    defense = _mapping(event.get('defense'))
    enforcement = _mapping(event.get('enforcement'))
    status = _mapping(event.get('enforcement_status'))
    effective = str(payload['effective_action'])
    decided = str(payload['decided_action'])
    rejected = []
    if decided != effective:
        rejected.append({
            'action': decided,
            'reason': f"core fallback: {payload['policy_reason'] or 'unspecified'}",
        })
    arbiter: Dict[str, Any] = {
        'source': 'azazel-edge-core',
        'action': effective,
        'decided_action': decided,
        'reason': _reason(defense, enforcement, str(payload['policy_reason'])),
        'applied_state': applied_state(enforcement),
        'policy_reason': str(payload['policy_reason']),
        'release_condition': _release_condition(enforcement),
        'control_mode': str(enforcement.get('mode') or 'none'),
        'enforcement_result': str(payload['enforcement_result']),
        'enforce_enabled': status.get('enforce_enabled') is True,
        'enforce_dry_run': status.get('dry_run') is True,
        'enforce_level': str(status.get('enforce_level') or ''),
        'core_trace_id': str(payload['core_trace_id']),
        'policy': {
            'version': f"{CORE_POLICY_PREFIX}/{payload['core_pipeline']}",
            'hash': core_config_hash(event),
            # Not a policy file hash: the core reports none (module doc).
            'hash_basis': 'enforcement_settings',
        },
        'chosen_evidence_ids': list(soc.get('evidence_ids') or []),
        'rejected_alternatives': rejected,
        'client_impact': {},
    }
    return {'trace_id': trace_id, 'arbiter': arbiter, 'target': str(payload['target'] or 'azazel-edge')}


class LiveDecisionExplanationWriter:
    """Writes one v2 explanation per core decision event (see module doc)."""

    def __init__(
        self,
        output_path: str | Path = LIVE_DECISION_EXPLANATIONS_PATH,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep: int = DEFAULT_KEEP,
    ):
        # No /tmp fallback: a file nobody reads is not an explanation.
        self.explainer = DecisionExplainer(output_path, max_bytes=max_bytes, keep=keep, fallback_to_tmp=False)
        self.output_path = self.explainer.output_path
        self._lock = threading.Lock()
        self.written_total = 0
        self.failed_total = 0

    def record(self, event: Mapping[str, Any], advisory: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Explain and append one core decision. Returns the explanation, or
        None for an event that is not a core decision or when writing failed
        (logged, counted). Never raises."""

        try:
            soc = second_pass_soc(advisory if isinstance(advisory, Mapping) else {})
            built = core_decision_arbiter(event, soc) if isinstance(event, Mapping) else None
            if built is None:
                return None
            explanation = self.explainer.explain(
                noc={},
                soc=soc,
                arbiter=built['arbiter'],
                target=built['target'],
                trace_id=built['trace_id'],
                persist=False,
                runbook_support={},
            )
            with self._lock:
                self.explainer.write_jsonl(explanation)
                self.written_total += 1
            return explanation
        except Exception as exc:
            with self._lock:
                self.failed_total += 1
                failed = self.failed_total
            if failed == 1 or failed % _LOG_EVERY == 0:
                logger.error(
                    "decision explanation not written to %s (%d failed so far): %s",
                    self.output_path, failed, exc,
                )
            return None
