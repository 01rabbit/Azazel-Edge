from __future__ import annotations

from typing import Any, Callable, Dict, List

from azazel_edge.runbook_review import review_runbook_id
from azazel_edge.runbooks import get_runbook


STATE_RUNBOOKS: Dict[str, List[str]] = {
    "wifi_signal_unavailable": [
        "rb.user.first-contact.network-issue",
        "rb.noc.ui-snapshot.check",
    ],
    "dhcp_likely": [
        "rb.noc.dhcp.failure.check",
        "rb.user.first-contact.network-issue",
    ],
    "dns_likely": [
        "rb.noc.dns.failure.check",
        "rb.user.first-contact.network-issue",
    ],
    "multi_client_wifi_issue": [
        "rb.noc.ui-snapshot.check",
        "rb.user.incident-status-brief",
    ],
    "wifi_onboarding_needed": [
        "rb.user.device-onboarding-guide",
        "rb.user.portal-access-guide",
    ],
    "reconnect_credentials_refresh": [
        "rb.user.reconnect-guide",
        "rb.user.first-contact.network-issue",
    ],
    "portal_trigger_likely": [
        "rb.user.portal-access-guide",
        "rb.user.first-contact.network-issue",
    ],
    "onboarding_guidance_ready": [
        "rb.user.device-onboarding-guide",
    ],
    "dns_partial_failure": [
        "rb.noc.dns.failure.check",
        "rb.user.incident-status-brief",
    ],
    "dns_global_failure": [
        "rb.noc.dns.failure.check",
        "rb.noc.default-route.check",
    ],
    "uplink_reachability_likely": [
        "rb.noc.default-route.check",
        "rb.noc.ui-snapshot.check",
    ],
    "portal_session_issue": [
        "rb.user.portal-access-guide",
        "rb.user.incident-status-brief",
    ],
    "partial_path_issue": [
        "rb.noc.default-route.check",
        "rb.user.incident-status-brief",
    ],
    "uplink_issue": [
        "rb.noc.default-route.check",
        "rb.noc.ui-snapshot.check",
    ],
    "gateway_issue": [
        "rb.noc.default-route.check",
        "rb.noc.service.status.check",
    ],
    "service_check_ready": [
        "rb.noc.service.status.check",
        "rb.noc.ui-snapshot.check",
    ],
    "service_guidance_ready": [
        "rb.user.incident-status-brief",
        "rb.noc.service.status.check",
    ],
    "service_multiple_failure": [
        "rb.noc.service.status.check",
        "rb.noc.ui-snapshot.check",
    ],
    "user_cannot_answer": [
        "rb.user.first-contact.network-issue",
        "rb.noc.ui-snapshot.check",
    ],
    "wifi_reconnect_needed": [
        "rb.user.reconnect-guide",
        "rb.user.first-contact.network-issue",
    ],
}

NOC_RULE_RUNBOOKS: Dict[str, Dict[str, str]] = {
    "resolution_failure": {
        "diagnostic_state": "dns_global_failure",
        "runbook_id": "rb.noc.dns.failure.check",
    },
    "service_assurance_failure": {
        "diagnostic_state": "service_multiple_failure",
        "runbook_id": "rb.noc.service.status.check",
    },
    "path_degradation": {
        "diagnostic_state": "uplink_issue",
        "runbook_id": "rb.noc.default-route.check",
    },
    "config_drift": {
        "runbook_id": "rb.noc.ui-snapshot.check",
    },
    "client_inventory_anomaly": {
        "runbook_id": "rb.noc.ui-snapshot.check",
    },
    "capacity_pressure": {
        "runbook_id": "rb.noc.ui-snapshot.check",
    },
    "stable_observe": {
        "runbook_id": "rb.noc.ui-snapshot.check",
    },
}

GOOD_LABELS = {"", "good", "ok", "healthy", "stable", "present", "known", "none", "normal", "on"}


def _score_for_audience(runbook: Dict[str, Any], audience: str, order_index: int = 0) -> int:
    score = 100 - (order_index * 5)
    runbook_audience = str(runbook.get("audience") or "")
    domain = str(runbook.get("domain") or "")
    effect = str(runbook.get("effect") or "")
    if audience == "temporary":
        if runbook_audience == "beginner":
            score += 25
        if domain == "user":
            score += 20
        if domain == "noc":
            score += 8
        if effect == "controlled_exec":
            score -= 40
    else:
        if runbook_audience == "operator":
            score += 20
        if domain in {"noc", "ops", "soc"}:
            score += 10
        if domain == "user":
            score -= 5
    return score


def _string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _dict_value(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _health_value(payload: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        text = str(payload.get(key) or "").strip().lower()
        if text:
            return text
    return ""


def _is_problem_state(payload: Dict[str, Any], *keys: str) -> bool:
    state = _health_value(payload, *keys)
    return bool(state and state not in GOOD_LABELS)


def _hydrate_runbook_candidate(
    runbook_id: str,
    audience: str,
    lang: str,
    context: Dict[str, Any],
    order_index: int = 0,
) -> Dict[str, Any]:
    runbook = get_runbook(runbook_id, lang=lang)
    review = review_runbook_id(runbook_id, context=context)
    return {
        "runbook_id": runbook_id,
        "title": str(runbook.get("title") or ""),
        "domain": str(runbook.get("domain") or ""),
        "audience": str(runbook.get("audience") or ""),
        "effect": str(runbook.get("effect") or ""),
        "requires_approval": bool(runbook.get("requires_approval")),
        "steps": list(runbook.get("steps") or []),
        "user_message_template": str(runbook.get("user_message_template") or ""),
        "score": _score_for_audience(runbook, audience, order_index=order_index),
        "review": review,
    }


def _candidate_from_noc_rule(
    rule_id: str,
    audience: str,
    lang: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    rule = NOC_RULE_RUNBOOKS.get(rule_id, NOC_RULE_RUNBOOKS["stable_observe"])
    diagnostic_state = str(rule.get("diagnostic_state") or "").strip()
    if diagnostic_state:
        payload = select_runbooks_for_diagnostic_state(
            diagnostic_state,
            audience=audience,
            lang=lang,
            max_items=1,
            context=context,
        )
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        if items:
            return items[0]
    return _hydrate_runbook_candidate(str(rule.get("runbook_id") or "rb.noc.ui-snapshot.check"), audience, lang, context)


def _primary_noc_rule(noc: Dict[str, Any]) -> Dict[str, Any]:
    summary = _dict_value(noc.get("summary"))
    incident = _dict_value(noc.get("incident_summary") or summary.get("incident_summary"))
    affected_scope = _dict_value(noc.get("affected_scope") or noc.get("blast_radius") or summary.get("blast_radius"))
    config_drift = _dict_value(noc.get("config_drift_health") or noc.get("config_drift"))
    resolution_health = _dict_value(noc.get("resolution_health"))
    service_health = _dict_value(noc.get("service_health"))
    path_health = _dict_value(noc.get("path_health"))
    availability = _dict_value(noc.get("availability"))
    capacity = _dict_value(noc.get("capacity_health") or noc.get("capacity"))
    client_inventory = _dict_value(noc.get("client_inventory_health") or noc.get("client_inventory"))

    probable_cause = str(incident.get("probable_cause") or "").strip().lower()
    if probable_cause == "config_drift":
        return {"rule_id": "config_drift", "severity": 80}
    if probable_cause == "resolution_failure":
        return {"rule_id": "resolution_failure", "severity": 75}
    if probable_cause == "service_assurance_failure":
        return {"rule_id": "service_assurance_failure", "severity": 70}
    if probable_cause in {"path_degradation", "uplink_degradation"}:
        return {"rule_id": "path_degradation", "severity": 65}
    if probable_cause == "client_inventory_anomaly":
        return {"rule_id": "client_inventory_anomaly", "severity": 60}
    if probable_cause == "capacity_pressure":
        return {"rule_id": "capacity_pressure", "severity": 55}

    if _is_problem_state(config_drift, "label", "status", "baseline_state"):
        return {"rule_id": "config_drift", "severity": 80}
    if _is_problem_state(resolution_health, "label", "status", "state"):
        return {"rule_id": "resolution_failure", "severity": 75}
    if _is_problem_state(service_health, "label", "status", "state"):
        return {"rule_id": "service_assurance_failure", "severity": 70}
    if _is_problem_state(path_health, "label", "status") or _is_problem_state(availability, "label", "status") or _string_list(affected_scope.get("affected_uplinks")):
        return {"rule_id": "path_degradation", "severity": 65}

    unknown_clients = int(client_inventory.get("unknown_client_count") or 0)
    unauthorized_clients = int(client_inventory.get("unauthorized_client_count") or 0)
    mismatched_clients = int(client_inventory.get("inventory_mismatch_count") or 0)
    stale_sessions = int(client_inventory.get("stale_session_count") or 0)
    if (
        _is_problem_state(client_inventory, "label", "status", "state")
        or unknown_clients > 0
        or unauthorized_clients > 0
        or mismatched_clients > 0
        or stale_sessions > 0
    ):
        return {"rule_id": "client_inventory_anomaly", "severity": 60}

    utilization = float(capacity.get("utilization_pct") or 0.0)
    if _is_problem_state(capacity, "label", "status", "state") or utilization >= 75.0:
        return {"rule_id": "capacity_pressure", "severity": 55}
    return {"rule_id": "stable_observe", "severity": 20}


def _noc_reasoning(
    rule_id: str,
    noc: Dict[str, Any],
) -> Dict[str, Any]:
    incident = _dict_value(noc.get("incident_summary") or _dict_value(noc.get("summary")).get("incident_summary"))
    affected_scope = _dict_value(noc.get("affected_scope") or noc.get("blast_radius") or _dict_value(noc.get("summary")).get("blast_radius"))
    config_drift = _dict_value(noc.get("config_drift_health") or noc.get("config_drift"))
    resolution_health = _dict_value(noc.get("resolution_health"))
    service_health = _dict_value(noc.get("service_health"))
    capacity = _dict_value(noc.get("capacity_health") or noc.get("capacity"))
    client_inventory = _dict_value(noc.get("client_inventory_health") or noc.get("client_inventory"))
    evidence_ids: List[str] = []
    for payload in (config_drift, resolution_health, service_health, capacity, client_inventory):
        evidence_ids.extend(_string_list(payload.get("evidence_ids")))
    supporting_symptoms = _string_list(incident.get("supporting_symptoms"))
    if not evidence_ids:
        evidence_ids.extend(supporting_symptoms[:4])

    if rule_id == "config_drift":
        changed_fields = _string_list(config_drift.get("changed_fields"))
        return {
            "why_this_runbook": "Health-impacting config drift was detected and should be compared against the last known good baseline.",
            "operator_checks": [
                "Review changed health-relevant fields against the current baseline.",
                "Confirm whether the change was approved before making any corrective action.",
                "Validate uplink, probe target, and policy marker consistency in the current snapshot.",
            ] + ([f"Changed fields: {', '.join(changed_fields[:3])}."] if changed_fields else []),
            "escalation_hint": "Escalate if the drift is unapproved or if restoring the baseline does not recover service health.",
            "evidence_ids": evidence_ids[:8],
        }
    if rule_id == "resolution_failure":
        failed_targets = _string_list(resolution_health.get("failed_targets"))
        return {
            "why_this_runbook": "Resolver failures are the clearest current symptom and need DNS-specific read-only checks first.",
            "operator_checks": [
                "Check gateway, resolver reachability, and DNS target health before changing control mode.",
                "Confirm whether failures are local to the edge or shared across the affected segment.",
            ] + ([f"Failed targets: {', '.join(failed_targets[:3])}."] if failed_targets else []),
            "escalation_hint": "Escalate if resolver failures persist after gateway and default-route verification.",
            "evidence_ids": evidence_ids[:8],
        }
    if rule_id == "service_assurance_failure":
        degraded_targets = _string_list(service_health.get("degraded_targets"))
        return {
            "why_this_runbook": "Service assurance degraded before stronger containment criteria were met.",
            "operator_checks": [
                "Run read-only service status checks and confirm which targets are degraded or down.",
                "Compare service failures with the currently affected uplinks and segments.",
            ] + ([f"Service targets: {', '.join(degraded_targets[:3])}."] if degraded_targets else []),
            "escalation_hint": "Escalate if multiple service targets remain degraded after read-only verification.",
            "evidence_ids": evidence_ids[:8],
        }
    if rule_id == "path_degradation":
        affected_uplinks = _string_list(affected_scope.get("affected_uplinks"))
        return {
            "why_this_runbook": "Path degradation is affecting current reachability and should be verified at the uplink and default-route layer first.",
            "operator_checks": [
                "Confirm uplink state, default route, and gateway reachability with read-only checks.",
                "Compare the impacted scope before assuming a wider upstream outage.",
            ] + ([f"Affected uplinks: {', '.join(affected_uplinks[:3])}."] if affected_uplinks else []),
            "escalation_hint": "Escalate if uplink reachability remains degraded after route verification.",
            "evidence_ids": evidence_ids[:8],
        }
    if rule_id == "client_inventory_anomaly":
        return {
            "why_this_runbook": "Client inventory drift or unknown sessions were detected and need operator review before stronger action.",
            "operator_checks": [
                "Review unknown, unauthorized, and mismatched sessions in the latest inventory snapshot.",
                "Confirm whether new sessions align with the expected segment and SoT policy.",
                f"Inventory counts: unknown={int(client_inventory.get('unknown_client_count') or 0)}, unauthorized={int(client_inventory.get('unauthorized_client_count') or 0)}, mismatch={int(client_inventory.get('inventory_mismatch_count') or 0)}.",
            ],
            "escalation_hint": "Escalate if unauthorized or spreading unknown sessions remain after inventory confirmation.",
            "evidence_ids": evidence_ids[:8],
        }
    if rule_id == "capacity_pressure":
        return {
            "why_this_runbook": "Current utilization or traffic concentration suggests congestion pressure rather than an immediate outage.",
            "operator_checks": [
                "Confirm utilization trend and top talker concentration across the bounded observation window.",
                "Check whether impacted clients overlap with the current blast-radius estimate before throttling.",
            ] + ([f"Capacity signals: {', '.join(_string_list(capacity.get('signals'))[:3])}."] if _string_list(capacity.get("signals")) else []),
            "escalation_hint": "Escalate if elevated utilization persists across windows or impacts critical clients.",
            "evidence_ids": evidence_ids[:8],
        }
    return {
        "why_this_runbook": "No dominant NOC failure was confirmed, so the snapshot check remains the safest first step.",
        "operator_checks": [
            "Capture the latest UI and service snapshot before making any control change.",
            "Keep monitoring until a stronger NOC symptom or operator request appears.",
        ],
        "escalation_hint": "Escalate if the state leaves stable or if new symptoms appear during observation.",
        "evidence_ids": evidence_ids[:8],
    }


def select_noc_runbook_support(
    noc: Dict[str, Any],
    audience: str = "professional",
    lang: str = "ja",
    context: Dict[str, Any] | None = None,
    ai_governance: Any | None = None,
    ai_invoker: Callable[[Dict[str, Any]], Dict[str, Any]] | None = None,
    source: str = "dashboard",
) -> Dict[str, Any]:
    ctx = dict(context) if isinstance(context, dict) else {}
    ctx.setdefault("lang", lang)
    ctx.setdefault("audience", audience)
    ctx.setdefault("source", source)
    primary = _primary_noc_rule(noc if isinstance(noc, dict) else {})
    rule_id = str(primary.get("rule_id") or "stable_observe")
    candidate = _candidate_from_noc_rule(rule_id, audience, lang, ctx)
    reasoning = _noc_reasoning(rule_id, noc if isinstance(noc, dict) else {})
    support = {
        "ok": True,
        "rule_id": rule_id,
        "risk_score": int(primary.get("severity") or 0),
        "runbook_candidate_id": str(candidate.get("runbook_id") or ""),
        "why_this_runbook": str(reasoning.get("why_this_runbook") or ""),
        "operator_checks": _string_list(reasoning.get("operator_checks"))[:4],
        "escalation_hint": str(reasoning.get("escalation_hint") or ""),
        "candidate_scope": rule_id,
        "reviewed_runbook": candidate,
        "operator_note": str(reasoning.get("why_this_runbook") or ""),
        "evidence_ids": _string_list(reasoning.get("evidence_ids"))[:8],
        "ai_used": False,
        "ai_summary": "",
        "ai_advice": "",
    }
    if ai_governance is not None and ai_invoker is not None:
        ai_result = ai_governance.invoke(
            context={
                "trace_id": str(ctx.get("trace_id") or ""),
                "source": source,
                "intent": "summary",
            },
            raw_payload={
                "trace_id": str(ctx.get("trace_id") or ""),
                "source": source,
                "subject": "noc_runbook_support",
                "intent": "summary",
                "risk_score": int(primary.get("severity") or 0),
                "category": rule_id,
                "summary": f"{support['why_this_runbook']} {' '.join(support['operator_checks'][:2])}".strip(),
                "evidence_ids": support["evidence_ids"],
                "candidate_scope": support["runbook_candidate_id"],
            },
            invoker=ai_invoker,
        )
        support["ai_summary"] = str(ai_result.get("summary") or "")
        support["ai_advice"] = str(ai_result.get("advice") or "")
        support["ai_used"] = bool(support["ai_summary"] or support["ai_advice"])
        if support["ai_summary"]:
            support["operator_note"] = support["ai_summary"]
    return support


def select_runbooks_for_diagnostic_state(
    diagnostic_state: str,
    audience: str = "temporary",
    lang: str = "ja",
    max_items: int = 3,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    state_id = str(diagnostic_state or "").strip()
    candidates = STATE_RUNBOOKS.get(state_id, ["rb.user.first-contact.network-issue", "rb.noc.ui-snapshot.check"])
    ctx = dict(context) if isinstance(context, dict) else {}
    ctx.setdefault("lang", lang)
    ctx.setdefault("audience", audience)
    ctx.setdefault("diagnostic_state", state_id)
    items: List[Dict[str, Any]] = []
    for order_index, runbook_id in enumerate(candidates):
        runbook = get_runbook(runbook_id, lang=lang)
        review = review_runbook_id(runbook_id, context=ctx)
        items.append(
            {
                "runbook_id": runbook_id,
                "title": str(runbook.get("title") or ""),
                "domain": str(runbook.get("domain") or ""),
                "audience": str(runbook.get("audience") or ""),
                "effect": str(runbook.get("effect") or ""),
                "requires_approval": bool(runbook.get("requires_approval")),
                "steps": list(runbook.get("steps") or []),
                "user_message_template": str(runbook.get("user_message_template") or ""),
                "score": _score_for_audience(runbook, audience, order_index=order_index),
                "review": review,
            }
        )
    items.sort(key=lambda item: (-int(item.get("score", 0)), item["runbook_id"]))
    return {
        "ok": True,
        "diagnostic_state": state_id,
        "audience": audience,
        "items": items[: max(1, min(max_items, 10))],
    }
