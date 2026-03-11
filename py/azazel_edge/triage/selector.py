from __future__ import annotations

from typing import Any, Dict, List

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
