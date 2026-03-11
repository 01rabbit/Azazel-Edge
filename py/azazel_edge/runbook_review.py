from __future__ import annotations

import time
from typing import Any, Dict, List

from azazel_edge.i18n import translate_review_texts
from azazel_edge.runbooks import get_runbook, list_runbooks


def _as_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _review_record(
    reviewer: str,
    role: str,
    status: str,
    findings: List[str] | None = None,
    amendments: List[str] | None = None,
) -> Dict[str, Any]:
    return {
        "reviewer": reviewer,
        "role": role,
        "status": status,
        "findings": findings or [],
        "amendments": amendments or [],
    }


def _merge_status(current: str, candidate: str) -> str:
    order = {"approved": 0, "amend_required": 1, "rejected": 2}
    return candidate if order.get(candidate, 0) > order.get(current, 0) else current


def _soc_review(runbook: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[str] = []
    amendments: List[str] = []
    status = "approved"
    runbook_id = str(runbook.get("id") or "")
    risk = str(runbook.get("risk") or "low")
    effect = str(runbook.get("effect") or "")
    requires_approval = bool(runbook.get("requires_approval"))
    steps = _as_list(runbook.get("steps"))
    risk_score = int(context.get("risk_score") or 0)

    if str(runbook.get("domain") or "") == "soc" and not steps:
        status = _merge_status(status, "amend_required")
        findings.append("SOC runbook has no operator steps.")
        amendments.append("Add explicit triage steps before escalation.")
    if any(token in runbook_id for token in ("contain", "block", "quarantine")):
        if not requires_approval:
            status = _merge_status(status, "rejected")
            findings.append("Containment-style runbook lacks approval gate.")
            amendments.append("Set requires_approval=true for containment guidance.")
        if effect == "read_only":
            status = _merge_status(status, "amend_required")
            findings.append("Containment should not appear as read-only evidence collection.")
            amendments.append("Use operator_guidance or controlled_exec with approval.")
        if risk in {"low"}:
            status = _merge_status(status, "amend_required")
            findings.append("Containment runbook risk is understated.")
            amendments.append("Raise risk to at least medium for containment review.")
    if risk_score >= 85 and str(runbook.get("domain") or "") == "user":
        status = _merge_status(status, "amend_required")
        findings.append("User-facing guidance alone is insufficient for critical risk context.")
        amendments.append("Pair user guidance with a SOC or NOC operator runbook.")
    return _review_record("soc_analyst_ai", "SOC Analyst", status, findings, amendments)


def _noc_review(runbook: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[str] = []
    amendments: List[str] = []
    status = "approved"
    runbook_id = str(runbook.get("id") or "")
    domain = str(runbook.get("domain") or "")
    effect = str(runbook.get("effect") or "")
    steps = _as_list(runbook.get("steps"))
    user_message = str(runbook.get("user_message_template") or "").strip()
    question = str(context.get("question") or "").lower()

    if domain == "noc" and not steps:
        status = _merge_status(status, "amend_required")
        findings.append("NOC runbook has no operational checklist.")
        amendments.append("Add steps for interface, gateway, DNS, and service confirmation.")
    if any(token in runbook_id for token in ("default-route", "service.status", "ui-snapshot")) and effect != "read_only":
        status = _merge_status(status, "amend_required")
        findings.append("Observation runbook should stay read-only.")
        amendments.append("Use read_only for inspection-only NOC checks.")
    if domain == "noc" and not user_message:
        status = _merge_status(status, "amend_required")
        findings.append("NOC runbook has no operator-facing user update template.")
        amendments.append("Add a short status message for the affected user.")
    if any(token in question for token in ("wifi", "ssid", "接続", "network", "internet")) and domain not in {"noc", "user"}:
        status = _merge_status(status, "amend_required")
        findings.append("Selected runbook does not align with network symptom context.")
        amendments.append("Prefer a NOC or user-support runbook for connectivity issues.")
    return _review_record("noc_operator_ai", "NOC Operator", status, findings, amendments)


def _user_support_review(runbook: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[str] = []
    amendments: List[str] = []
    status = "approved"
    audience = str(runbook.get("audience") or "operator")
    effect = str(runbook.get("effect") or "")
    steps = _as_list(runbook.get("steps"))
    user_message = str(runbook.get("user_message_template") or "").strip()

    if audience == "beginner":
        if not user_message:
            status = _merge_status(status, "rejected")
            findings.append("Beginner-facing runbook lacks an exact user message.")
            amendments.append("Add one short plain-language message for the user.")
        if len(user_message) > 140:
            status = _merge_status(status, "amend_required")
            findings.append("Beginner-facing user message is too long.")
            amendments.append("Keep user messages concise and action-oriented.")
        if len(steps) < 2:
            status = _merge_status(status, "amend_required")
            findings.append("Beginner-facing runbook lacks enough guided steps.")
            amendments.append("Add step-by-step guidance with one instruction at a time.")
        if effect == "controlled_exec":
            status = _merge_status(status, "rejected")
            findings.append("Beginner-facing runbook must not trigger direct execution.")
            amendments.append("Use operator_guidance and keep execution behind an operator.")
    return _review_record("user_support_ai", "User Support", status, findings, amendments)


def _security_review(runbook: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[str] = []
    amendments: List[str] = []
    status = "approved"
    runbook_id = str(runbook.get("id") or "")
    effect = str(runbook.get("effect") or "")
    requires_approval = bool(runbook.get("requires_approval"))
    command = runbook.get("command")

    if effect == "controlled_exec" and not requires_approval:
        status = _merge_status(status, "rejected")
        findings.append("controlled_exec runbook lacks approval.")
        amendments.append("Require explicit approval before any controlled execution.")
    if effect == "operator_guidance" and isinstance(command, dict):
        status = _merge_status(status, "amend_required")
        findings.append("Guidance runbook should not hide executable commands.")
        amendments.append("Remove command block or convert to controlled_exec.")
    if any(token in runbook_id for token in ("password", "auth", "credential")) and effect != "operator_guidance":
        status = _merge_status(status, "rejected")
        findings.append("Credential-sensitive runbook is too permissive.")
        amendments.append("Restrict auth-related runbooks to operator_guidance only.")
    if any(token in runbook_id for token in ("contain", "block", "quarantine")) and not requires_approval:
        status = _merge_status(status, "rejected")
        findings.append("Network impacting action lacks explicit approval.")
        amendments.append("Containment-class runbooks must always require approval.")
    if context.get("audience") == "beginner" and effect == "controlled_exec":
        status = _merge_status(status, "rejected")
        findings.append("Beginner workflow cannot front a controlled execution runbook.")
        amendments.append("Gate controlled execution behind operator-only review.")
    return _review_record("security_architect_ai", "Security Architect", status, findings, amendments)


def _qa_review(runbook: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[str] = []
    amendments: List[str] = []
    status = "approved"
    title = str(runbook.get("title") or "").strip()
    effect = str(runbook.get("effect") or "")
    steps = _as_list(runbook.get("steps"))
    command = runbook.get("command")
    args_schema = runbook.get("args_schema") if isinstance(runbook.get("args_schema"), dict) else {}
    properties = args_schema.get("properties") if isinstance(args_schema, dict) else {}

    if not title:
        status = _merge_status(status, "rejected")
        findings.append("Runbook title is empty.")
        amendments.append("Provide a stable human-readable title.")
    if not steps:
        status = _merge_status(status, "amend_required")
        findings.append("Runbook has no steps.")
        amendments.append("Add at least one operator step.")
    if effect == "read_only" and not isinstance(command, dict):
        status = _merge_status(status, "rejected")
        findings.append("read_only runbook has no command.")
        amendments.append("Define a safe inspection command.")
    if effect == "controlled_exec" and not isinstance(command, dict):
        status = _merge_status(status, "rejected")
        findings.append("controlled_exec runbook has no command.")
        amendments.append("Define the command and gate it behind approval.")
    if isinstance(properties, dict) and len(properties) > 6:
        status = _merge_status(status, "amend_required")
        findings.append("Runbook has too many free-form inputs for beginner operations.")
        amendments.append("Reduce arguments or move details into operator guidance.")
    return _review_record("runbook_qa_ai", "Runbook QA", status, findings, amendments)


def review_runbook(runbook: Dict[str, Any], context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    ctx = context if isinstance(context, dict) else {}
    lang = str(ctx.get("lang") or "ja")
    reviewers = [
        _soc_review(runbook, ctx),
        _noc_review(runbook, ctx),
        _user_support_review(runbook, ctx),
        _security_review(runbook, ctx),
        _qa_review(runbook, ctx),
    ]
    final_status = "approved"
    required_changes: List[str] = []
    findings: List[str] = []
    for item in reviewers:
        final_status = _merge_status(final_status, str(item.get("status") or "approved"))
        required_changes.extend([x for x in item.get("amendments", []) if x not in required_changes])
        findings.extend([x for x in item.get("findings", []) if x not in findings])
    confidence = 0.92
    if final_status == "amend_required":
        confidence = 0.74
    elif final_status == "rejected":
        confidence = 0.58
    findings = translate_review_texts(findings, lang=lang)
    required_changes = translate_review_texts(required_changes, lang=lang)
    for item in reviewers:
        item["findings"] = translate_review_texts(item.get("findings", []), lang=lang)
        item["amendments"] = translate_review_texts(item.get("amendments", []), lang=lang)
    return {
        "ok": True,
        "runbook_id": str(runbook.get("id") or ""),
        "title": str(runbook.get("title") or ""),
        "final_status": final_status,
        "confidence": confidence,
        "reviewed_at": int(time.time()),
        "findings": findings,
        "required_changes": required_changes,
        "reviewers": reviewers,
    }


def review_runbook_id(runbook_id: str, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    lang = str((context or {}).get("lang") or "ja")
    runbook = get_runbook(runbook_id, lang=lang)
    return review_runbook(runbook, context=context)


def propose_runbooks(
    question: str,
    audience: str = "beginner",
    max_items: int = 3,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    q = str(question or "").strip()
    q_lower = q.lower()
    ctx = dict(context) if isinstance(context, dict) else {}
    ctx.setdefault("question", q)
    ctx.setdefault("audience", audience)
    candidates: List[Dict[str, Any]] = []

    def add(runbook_id: str, score: int, reason: str) -> None:
        for item in candidates:
            if item["runbook_id"] == runbook_id:
                item["score"] = max(item["score"], score)
                if reason not in item["selection_reasons"]:
                    item["selection_reasons"].append(reason)
                return
        candidates.append({"runbook_id": runbook_id, "score": score, "selection_reasons": [reason]})

    if any(token in q_lower for token in ("route", "gateway", "uplink", "internet", "回線", "ゲートウェイ")):
        add("rb.noc.default-route.check", 100, "uplink/gateway symptom")
        add("rb.noc.ui-snapshot.check", 85, "compare runtime view with actual route")
    if any(token in q_lower for token in ("service", "systemd", "起動", "停止", "サービス")):
        add("rb.noc.service.status.check", 100, "service health symptom")
    if any(token in q_lower for token in ("restart", "再起動")):
        add("rb.noc.service.restart.controlled", 85, "controlled restart candidate")
    if any(token in q_lower for token in ("epd", "display", "screen", "画面")):
        add("rb.ops.epd.state.check", 100, "display/EPD symptom")
        add("rb.noc.ui-snapshot.check", 80, "cross-check runtime state")
    if any(token in q_lower for token in ("log", "llm", "ai", "遅い", "失敗", "fallback", "ログ")):
        add("rb.ops.logs.ai.recent", 100, "ai/log symptom")
    if any(token in q_lower for token in ("wifi", "wi-fi", "ssid", "network", "connect", "接続", "つなが", "繋が", "ネット", "無線")):
        add("rb.user.first-contact.network-issue", 100, "beginner connectivity intake")
        add("rb.user.reconnect-guide", 95, "guided reconnect flow")
        add("rb.noc.ui-snapshot.check", 80, "verify actual network status")
    if any(token in q_lower for token in ("dns", "名前解決")):
        add("rb.noc.dns.failure.check", 100, "dns symptom")
        add("rb.user.first-contact.network-issue", 70, "user intake before noc action")
    if any(token in q_lower for token in ("dhcp", "ip address", "ipが", "アドレス")):
        add("rb.noc.dhcp.failure.check", 100, "dhcp/address symptom")
        add("rb.user.first-contact.network-issue", 75, "user intake before noc action")
    if any(token in q_lower for token in ("alert", "suricata", "侵入", "攻撃", "false positive", "誤検知")):
        add("rb.soc.alert.triage.basic", 100, "suricata alert triage")
    if any(token in q_lower for token in ("contain", "block", "isolate", "遮断", "隔離")):
        add("rb.soc.contain.recommend", 100, "containment decision")
    if not candidates:
        add("rb.noc.ui-snapshot.check", 70, "default runtime state inspection")
        add("rb.user.first-contact.network-issue", 65, "default beginner intake")

    def sort_bonus(runbook: Dict[str, Any]) -> int:
        bonus = 0
        runbook_audience = str(runbook.get("audience") or "")
        domain = str(runbook.get("domain") or "")
        effect = str(runbook.get("effect") or "")
        if audience == "beginner":
            if runbook_audience == "beginner":
                bonus += 20
            if domain == "user":
                bonus += 15
            if domain == "noc":
                bonus += 5
            if effect == "controlled_exec":
                bonus -= 30
        else:
            if runbook_audience == "operator":
                bonus += 15
            if domain in {"noc", "soc", "ops"}:
                bonus += 10
            if domain == "user":
                bonus -= 5
        return bonus

    hydrated: List[Dict[str, Any]] = []
    for candidate in candidates:
        try:
            runbook = get_runbook(candidate["runbook_id"])
        except Exception:
            continue
        candidate["effective_score"] = int(candidate["score"]) + sort_bonus(runbook)
        candidate["runbook"] = runbook
        hydrated.append(candidate)

    items: List[Dict[str, Any]] = []
    for candidate in sorted(hydrated, key=lambda item: (-int(item.get("effective_score", item["score"])), -item["score"], item["runbook_id"]))[: max(1, min(max_items, 10))]:
        runbook = candidate["runbook"]
        review = review_runbook(runbook, context=ctx)
        items.append(
            {
                "runbook_id": candidate["runbook_id"],
                "title": str(runbook.get("title") or ""),
                "domain": str(runbook.get("domain") or ""),
                "audience": str(runbook.get("audience") or ""),
                "effect": str(runbook.get("effect") or ""),
                "requires_approval": bool(runbook.get("requires_approval")),
                "args_schema": runbook.get("args_schema") if isinstance(runbook.get("args_schema"), dict) else {"type": "object", "properties": {}, "required": []},
                "steps": runbook.get("steps") if isinstance(runbook.get("steps"), list) else [],
                "user_message_template": str(runbook.get("user_message_template") or ""),
                "score": candidate["score"],
                "effective_score": candidate.get("effective_score", candidate["score"]),
                "selection_reasons": candidate["selection_reasons"],
                "review": review,
            }
        )
    return {
        "ok": True,
        "question": q,
        "audience": audience,
        "items": items,
    }


def list_reviewable_runbooks() -> List[Dict[str, Any]]:
    items = list_runbooks()
    return [item for item in items if str(item.get("id") or "").strip()]
