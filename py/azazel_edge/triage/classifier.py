from __future__ import annotations

from typing import Dict, List

from .loader import list_flows
from .types import IntentCandidate


RULES: Dict[str, List[str]] = {
    "wifi_connectivity": [
        "wifi", "wi-fi", "wireless", "ssid", "ap", "電波", "無線", "つながらない", "繋がらない",
    ],
    "wifi_reconnect": [
        "reconnect", "re-join", "again", "再接続", "戻らない", "切れた", "切断後",
    ],
    "wifi_onboarding": [
        "onboarding", "first time", "new device", "初回", "新しい端末", "新規端末", "登録",
    ],
    "dns_resolution": [
        "dns", "name resolve", "resolve", "resolver", "名前解決", "引けない", "ドメイン",
    ],
    "portal_access": [
        "portal", "login page", "captive", "認証画面", "ポータル", "ログイン画面",
    ],
    "uplink_reachability": [
        "internet", "gateway", "uplink", "wan", "route", "default route", "外部", "上位回線", "ゲートウェイ",
    ],
    "service_status": [
        "service", "daemon", "status", "restart", "systemctl", "落ちて", "停止", "サービス",
    ],
}


def _labels_by_intent(lang: str = "ja") -> Dict[str, str]:
    labels: Dict[str, str] = {}
    for flow in list_flows():
        label = flow.label_i18n.get(lang) or flow.label_i18n.get("en") or flow.flow_id
        for intent_id in flow.intents:
            labels[intent_id] = label
    return labels


def classify_intent_candidates(text: str, lang: str = "ja", limit: int = 2) -> List[IntentCandidate]:
    normalized = (text or "").strip().lower()
    if not normalized:
        return []
    labels = _labels_by_intent(lang=lang)
    scored: List[IntentCandidate] = []
    for intent_id, terms in RULES.items():
        hits = 0
        for term in terms:
            if term.lower() in normalized:
                hits += 1
        if hits <= 0:
            continue
        confidence = min(0.95, 0.35 + (hits * 0.18))
        scored.append(
            IntentCandidate(
                intent_id=intent_id,
                label=labels.get(intent_id, intent_id),
                confidence=round(confidence, 2),
                source="rule_first",
            )
        )
    scored.sort(key=lambda item: (-item.confidence, item.intent_id))
    return scored[: max(1, limit)]
