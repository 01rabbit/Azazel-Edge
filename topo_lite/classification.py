from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from db.repository import TopoLiteRepository

if TYPE_CHECKING:
    from logging_utils import TopoLiteLoggers


LABELS = {"smartphone", "laptop", "desktop", "printer", "network_device", "server", "iot", "unknown"}


@dataclass(slots=True, frozen=True)
class ClassificationResult:
    label: str
    confidence: float
    reason: dict[str, object]


def classify_hosts(
    repository: TopoLiteRepository,
    loggers: "TopoLiteLoggers | None" = None,
    host_ids: list[int] | None = None,
) -> dict[str, object]:
    updated = 0
    summary: dict[str, int] = {}
    allowed_host_ids = set(host_ids or [])
    for host in repository.list_hosts():
        host_id = int(host["id"])
        if allowed_host_ids and host_id not in allowed_host_ids:
            continue
        result = classify_host(
            host=host,
            services=repository.list_services(host_id),
            observations=repository.list_observations(host_id),
        )
        repository.set_classification(
            host_id=host_id,
            label=result.label,
            confidence=result.confidence,
            reason=result.reason,
        )
        updated += 1
        summary[result.label] = summary.get(result.label, 0) + 1

    if loggers is not None:
        from logging_utils import log_event

        log_event(
            loggers.scanner,
            "classification_finished",
            "host classification finished",
            host_count=updated,
            summary=summary,
        )

    return {"host_count": updated, "summary": summary}


def classify_host(*, host: dict[str, object], services: list[dict[str, object]], observations: list[dict[str, object]]) -> ClassificationResult:
    vendor = str(host.get("vendor") or "").lower()
    hostname = str(host.get("hostname") or "").lower()
    open_ports = {int(service["port"]) for service in services if str(service["state"]) == "open"}
    payloads_by_source = _group_observations(observations)

    candidates: list[ClassificationResult] = []

    if {631, 9100}.intersection(open_ports) or any(token in hostname for token in ("printer", "epson", "canon", "brother", "hp")):
        candidates.append(
            ClassificationResult(
                label="printer",
                confidence=0.95 if {631, 9100}.intersection(open_ports) else 0.78,
                reason={"ports": sorted({631, 9100}.intersection(open_ports)), "hostname": hostname},
            )
        )

    if any(token in vendor for token in ("ubiquiti", "cisco", "mikrotik", "juniper", "netgear")) or any(
        token in hostname for token in ("router", "gateway", "switch", "ap", "firewall")
    ):
        confidence = 0.9 if any(token in vendor for token in ("ubiquiti", "cisco", "mikrotik", "juniper")) else 0.72
        candidates.append(
            ClassificationResult(
                label="network_device",
                confidence=confidence,
                reason={"vendor": host.get("vendor"), "hostname": host.get("hostname"), "ports": sorted(open_ports)},
            )
        )

    if {22, 80}.issubset(open_ports) or {22, 443}.issubset(open_ports) or any(token in vendor for token in ("vmware", "supermicro", "dell")):
        candidates.append(
            ClassificationResult(
                label="server",
                confidence=0.84,
                reason={"ports": sorted(open_ports), "vendor": host.get("vendor")},
            )
        )

    if any(token in hostname for token in ("laptop", "notebook", "macbook", "thinkpad")):
        candidates.append(
            ClassificationResult(
                label="laptop",
                confidence=0.86,
                reason={"hostname": host.get("hostname")},
            )
        )
    elif any(token in vendor for token in ("lenovo", "apple", "dell", "hp")) and not open_ports.difference({22, 80, 443, 5353}):
        candidates.append(
            ClassificationResult(
                label="laptop",
                confidence=0.65,
                reason={"vendor": host.get("vendor"), "ports": sorted(open_ports)},
            )
        )

    if any(token in hostname for token in ("desktop", "workstation", "pc-", "desk")):
        candidates.append(
            ClassificationResult(
                label="desktop",
                confidence=0.8,
                reason={"hostname": host.get("hostname")},
            )
        )

    if any(token in vendor for token in ("apple", "samsung", "google")) and not open_ports.difference({5353}):
        candidates.append(
            ClassificationResult(
                label="smartphone",
                confidence=0.7,
                reason={"vendor": host.get("vendor"), "ports": sorted(open_ports)},
            )
        )

    if any(token in vendor for token in ("tuya", "ring", "nest", "amazon")) or payloads_by_source.get("mdns-name"):
        candidates.append(
            ClassificationResult(
                label="iot",
                confidence=0.68,
                reason={"vendor": host.get("vendor"), "mdns": payloads_by_source.get("mdns-name", [])[:2]},
            )
        )

    if payloads_by_source.get("http-banner"):
        http_banner = payloads_by_source["http-banner"][0]
        title = str(http_banner.get("title") or "").lower()
        server = str(http_banner.get("server") or "").lower()
        if any(token in title for token in ("printer", "airprint", "cups")) or "jetdirect" in server:
            candidates.append(
                ClassificationResult(
                    label="printer",
                    confidence=0.88,
                    reason={"http_title": http_banner.get("title"), "server": http_banner.get("server")},
                )
            )
        if any(token in title for token in ("router", "gateway", "switch")):
            candidates.append(
                ClassificationResult(
                    label="network_device",
                    confidence=0.82,
                    reason={"http_title": http_banner.get("title")},
                )
            )

    if payloads_by_source.get("tls-banner"):
        tls_banner = payloads_by_source["tls-banner"][0]
        subject = json.dumps(tls_banner.get("subject") or {}, sort_keys=True).lower()
        if any(token in subject for token in ("nas", "server", "vpn")):
            candidates.append(
                ClassificationResult(
                    label="server",
                    confidence=0.8,
                    reason={"subject": tls_banner.get("subject"), "issuer": tls_banner.get("issuer")},
                )
            )

    if candidates:
        best = max(candidates, key=lambda item: item.confidence)
        return ClassificationResult(
            label=best.label if best.label in LABELS else "unknown",
            confidence=round(best.confidence, 2),
            reason=best.reason,
        )

    return ClassificationResult(
        label="unknown",
        confidence=0.2,
        reason={"vendor": host.get("vendor"), "hostname": host.get("hostname"), "ports": sorted(open_ports)},
    )


def _group_observations(observations: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for item in observations:
        source = str(item["source"])
        payload = json.loads(str(item["payload_json"]))
        grouped.setdefault(source, []).append(payload)
    return grouped
