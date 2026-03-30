from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
from dataclasses import dataclass
from html import unescape
from typing import Callable, TYPE_CHECKING
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from db.repository import TopoLiteRepository

if TYPE_CHECKING:
    from configuration import TopoLiteConfig
    from logging_utils import TopoLiteLoggers


TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
HTTP_PORTS = {80: "http", 8000: "http", 8080: "http", 443: "https", 8443: "https"}
TLS_PORTS = {443, 8443}
MDNS_PORTS = {5353}


@dataclass(slots=True, frozen=True)
class BannerObservation:
    host_id: int
    port: int
    source: str
    payload: dict[str, object]


def collect_banner_observations(
    *,
    config: "TopoLiteConfig",
    repository: TopoLiteRepository,
    loggers: "TopoLiteLoggers | None" = None,
    host_ids: list[int] | None = None,
    http_fetcher: Callable[[str, str, int, float], dict[str, object] | None] | None = None,
    tls_fetcher: Callable[[str, int, float], dict[str, object] | None] | None = None,
    mdns_fetcher: Callable[[str], str | None] | None = None,
) -> dict[str, object]:
    fetch_http = http_fetcher or fetch_http_banner
    fetch_tls = tls_fetcher or fetch_tls_banner
    fetch_mdns = mdns_fetcher or fetch_mdns_name

    banner_timeout = min(float(config.probe.timeout_seconds), 2.0)
    observations: list[BannerObservation] = []
    errors: list[dict[str, object]] = []
    allowed_host_ids = set(host_ids or [])

    for host in repository.list_hosts():
        host_id = int(host["id"])
        if allowed_host_ids and host_id not in allowed_host_ids:
            continue
        ip = str(host["ip"])
        services = [
            service
            for service in repository.list_services(host_id)
            if str(service["state"]) == "open"
        ]

        for service in services:
            port = int(service["port"])

            if port in HTTP_PORTS:
                scheme = HTTP_PORTS[port]
                try:
                    payload = fetch_http(ip, scheme, port, banner_timeout)
                except Exception as error:
                    errors.append({"host_id": host_id, "ip": ip, "port": port, "source": "http-banner", "error": str(error)})
                else:
                    if payload:
                        observations.append(BannerObservation(host_id=host_id, port=port, source="http-banner", payload=payload))

            if port in TLS_PORTS:
                try:
                    payload = fetch_tls(ip, port, banner_timeout)
                except Exception as error:
                    errors.append({"host_id": host_id, "ip": ip, "port": port, "source": "tls-banner", "error": str(error)})
                else:
                    if payload:
                        observations.append(BannerObservation(host_id=host_id, port=port, source="tls-banner", payload=payload))

            if port in MDNS_PORTS:
                try:
                    name = fetch_mdns(ip)
                except Exception as error:
                    errors.append({"host_id": host_id, "ip": ip, "port": port, "source": "mdns-name", "error": str(error)})
                else:
                    if name:
                        observations.append(
                            BannerObservation(
                                host_id=host_id,
                                port=port,
                                source="mdns-name",
                                payload={"name": name, "ip": ip, "port": port},
                            )
                        )

    for observation in observations:
        repository.record_observation(
            host_id=observation.host_id,
            source=observation.source,
            payload={"port": observation.port, **observation.payload},
        )
        service = next(
            (
                item
                for item in repository.list_services(observation.host_id)
                if int(item["port"]) == observation.port and str(item["state"]) == "open"
            ),
            None,
        )
        if service is not None:
            repository.upsert_service(
                host_id=observation.host_id,
                proto=str(service["proto"]),
                port=observation.port,
                state=str(service["state"]),
                service_name=_service_name_from_observation(observation),
                banner=_banner_summary(observation.payload),
            )

    if loggers is not None:
        from logging_utils import log_event

        log_event(
            loggers.scanner,
            "banner_probe_finished",
            "banner collection finished",
            observation_count=len(observations),
            error_count=len(errors),
        )

    return {
        "observation_count": len(observations),
        "errors": errors,
        "sources": sorted({observation.source for observation in observations}),
    }


def fetch_http_banner(ip: str, scheme: str, port: int, timeout_seconds: float) -> dict[str, object] | None:
    url = f"{scheme}://{ip}:{port}/"
    headers = {"User-Agent": "Azazel-Topo-Lite/0.1"}
    request = Request(url, headers=headers, method="GET")
    context = ssl._create_unverified_context() if scheme == "https" else None
    try:
        with urlopen(request, timeout=timeout_seconds, context=context) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
            server = response.headers.get("Server")
    except HTTPError as error:
        body = error.read(4096).decode("utf-8", errors="replace")
        server = error.headers.get("Server")
    except URLError:
        return None

    title = _extract_html_title(body)
    if not title and not server:
        return None
    payload: dict[str, object] = {"ip": ip, "port": port, "scheme": scheme}
    if title:
        payload["title"] = title
    if server:
        payload["server"] = server
    return payload


def fetch_tls_banner(ip: str, port: int, timeout_seconds: float) -> dict[str, object] | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                cert = tls_sock.getpeercert()
    except OSError:
        return None
    if not cert:
        return None

    subject = _flatten_x509_name(cert.get("subject", ()))
    issuer = _flatten_x509_name(cert.get("issuer", ()))
    if not subject and not issuer:
        return None
    payload: dict[str, object] = {"ip": ip, "port": port}
    if subject:
        payload["subject"] = subject
    if issuer:
        payload["issuer"] = issuer
    return payload


def fetch_mdns_name(ip: str) -> str | None:
    try:
        completed = subprocess.run(
            ["avahi-resolve-address", ip],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    parts = completed.stdout.strip().split("\t")
    if len(parts) < 2:
        return None
    return parts[-1].strip() or None


def _extract_html_title(body: str) -> str | None:
    match = TITLE_PATTERN.search(body or "")
    if not match:
        return None
    title = unescape(match.group(1)).strip()
    return title or None


def _flatten_x509_name(items: object) -> dict[str, str] | None:
    flattened: dict[str, str] = {}
    for group in items or ():
        for key, value in group:
            flattened[str(key)] = str(value)
    return flattened or None


def _service_name_from_observation(observation: BannerObservation) -> str | None:
    if observation.source == "http-banner":
        return "https" if str(observation.payload.get("scheme")) == "https" else "http"
    if observation.source == "tls-banner":
        return "tls"
    if observation.source == "mdns-name":
        return "mdns"
    return None


def _banner_summary(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)
