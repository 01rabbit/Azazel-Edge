from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, TYPE_CHECKING

from classification import classify_hosts
from db.repository import TopoLiteRepository
from scanner.banner import collect_banner_observations
from scanner.probe import ProbeObservation, _chunked, _probe_single_service, tcp_connect_probe

if TYPE_CHECKING:
    from configuration import TopoLiteConfig
    from logging_utils import TopoLiteLoggers


DEEP_PROBE_SCAN_KIND = "deep_probe"
DEEP_PROBE_SOURCE = "tcp-connect-deep-probe"


def deep_probe_new_hosts(
    *,
    config: "TopoLiteConfig",
    repository: TopoLiteRepository,
    discovery_scan_run_id: int,
    loggers: "TopoLiteLoggers | None" = None,
    connector: Callable[[str, int, float], str] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    if not config.deep_probe.enabled:
        return _skipped("disabled")

    current_run = repository.get_scan_run(discovery_scan_run_id)
    if current_run is None:
        return _skipped("discovery_run_missing")

    if _has_existing_deep_probe(repository, discovery_scan_run_id):
        return _skipped("already_processed")

    current_details = _load_details(current_run)
    previous_run = repository.get_previous_scan_run(
        "arp_discovery",
        before_run_id=discovery_scan_run_id,
        statuses=("completed", "partial_failed"),
    )
    previous_details = _load_details(previous_run)
    current_hosts = _hydrate_hosts(repository, list(current_details.get("discovered_hosts", [])))
    new_hosts = _filter_new_hosts(current_hosts, list(previous_details.get("discovered_hosts", [])))
    target_hosts = _apply_recent_dedupe(repository, new_hosts, config.deep_probe.dedupe_window_seconds)

    if not target_hosts:
        return _skipped("no_new_hosts")

    scan_run = repository.create_scan_run(
        scan_kind=DEEP_PROBE_SCAN_KIND,
        details={
            "trigger_discovery_scan_run_id": discovery_scan_run_id,
            "target_ports": config.deep_probe.target_ports,
            "timeout_seconds": config.deep_probe.timeout_seconds,
            "dedupe_window_seconds": config.deep_probe.dedupe_window_seconds,
            "target_hosts": _serialize_target_hosts(target_hosts),
        },
    )
    run_connector = connector or tcp_connect_probe
    observations: list[ProbeObservation] = []
    errors: list[dict[str, object]] = []
    targets = [(host, port) for host in target_hosts for port in config.deep_probe.target_ports]

    if loggers is not None:
        from logging_utils import log_event

        log_event(
            loggers.scanner,
            "deep_probe_started",
            "deep probe started for newly discovered hosts",
            scan_run_id=scan_run["id"],
            trigger_discovery_scan_run_id=discovery_scan_run_id,
            host_count=len(target_hosts),
            target_count=len(targets),
            target_ports=config.deep_probe.target_ports,
        )

    for batch in _chunked(targets, config.probe.batch_size):
        batch_observations: list[ProbeObservation] = []
        with ThreadPoolExecutor(max_workers=config.probe.concurrency) as executor:
            futures = {
                executor.submit(
                    _probe_single_service,
                    host,
                    port,
                    config.deep_probe.timeout_seconds,
                    config.probe.retry_count,
                    config.probe.retry_backoff_seconds,
                    run_connector,
                    sleep_fn,
                ): (host, port)
                for host, port in batch
            }
            for future in as_completed(futures):
                host, port = futures[future]
                try:
                    observation = future.result()
                except Exception as error:
                    errors.append({"host_id": host["id"], "ip": host["ip"], "port": port, "error": str(error)})
                    continue
                deep_observation = ProbeObservation(
                    host_id=observation.host_id,
                    ip=observation.ip,
                    proto=observation.proto,
                    port=observation.port,
                    state=observation.state,
                    source=DEEP_PROBE_SOURCE,
                    attempts=observation.attempts,
                    duration_ms=observation.duration_ms,
                )
                observations.append(deep_observation)
                batch_observations.append(deep_observation)

        repository.bulk_upsert_services_and_observations(
            entries=[
                {
                    "host_id": observation.host_id,
                    "proto": observation.proto,
                    "port": observation.port,
                    "state": observation.state,
                    "source": observation.source,
                    "payload": asdict(observation),
                }
                for observation in batch_observations
            ]
        )

    target_host_ids = [int(host["id"]) for host in target_hosts]
    banner_summary = collect_banner_observations(
        config=config,
        repository=repository,
        loggers=loggers,
        host_ids=target_host_ids,
    )
    classification_summary = classify_hosts(
        repository,
        loggers=loggers,
        host_ids=target_host_ids,
    )
    service_count = len(observations)
    state_counts = {
        "open": sum(1 for observation in observations if observation.state == "open"),
        "closed": sum(1 for observation in observations if observation.state == "closed"),
        "timeout": sum(1 for observation in observations if observation.state == "timeout"),
    }
    status = "completed" if not errors else "partial_failed"
    finished = repository.finish_scan_run(
        int(scan_run["id"]),
        status=status,
        details={
            "trigger_discovery_scan_run_id": discovery_scan_run_id,
            "target_ports": config.deep_probe.target_ports,
            "timeout_seconds": config.deep_probe.timeout_seconds,
            "dedupe_window_seconds": config.deep_probe.dedupe_window_seconds,
            "host_count": len(target_hosts),
            "service_count": service_count,
            "state_counts": state_counts,
            "target_hosts": _serialize_target_hosts(target_hosts),
            "services": sorted(
                [asdict(observation) for observation in observations],
                key=lambda item: (int(item["host_id"]), str(item["proto"]), int(item["port"])),
            ),
            "banner_summary": banner_summary,
            "classification_summary": classification_summary,
            "errors": errors,
        },
    )

    if loggers is not None:
        from logging_utils import append_audit_record, log_event

        append_audit_record(
            loggers.audit,
            "deep_probe_completed",
            actor="system",
            scan_run_id=finished["id"],
            trigger_discovery_scan_run_id=discovery_scan_run_id,
            status=status,
            host_count=len(target_hosts),
            service_count=service_count,
        )
        log_event(
            loggers.scanner,
            "deep_probe_finished",
            "deep probe finished",
            scan_run_id=finished["id"],
            trigger_discovery_scan_run_id=discovery_scan_run_id,
            status=status,
            host_count=len(target_hosts),
            service_count=service_count,
            error_count=len(errors),
        )

    return {
        "scan_run_id": int(finished["id"]),
        "status": status,
        "host_count": len(target_hosts),
        "service_count": service_count,
        "errors": errors,
        "target_hosts": _serialize_target_hosts(target_hosts),
        "banner_summary": banner_summary,
        "classification_summary": classification_summary,
        "state_counts": state_counts,
    }


def _hydrate_hosts(repository: TopoLiteRepository, discovered_hosts: list[dict[str, Any]]) -> list[dict[str, object]]:
    hydrated: list[dict[str, object]] = []
    for item in discovered_hosts:
        host_id = int(item["host_id"])
        host = repository.get_host(host_id)
        if host is not None:
            hydrated.append(host)
    return hydrated


def _filter_new_hosts(
    current_hosts: list[dict[str, object]],
    previous_hosts: list[dict[str, object]],
) -> list[dict[str, object]]:
    previous_ips = {str(item.get("ip")) for item in previous_hosts}
    return [host for host in current_hosts if str(host.get("ip")) not in previous_ips]


def _serialize_target_hosts(hosts: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "host_id": int(host["id"]),
            "ip": str(host["ip"]),
            "hostname": host.get("hostname"),
        }
        for host in hosts
    ]


def _load_details(scan_run: dict[str, Any] | None) -> dict[str, Any]:
    if scan_run is None:
        return {}
    return json.loads(str(scan_run["details_json"]) or "{}")


def _has_existing_deep_probe(repository: TopoLiteRepository, discovery_scan_run_id: int) -> bool:
    for scan_run in reversed(repository.list_scan_runs()):
        if str(scan_run["scan_kind"]) != DEEP_PROBE_SCAN_KIND:
            continue
        details = _load_details(scan_run)
        trigger_run_id = details.get("trigger_discovery_scan_run_id")
        if isinstance(trigger_run_id, int) and trigger_run_id == discovery_scan_run_id:
            return True
    return False


def _apply_recent_dedupe(
    repository: TopoLiteRepository,
    target_hosts: list[dict[str, object]],
    dedupe_window_seconds: int,
) -> list[dict[str, object]]:
    if dedupe_window_seconds <= 0:
        return target_hosts
    threshold = datetime.now(UTC) - timedelta(seconds=dedupe_window_seconds)
    recently_probed_ips: set[str] = set()
    for scan_run in reversed(repository.list_scan_runs()):
        if str(scan_run["scan_kind"]) != DEEP_PROBE_SCAN_KIND:
            continue
        started_at = _parse_timestamp(str(scan_run["started_at"]))
        if started_at is None or started_at < threshold:
            continue
        details = _load_details(scan_run)
        for item in details.get("target_hosts", []):
            recently_probed_ips.add(str(item.get("ip")))
    return [host for host in target_hosts if str(host.get("ip")) not in recently_probed_ips]


def _parse_timestamp(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _skipped(reason: str) -> dict[str, object]:
    return {
        "scan_run_id": None,
        "status": "skipped",
        "reason": reason,
        "host_count": 0,
        "service_count": 0,
        "target_hosts": [],
    }
