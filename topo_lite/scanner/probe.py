from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Callable, TYPE_CHECKING

from classification import classify_hosts
from db.repository import TopoLiteRepository
from scanner.banner import collect_banner_observations

if TYPE_CHECKING:
    from configuration import TopoLiteConfig
    from logging_utils import TopoLiteLoggers


@dataclass(slots=True, frozen=True)
class ProbeObservation:
    host_id: int
    ip: str
    proto: str
    port: int
    state: str
    source: str = "tcp-connect-probe"
    attempts: int = 1
    duration_ms: float = 0.0


def probe_hosts(
    *,
    config: "TopoLiteConfig",
    repository: TopoLiteRepository,
    loggers: "TopoLiteLoggers | None" = None,
    connector: Callable[[str, int, float], str] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    started_at = time.perf_counter()
    hosts = repository.list_hosts()
    scan_run = repository.create_scan_run(
        scan_kind="service_probe",
        details={
            "target_ports": config.target_ports,
            "timeout_seconds": config.probe.timeout_seconds,
            "concurrency": config.probe.concurrency,
            "retry_count": config.probe.retry_count,
            "retry_backoff_seconds": config.probe.retry_backoff_seconds,
            "batch_size": config.probe.batch_size,
        },
    )
    run_connector = connector or tcp_connect_probe
    observations: list[ProbeObservation] = []
    errors: list[dict[str, object]] = []
    targets = [(host, port) for host in hosts for port in config.target_ports]

    if loggers is not None:
        from logging_utils import log_event

        log_event(
            loggers.scanner,
            "probe_started",
            "service probe started",
            scan_run_id=scan_run["id"],
            host_count=len(hosts),
            target_count=len(targets),
            target_ports=config.target_ports,
            concurrency=config.probe.concurrency,
            retry_count=config.probe.retry_count,
            retry_backoff_seconds=config.probe.retry_backoff_seconds,
            batch_size=config.probe.batch_size,
        )

    for batch in _chunked(targets, config.probe.batch_size):
        batch_observations: list[ProbeObservation] = []
        with ThreadPoolExecutor(max_workers=config.probe.concurrency) as executor:
            futures = {
                executor.submit(
                    _probe_single_service,
                    host,
                    port,
                    config.probe.timeout_seconds,
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
                observations.append(observation)
                batch_observations.append(observation)

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

    service_count = len(observations)
    state_counts = {
        "open": sum(1 for observation in observations if observation.state == "open"),
        "closed": sum(1 for observation in observations if observation.state == "closed"),
        "timeout": sum(1 for observation in observations if observation.state == "timeout"),
    }
    banner_summary = collect_banner_observations(
        config=config,
        repository=repository,
        loggers=loggers,
    )
    classification_summary = classify_hosts(repository, loggers=loggers)
    duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
    average_attempts = round(
        sum(observation.attempts for observation in observations) / len(observations),
        2,
    ) if observations else 0.0

    status = "completed" if not errors else "partial_failed"
    finished = repository.finish_scan_run(
        scan_run["id"],
        status=status,
        details={
            "target_ports": config.target_ports,
            "timeout_seconds": config.probe.timeout_seconds,
            "concurrency": config.probe.concurrency,
            "retry_count": config.probe.retry_count,
            "retry_backoff_seconds": config.probe.retry_backoff_seconds,
            "batch_size": config.probe.batch_size,
            "service_count": service_count,
            "host_count": len(hosts),
            "target_count": len(targets),
            "duration_ms": duration_ms,
            "average_attempts": average_attempts,
            "state_counts": state_counts,
            "banner_summary": banner_summary,
            "classification_summary": classification_summary,
            "services": sorted(
                [asdict(observation) for observation in observations],
                key=lambda item: (int(item["host_id"]), str(item["proto"]), int(item["port"])),
            ),
            "errors": errors,
        },
    )

    if loggers is not None:
        from logging_utils import log_event

        log_event(
            loggers.scanner,
            "probe_finished",
            "service probe finished",
            scan_run_id=finished["id"],
            status=status,
            host_count=len(hosts),
            service_count=service_count,
            error_count=len(errors),
            duration_ms=duration_ms,
            average_attempts=average_attempts,
            state_counts=state_counts,
            banner_observation_count=banner_summary["observation_count"],
            classified_host_count=classification_summary["host_count"],
        )

    return {
        "scan_run_id": finished["id"],
        "status": status,
        "host_count": len(hosts),
        "service_count": service_count,
        "errors": errors,
        "duration_ms": duration_ms,
        "state_counts": state_counts,
        "banner_summary": banner_summary,
        "classification_summary": classification_summary,
    }


def tcp_connect_probe(ip: str, port: int, timeout_seconds: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds):
            return "open"
    except socket.timeout:
        return "timeout"
    except TimeoutError:
        return "timeout"
    except ConnectionRefusedError:
        return "closed"
    except OSError as error:
        if error.errno in {111, 113}:
            return "closed"
        if error.errno in {110}:
            return "timeout"
        return "closed"


def _probe_single_service(
    host: dict[str, object],
    port: int,
    timeout_seconds: float,
    retry_count: int,
    retry_backoff_seconds: float,
    connector: Callable[[str, int, float], str],
    sleep_fn: Callable[[float], None],
) -> ProbeObservation:
    ip = str(host["ip"])
    attempts = 0
    last_state = "closed"
    started_at = time.perf_counter()
    while attempts <= retry_count:
        attempts += 1
        last_state = connector(ip, port, timeout_seconds)
        if last_state != "timeout" or attempts > retry_count:
            break
        sleep_fn(retry_backoff_seconds * attempts)
    return ProbeObservation(
        host_id=int(host["id"]),
        ip=ip,
        proto="tcp",
        port=port,
        state=last_state,
        attempts=attempts,
        duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
    )


def _chunked(items: list[tuple[dict[str, object], int]], size: int):
    for index in range(0, len(items), size):
        yield items[index : index + size]
