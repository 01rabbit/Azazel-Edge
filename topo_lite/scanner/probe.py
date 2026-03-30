from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Callable, TYPE_CHECKING

from db.repository import TopoLiteRepository

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


def probe_hosts(
    *,
    config: "TopoLiteConfig",
    repository: TopoLiteRepository,
    loggers: "TopoLiteLoggers | None" = None,
    connector: Callable[[str, int, float], str] | None = None,
) -> dict[str, object]:
    hosts = repository.list_hosts()
    scan_run = repository.create_scan_run(
        scan_kind="service_probe",
        details={
            "target_ports": config.target_ports,
            "timeout_seconds": config.probe.timeout_seconds,
            "concurrency": config.probe.concurrency,
        },
    )
    run_connector = connector or tcp_connect_probe
    observations: list[ProbeObservation] = []
    errors: list[dict[str, object]] = []

    if loggers is not None:
        from logging_utils import log_event

        log_event(
            loggers.scanner,
            "probe_started",
            "service probe started",
            scan_run_id=scan_run["id"],
            host_count=len(hosts),
            target_ports=config.target_ports,
            concurrency=config.probe.concurrency,
        )

    with ThreadPoolExecutor(max_workers=config.probe.concurrency) as executor:
        futures = {
            executor.submit(
                _probe_single_service,
                host,
                port,
                config.probe.timeout_seconds,
                run_connector,
            ): (host, port)
            for host in hosts
            for port in config.target_ports
        }
        for future in as_completed(futures):
            host, port = futures[future]
            try:
                observation = future.result()
            except Exception as error:
                errors.append({"host_id": host["id"], "ip": host["ip"], "port": port, "error": str(error)})
                continue
            observations.append(observation)

    service_count = 0
    for observation in observations:
        repository.upsert_service(
            host_id=observation.host_id,
            proto=observation.proto,
            port=observation.port,
            state=observation.state,
        )
        repository.record_observation(
            host_id=observation.host_id,
            source=observation.source,
            payload=asdict(observation),
        )
        service_count += 1

    status = "completed" if not errors else "partial_failed"
    finished = repository.finish_scan_run(
        scan_run["id"],
        status=status,
        details={
            "target_ports": config.target_ports,
            "timeout_seconds": config.probe.timeout_seconds,
            "concurrency": config.probe.concurrency,
            "service_count": service_count,
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
        )

    return {
        "scan_run_id": finished["id"],
        "status": status,
        "host_count": len(hosts),
        "service_count": service_count,
        "errors": errors,
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
    connector: Callable[[str, int, float], str],
) -> ProbeObservation:
    ip = str(host["ip"])
    state = connector(ip, port, timeout_seconds)
    return ProbeObservation(
        host_id=int(host["id"]),
        ip=ip,
        proto="tcp",
        port=port,
        state=state,
    )
