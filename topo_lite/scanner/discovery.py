from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from typing import Callable, TYPE_CHECKING

from db.repository import TopoLiteRepository

if TYPE_CHECKING:
    from configuration import TopoLiteConfig
    from logging_utils import TopoLiteLoggers


@dataclass(slots=True)
class DiscoveryJob:
    interface: str = "eth0"
    subnets: list[str] = field(default_factory=lambda: ["192.168.40.0/24"])
    target_ports: list[int] = field(default_factory=lambda: [22, 80, 443])
    interval_seconds: int = 300


@dataclass(slots=True, frozen=True)
class ArpDiscoveryResult:
    ip: str
    mac: str
    vendor: str | None
    subnet: str
    source: str = "arp-scan"


class DiscoveryRunError(RuntimeError):
    """Raised when an arp-scan execution fails."""


def build_default_job() -> DiscoveryJob:
    return DiscoveryJob()


def build_job_from_config(config: "TopoLiteConfig") -> DiscoveryJob:
    return DiscoveryJob(
        interface=config.interface,
        subnets=list(config.subnets),
        target_ports=list(config.target_ports),
        interval_seconds=config.scan_intervals.discovery_seconds,
    )


def build_arp_scan_command(interface: str, subnet: str) -> list[str]:
    return ["arp-scan", "--interface", interface, subnet]


def parse_arp_scan_output(output: str, *, subnet: str) -> list[ArpDiscoveryResult]:
    results: list[ArpDiscoveryResult] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        ip, mac = parts[0], parts[1].lower()
        if not _looks_like_ipv4(ip) or not _looks_like_mac(mac):
            continue
        vendor = " ".join(parts[2:]).strip()
        results.append(
            ArpDiscoveryResult(
                ip=ip,
                mac=mac,
                vendor=None if vendor == "(Unknown)" else vendor,
                subnet=subnet,
            )
        )
    return results


def run_arp_scan(
    *,
    interface: str,
    subnet: str,
    runner: Callable[[list[str], int], subprocess.CompletedProcess[str]] | None = None,
    timeout: int = 30,
) -> list[ArpDiscoveryResult]:
    command = build_arp_scan_command(interface, subnet)
    run = runner or _default_runner
    try:
        completed = run(command, timeout)
    except FileNotFoundError as error:
        raise DiscoveryRunError(f"arp-scan is not installed: {error.filename}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.strip() if completed.stderr else ""
        raise DiscoveryRunError(f"arp-scan failed for {subnet}: {stderr or 'unknown error'}")
    return parse_arp_scan_output(completed.stdout, subnet=subnet)


def discover_hosts(
    *,
    config: "TopoLiteConfig",
    repository: TopoLiteRepository,
    runner: Callable[[list[str], int], subprocess.CompletedProcess[str]] | None = None,
    loggers: "TopoLiteLoggers | None" = None,
    timeout: int = 30,
) -> dict[str, object]:
    job = build_job_from_config(config)
    scan_run = repository.create_scan_run(
        scan_kind="arp_discovery",
        details={
            "interface": job.interface,
            "subnets": job.subnets,
            "source": "arp-scan",
        },
    )
    errors: list[dict[str, str]] = []
    host_count = 0
    observation_count = 0
    scanned_subnets = 0
    discovered_hosts: list[dict[str, object]] = []

    if loggers is not None:
        from logging_utils import log_event

        log_event(
            loggers.scanner,
            "discovery_started",
            "ARP discovery started",
            interface=job.interface,
            subnets=job.subnets,
            scan_run_id=scan_run["id"],
        )

    for subnet in job.subnets:
        try:
            results = run_arp_scan(interface=job.interface, subnet=subnet, runner=runner, timeout=timeout)
        except (DiscoveryRunError, subprocess.TimeoutExpired) as error:
            errors.append({"subnet": subnet, "error": str(error)})
            if loggers is not None:
                from logging_utils import log_event

                log_event(
                    loggers.scanner,
                    "discovery_subnet_failed",
                    "ARP discovery subnet failed",
                    interface=job.interface,
                    subnet=subnet,
                    scan_run_id=scan_run["id"],
                    error=str(error),
                )
            continue

        scanned_subnets += 1
        for result in results:
            host = repository.upsert_host(
                ip=result.ip,
                mac=result.mac,
                vendor=result.vendor,
                status="up",
            )
            repository.record_observation(
                host_id=host["id"],
                source=result.source,
                payload=asdict(result),
            )
            discovered_hosts.append(
                {
                    "host_id": host["id"],
                    "ip": result.ip,
                    "mac": result.mac,
                    "vendor": result.vendor,
                    "subnet": result.subnet,
                }
            )
            host_count += 1
            observation_count += 1

    status = _resolve_status(scanned_subnets, errors)
    finished = repository.finish_scan_run(
        scan_run["id"],
        status=status,
        details={
            "interface": job.interface,
            "subnets": job.subnets,
            "source": "arp-scan",
            "host_count": host_count,
            "observation_count": observation_count,
            "discovered_hosts": sorted(discovered_hosts, key=lambda item: (str(item["ip"]), int(item["host_id"]))),
            "errors": errors,
        },
    )

    if loggers is not None:
        from logging_utils import log_event

        log_event(
            loggers.scanner,
            "discovery_finished",
            "ARP discovery finished",
            interface=job.interface,
            subnets=job.subnets,
            scan_run_id=finished["id"],
            status=status,
            host_count=host_count,
            observation_count=observation_count,
            error_count=len(errors),
        )

    return {
        "scan_run_id": finished["id"],
        "status": status,
        "host_count": host_count,
        "observation_count": observation_count,
        "subnets_scanned": scanned_subnets,
        "errors": errors,
    }


def _default_runner(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)


def _resolve_status(scanned_subnets: int, errors: list[dict[str, str]]) -> str:
    if scanned_subnets == 0 and errors:
        return "failed"
    if errors:
        return "partial_failed"
    return "completed"


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _looks_like_mac(value: str) -> bool:
    parts = value.split(":")
    if len(parts) != 6:
        return False
    return all(len(part) == 2 and all(char in "0123456789abcdefABCDEF" for char in part) for part in parts)
