from __future__ import annotations

import ipaddress
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
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


@dataclass(slots=True, frozen=True)
class SupplementalDiscoveryResult:
    ip: str
    source: str
    subnet: str | None = None
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


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
    include_active_sources: bool = False,
    arp_cache_reader: Callable[[], str] | None = None,
    dhcp_lease_reader: Callable[[], str] | None = None,
    ping_runner: Callable[[str, int], bool] | None = None,
    tcp_discovery_runner: Callable[[str, list[int], float], int | None] | None = None,
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
    supplemental_hosts: list[dict[str, object]] = []
    source_counts: dict[str, int] = {}

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
            source_counts[result.source] = source_counts.get(result.source, 0) + 1

    supplemental_errors: list[dict[str, str]] = []
    primary_ips = {str(item["ip"]) for item in discovered_hosts}
    supplemental_results, source_errors = discover_supplemental_hosts(
        config=config,
        known_ips=primary_ips,
        timeout=timeout,
        include_active_sources=include_active_sources,
        arp_cache_reader=arp_cache_reader,
        dhcp_lease_reader=dhcp_lease_reader,
        ping_runner=ping_runner,
        tcp_discovery_runner=tcp_discovery_runner,
    )
    supplemental_errors.extend(source_errors)
    for result in supplemental_results:
        host = repository.upsert_host(
            ip=result.ip,
            mac=result.mac,
            vendor=result.vendor,
            hostname=result.hostname,
            status="up",
        )
        payload = {
            "ip": result.ip,
            "subnet": result.subnet,
            "source": result.source,
            "mac": result.mac,
            "hostname": result.hostname,
            **result.metadata,
        }
        repository.record_observation(
            host_id=host["id"],
            source=result.source,
            payload={key: value for key, value in payload.items() if value is not None},
        )
        supplemental_hosts.append(
            {
                "host_id": host["id"],
                "ip": result.ip,
                "source": result.source,
                "mac": result.mac,
                "hostname": result.hostname,
                "subnet": result.subnet,
            }
        )
        host_count += 1
        observation_count += 1
        source_counts[result.source] = source_counts.get(result.source, 0) + 1

    all_errors = errors + supplemental_errors
    status = _resolve_status(scanned_subnets, all_errors)
    finished = repository.finish_scan_run(
        scan_run["id"],
        status=status,
        details={
            "interface": job.interface,
            "subnets": job.subnets,
            "source": "arp-scan",
            "host_count": host_count,
            "observation_count": observation_count,
            "source_counts": source_counts,
            "discovered_hosts": sorted(discovered_hosts, key=lambda item: (str(item["ip"]), int(item["host_id"]))),
            "supplemental_hosts": sorted(supplemental_hosts, key=lambda item: (str(item["ip"]), str(item["source"]))),
            "errors": all_errors,
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
            error_count=len(all_errors),
            source_counts=source_counts,
        )

    return {
        "scan_run_id": finished["id"],
        "status": status,
        "host_count": host_count,
        "observation_count": observation_count,
        "subnets_scanned": scanned_subnets,
        "errors": all_errors,
        "source_counts": source_counts,
    }


def discover_supplemental_hosts(
    *,
    config: "TopoLiteConfig",
    known_ips: set[str],
    timeout: int = 30,
    include_active_sources: bool = False,
    arp_cache_reader: Callable[[], str] | None = None,
    dhcp_lease_reader: Callable[[], str] | None = None,
    ping_runner: Callable[[str, int], bool] | None = None,
    tcp_discovery_runner: Callable[[str, list[int], float], int | None] | None = None,
) -> tuple[list[SupplementalDiscoveryResult], list[dict[str, str]]]:
    results: list[SupplementalDiscoveryResult] = []
    errors: list[dict[str, str]] = []

    for source_name, loader in (
        ("arp-cache", lambda: parse_ip_neigh_output((arp_cache_reader or read_ip_neigh_cache)(), config.subnets)),
        ("dhcp-lease", lambda: parse_dhcp_leases((dhcp_lease_reader or read_dhcp_leases)(), config.subnets)),
    ):
        try:
            loaded = loader()
        except Exception as error:
            errors.append({"source": source_name, "error": str(error)})
            loaded = []
        for item in loaded:
            if item.ip in known_ips or any(result.ip == item.ip for result in results):
                continue
            results.append(item)

    if include_active_sources:
        try:
            candidates = candidate_ips_from_subnets(config.subnets)
        except ValueError as error:
            errors.append({"source": "subnet-candidates", "error": str(error)})
            candidates = []

        ping = ping_runner or run_icmp_ping
        tcp_discover = tcp_discovery_runner or run_tcp_connect_discovery
        for ip in candidates:
            if ip in known_ips or any(result.ip == ip for result in results):
                continue
            try:
                if ping(ip, timeout):
                    results.append(
                        SupplementalDiscoveryResult(
                            ip=ip,
                            source="icmp-ping",
                            subnet=_match_subnet(ip, config.subnets),
                        )
                    )
                    continue
            except Exception as error:
                errors.append({"source": "icmp-ping", "ip": ip, "error": str(error)})

            try:
                open_port = tcp_discover(ip, config.target_ports[:3], float(min(timeout, config.probe.timeout_seconds)))
            except Exception as error:
                errors.append({"source": "tcp-connect-discovery", "ip": ip, "error": str(error)})
                continue
            if open_port is not None:
                results.append(
                    SupplementalDiscoveryResult(
                        ip=ip,
                        source="tcp-connect-discovery",
                        subnet=_match_subnet(ip, config.subnets),
                        metadata={"open_port": open_port},
                    )
                )

    return results, errors


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


def parse_ip_neigh_output(output: str, subnets: list[str]) -> list[SupplementalDiscoveryResult]:
    results: list[SupplementalDiscoveryResult] = []
    for raw_line in output.splitlines():
        parts = raw_line.strip().split()
        if len(parts) < 4:
            continue
        ip = parts[0]
        if not _looks_like_ipv4(ip):
            continue
        mac = parts[4].lower() if len(parts) >= 5 and _looks_like_mac(parts[4].lower()) else None
        results.append(
            SupplementalDiscoveryResult(
                ip=ip,
                source="arp-cache",
                subnet=_match_subnet(ip, subnets),
                mac=mac,
            )
        )
    return [item for item in results if item.subnet]


def parse_dhcp_leases(output: str, subnets: list[str]) -> list[SupplementalDiscoveryResult]:
    results: list[SupplementalDiscoveryResult] = []
    current_ip: str | None = None
    current_mac: str | None = None
    current_hostname: str | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("lease ") and line.endswith("{"):
            current_ip = line.split()[1]
            current_mac = None
            current_hostname = None
            continue
        if line.startswith("hardware ethernet"):
            current_mac = line.removeprefix("hardware ethernet").strip().rstrip(";").lower()
            continue
        if line.startswith("client-hostname"):
            current_hostname = line.removeprefix("client-hostname").strip().rstrip(";").strip('"')
            continue
        if line == "}":
            if current_ip and _looks_like_ipv4(current_ip):
                subnet = _match_subnet(current_ip, subnets)
                if subnet:
                    results.append(
                        SupplementalDiscoveryResult(
                            ip=current_ip,
                            source="dhcp-lease",
                            subnet=subnet,
                            mac=current_mac if current_mac and _looks_like_mac(current_mac) else None,
                            hostname=current_hostname,
                        )
                    )
            current_ip = None
            current_mac = None
            current_hostname = None
    return results


def candidate_ips_from_subnets(subnets: list[str]) -> list[str]:
    candidates: list[str] = []
    for subnet in subnets:
        network = ipaddress.ip_network(subnet, strict=False)
        candidates.extend(str(host) for host in network.hosts())
    return candidates


def read_ip_neigh_cache() -> str:
    completed = subprocess.run(
        ["ip", "neigh", "show"],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    if completed.returncode != 0:
        raise DiscoveryRunError(f"ip neigh failed: {completed.stderr.strip() or 'unknown error'}")
    return completed.stdout


def read_dhcp_leases() -> str:
    for path in (
        Path("/var/lib/misc/dnsmasq.leases"),
        Path("/var/lib/dhcp/dhcpd.leases"),
    ):
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
    return ""


def run_icmp_ping(ip: str, timeout: int) -> bool:
    completed = subprocess.run(
        ["ping", "-c", "1", "-W", str(max(timeout, 1)), ip],
        capture_output=True,
        text=True,
        check=False,
        timeout=max(timeout + 1, 2),
    )
    return completed.returncode == 0


def run_tcp_connect_discovery(ip: str, ports: list[int], timeout_seconds: float) -> int | None:
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout_seconds):
                return port
        except OSError:
            continue
    return None


def _match_subnet(ip: str, subnets: list[str]) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for subnet in subnets:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            continue
        if address in network:
            return subnet
    return None
