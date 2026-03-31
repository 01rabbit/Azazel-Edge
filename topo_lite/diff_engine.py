from __future__ import annotations

import json
from typing import Any

from db.repository import TopoLiteRepository


SNAPSHOT_SCAN_KIND = "inventory_snapshot"
MANAGEMENT_PORTS = {22, 445, 3389}


def generate_inventory_diff(
    repository: TopoLiteRepository,
    *,
    missing_threshold_runs: int = 2,
) -> dict[str, object]:
    current_snapshot = build_inventory_snapshot(repository)
    previous_snapshot_run = repository.get_latest_scan_run(
        SNAPSHOT_SCAN_KIND,
        statuses=("completed",),
    )
    previous_snapshot = _load_snapshot(previous_snapshot_run)

    events: list[dict[str, Any]] = []
    next_hosts: dict[str, dict[str, Any]] = {}
    previous_hosts = {
        str(host["ip"]): dict(host)
        for host in previous_snapshot.get("hosts", [])
    }
    previous_hosts_by_mac = {
        str(host["mac"]): dict(host)
        for host in previous_snapshot.get("hosts", [])
        if host.get("mac")
    }
    current_hosts = {
        str(host["ip"]): dict(host)
        for host in current_snapshot["hosts"]
    }

    if previous_snapshot:
        for ip, current_host in current_hosts.items():
            previous_host = previous_hosts.get(ip)
            current_host["present"] = True
            current_host["missing_streak"] = 0
            next_hosts[ip] = current_host

            if previous_host is None:
                events.append(
                    repository.create_event(
                        host_id=int(current_host["host_id"]),
                        event_type="new_host",
                        severity=_event_severity(
                            "new_host",
                            current_host=current_host,
                            previous_host=None,
                            previous_hosts_by_mac=previous_hosts_by_mac,
                        ),
                        summary=f"new host discovered: {ip}",
                    )
                )
                for service in current_host["open_services"]:
                    events.append(
                        repository.create_event(
                            host_id=int(current_host["host_id"]),
                            event_type="service_added",
                            severity=_event_severity(
                                "service_added",
                                current_host=current_host,
                                previous_host=None,
                                service=service,
                                previous_hosts_by_mac=previous_hosts_by_mac,
                            ),
                            summary=f"service added on {ip}: {service['proto']}/{service['port']}",
                        )
                    )
                continue

            _append_change_events(repository, events, previous_host, current_host, previous_hosts_by_mac)

        for ip, previous_host in previous_hosts.items():
            if ip in current_hosts:
                continue
            missing_streak = int(previous_host.get("missing_streak", 0)) + 1
            retained_host = dict(previous_host)
            retained_host["present"] = False
            retained_host["missing_streak"] = missing_streak
            next_hosts[ip] = retained_host
            if missing_streak >= missing_threshold_runs and int(previous_host.get("missing_streak", 0)) < missing_threshold_runs:
                events.append(
                    repository.create_event(
                        host_id=int(previous_host["host_id"]),
                        event_type="host_missing",
                        severity=_event_severity(
                            "host_missing",
                            current_host=None,
                            previous_host=previous_host,
                            previous_hosts_by_mac=previous_hosts_by_mac,
                        ),
                        summary=f"host missing after {missing_streak} scans: {ip}",
                    )
                )
    else:
        for ip, current_host in current_hosts.items():
            current_host["present"] = True
            current_host["missing_streak"] = 0
            next_hosts[ip] = current_host

    snapshot_run = repository.create_scan_run(
        scan_kind=SNAPSHOT_SCAN_KIND,
        details={
            "discovery_scan_run_id": current_snapshot["discovery_scan_run_id"],
            "probe_scan_run_id": current_snapshot["probe_scan_run_id"],
            "missing_threshold_runs": missing_threshold_runs,
        },
    )
    finished = repository.finish_scan_run(
        snapshot_run["id"],
        status="completed",
        details={
            "discovery_scan_run_id": current_snapshot["discovery_scan_run_id"],
            "probe_scan_run_id": current_snapshot["probe_scan_run_id"],
            "missing_threshold_runs": missing_threshold_runs,
            "event_count": len(events),
            "hosts": sorted(next_hosts.values(), key=lambda item: str(item["ip"])),
        },
    )
    return {
        "snapshot_scan_run_id": int(finished["id"]),
        "event_count": len(events),
        "events": events,
        "baseline_created": not bool(previous_snapshot),
        "current_host_count": len(current_hosts),
    }


def build_inventory_snapshot(repository: TopoLiteRepository) -> dict[str, Any]:
    discovery_run = repository.get_latest_scan_run("arp_discovery", statuses=("completed", "partial_failed"))
    if discovery_run is None:
        raise RuntimeError("no completed arp_discovery scan run available")

    discovery_details = _load_details(discovery_run)
    discovered_hosts = discovery_details.get("discovered_hosts", [])
    classifications = {
        int(row["host_id"]): row
        for row in repository.list_classifications()
    }
    overrides = {
        int(row["host_id"]): row
        for row in repository.list_overrides()
    }
    probe_run = repository.get_latest_scan_run("service_probe", statuses=("completed", "partial_failed"))
    probe_services_by_host: dict[int, list[dict[str, Any]]] = {}
    probe_run_id: int | None = None
    if probe_run is not None:
        probe_run_id = int(probe_run["id"])
        probe_details = _load_details(probe_run)
        for service in probe_details.get("services", []):
            host_id = int(service["host_id"])
            if str(service["state"]) != "open":
                continue
            probe_services_by_host.setdefault(host_id, []).append(
                {
                    "proto": str(service["proto"]),
                    "port": int(service["port"]),
                }
            )

    hosts: list[dict[str, Any]] = []
    for item in discovered_hosts:
        host_id = int(item["host_id"])
        host = repository.get_host(host_id)
        if host is None:
            continue
        classification = classifications.get(host_id)
        override = overrides.get(host_id)
        effective_role = (
            str(override["fixed_role"]) if override and override.get("fixed_role")
            else classification["label"] if classification else None
        )
        hosts.append(
            {
                "host_id": host_id,
                "ip": str(host["ip"]),
                "mac": host["mac"],
                "vendor": host["vendor"],
                "hostname": host["hostname"],
                "role": effective_role,
                "open_services": sorted(
                    probe_services_by_host.get(host_id, []),
                    key=lambda service: (str(service["proto"]), int(service["port"])),
                ),
            }
        )

    return {
        "discovery_scan_run_id": int(discovery_run["id"]),
        "probe_scan_run_id": probe_run_id,
        "hosts": hosts,
    }


def _append_change_events(
    repository: TopoLiteRepository,
    events: list[dict[str, Any]],
    previous_host: dict[str, Any],
    current_host: dict[str, Any],
    previous_hosts_by_mac: dict[str, dict[str, Any]],
) -> None:
    host_id = int(current_host["host_id"])
    previous_hostname = previous_host.get("hostname")
    current_hostname = current_host.get("hostname")
    if previous_hostname != current_hostname:
        events.append(
            repository.create_event(
                host_id=host_id,
                event_type="hostname_changed",
                severity=_event_severity(
                    "hostname_changed",
                    current_host=current_host,
                    previous_host=previous_host,
                    previous_hosts_by_mac=previous_hosts_by_mac,
                ),
                summary=f"hostname changed on {current_host['ip']}: {previous_hostname!r} -> {current_hostname!r}",
            )
        )

    previous_role = previous_host.get("role")
    current_role = current_host.get("role")
    if previous_role != current_role:
        events.append(
            repository.create_event(
                host_id=host_id,
                event_type="role_changed",
                severity=_event_severity(
                    "role_changed",
                    current_host=current_host,
                    previous_host=previous_host,
                    previous_hosts_by_mac=previous_hosts_by_mac,
                ),
                summary=f"role changed on {current_host['ip']}: {previous_role!r} -> {current_role!r}",
            )
        )

    previous_services = {
        (str(service["proto"]), int(service["port"]))
        for service in previous_host.get("open_services", [])
    }
    current_services = {
        (str(service["proto"]), int(service["port"]))
        for service in current_host.get("open_services", [])
    }
    for proto, port in sorted(current_services - previous_services):
        events.append(
            repository.create_event(
                host_id=host_id,
                event_type="service_added",
                severity=_event_severity(
                    "service_added",
                    current_host=current_host,
                    previous_host=previous_host,
                    service={"proto": proto, "port": port},
                    previous_hosts_by_mac=previous_hosts_by_mac,
                ),
                summary=f"service added on {current_host['ip']}: {proto}/{port}",
            )
        )
    for proto, port in sorted(previous_services - current_services):
        events.append(
            repository.create_event(
                host_id=host_id,
                event_type="service_removed",
                severity=_event_severity(
                    "service_removed",
                    current_host=current_host,
                    previous_host=previous_host,
                    service={"proto": proto, "port": port},
                    previous_hosts_by_mac=previous_hosts_by_mac,
                ),
                summary=f"service removed on {current_host['ip']}: {proto}/{port}",
            )
        )


def _event_severity(
    event_type: str,
    *,
    current_host: dict[str, Any] | None,
    previous_host: dict[str, Any] | None,
    service: dict[str, Any] | None = None,
    previous_hosts_by_mac: dict[str, dict[str, Any]] | None = None,
) -> str:
    host = current_host or previous_host or {}
    role = str(host.get("role") or "")
    port = int(service["port"]) if service and service.get("port") is not None else None

    if event_type == "new_host":
        if _mac_changed_ip(current_host, previous_hosts_by_mac or {}):
            return "high"
        if _is_gateway_like(current_host):
            return "high"
        if _has_management_ports(current_host):
            return "medium"
        return "low"

    if event_type == "host_missing":
        if _is_gateway_like(previous_host):
            return "high"
        return "medium"

    if event_type == "role_changed":
        if _is_gateway_like(current_host) or _is_gateway_like(previous_host):
            return "high"
        if role in {"server", "network_device"} or str(previous_host.get("role") or "") in {"server", "network_device"}:
            return "medium"
        return "low"

    if event_type == "hostname_changed":
        return "medium" if _is_gateway_like(current_host) or _is_gateway_like(previous_host) else "low"

    if event_type == "service_added":
        if port in MANAGEMENT_PORTS:
            if _is_gateway_like(current_host) or role in {"server", "network_device"}:
                return "high"
            return "medium"
        return "low"

    if event_type == "service_removed":
        if port in MANAGEMENT_PORTS:
            return "medium"
        return "low"

    return "info"


def _is_gateway_like(host: dict[str, Any] | None) -> bool:
    if not host:
        return False
    ip = str(host.get("ip") or "")
    hostname = str(host.get("hostname") or "").lower()
    role = str(host.get("role") or "").lower()
    return ip.endswith(".1") or role == "network_device" or any(token in hostname for token in ("gateway", "router", "firewall"))


def _has_management_ports(host: dict[str, Any] | None) -> bool:
    if not host:
        return False
    ports = {int(service["port"]) for service in host.get("open_services", [])}
    return bool(ports.intersection(MANAGEMENT_PORTS))


def _mac_changed_ip(current_host: dict[str, Any] | None, previous_hosts_by_mac: dict[str, dict[str, Any]]) -> bool:
    if not current_host:
        return False
    mac = current_host.get("mac")
    if not mac:
        return False
    previous_host = previous_hosts_by_mac.get(str(mac))
    if not previous_host:
        return False
    return str(previous_host.get("ip")) != str(current_host.get("ip"))


def _load_snapshot(scan_run: dict[str, Any] | None) -> dict[str, Any]:
    if scan_run is None:
        return {}
    return _load_details(scan_run)


def _load_details(scan_run: dict[str, Any]) -> dict[str, Any]:
    return json.loads(str(scan_run["details_json"]) or "{}")
