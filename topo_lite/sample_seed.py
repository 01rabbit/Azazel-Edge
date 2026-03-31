from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from db.repository import TopoLiteRepository


SYNTHETIC_SOURCE = "sample-seed"
SYNTHETIC_SCENARIO = "internal_lan_story_v1"


@dataclass(frozen=True, slots=True)
class SampleHost:
    ip: str
    mac: str
    vendor: str
    hostname: str
    role: str
    label: str
    icon: str
    status: str
    services: tuple[tuple[int, str], ...]
    observation_kind: str
    segment: str
    confidence: float


INTERNAL_LAN_STORY: tuple[SampleHost, ...] = (
    SampleHost(
        ip="172.16.0.254",
        mac="02:42:ac:10:00:fe",
        vendor="Azazel Internal Bridge",
        hostname="azazel-edge-core",
        role="network_device",
        label="Azazel Core",
        icon="bridge",
        status="up",
        services=((443, "open"), (8065, "open")),
        observation_kind="gateway",
        segment="internal-lan",
        confidence=0.97,
    ),
    SampleHost(
        ip="172.16.0.1",
        mac="70:b3:d5:10:00:01",
        vendor="CoreSwitch Inc.",
        hostname="core-switch-01",
        role="network_device",
        label="Core Switch",
        icon="switch",
        status="up",
        services=((22, "open"), (443, "open")),
        observation_kind="switch",
        segment="internal-lan",
        confidence=0.97,
    ),
    SampleHost(
        ip="172.16.0.21",
        mac="9c:ad:ef:10:00:21",
        vendor="Ops Console Co.",
        hostname="soc-console-01",
        role="desktop",
        label="SOC Console",
        icon="console",
        status="up",
        services=((3389, "open"),),
        observation_kind="operator-console",
        segment="soc-desk",
        confidence=0.88,
    ),
    SampleHost(
        ip="172.16.0.31",
        mac="58:11:22:10:00:31",
        vendor="Telemetry Labs",
        hostname="sensor-cam-01",
        role="iot",
        label="Telemetry Camera",
        icon="camera",
        status="up",
        services=((443, "open"),),
        observation_kind="camera",
        segment="facility",
        confidence=0.86,
    ),
    SampleHost(
        ip="172.16.0.42",
        mac="c0:ff:ee:10:00:42",
        vendor="Printer Vendor",
        hostname="printer-floor1",
        role="printer",
        label="Floor 1 Printer",
        icon="printer",
        status="up",
        services=((631, "open"), (9100, "open")),
        observation_kind="printer",
        segment="office",
        confidence=0.95,
    ),
    SampleHost(
        ip="172.16.0.80",
        mac="de:ad:be:10:00:80",
        vendor="File Server Ltd.",
        hostname="fileserver-01",
        role="server",
        label="File Server",
        icon="server",
        status="up",
        services=((22, "open"), (443, "open"), (445, "open")),
        observation_kind="file-server",
        segment="core-services",
        confidence=0.96,
    ),
)


def _clear_runtime_state(repository: TopoLiteRepository) -> None:
    with repository.transaction() as connection:
        for table in (
            "overrides",
            "classifications",
            "edges",
            "events",
            "observations",
            "services",
            "scan_runs",
            "hosts",
        ):
            connection.execute(f"DELETE FROM {table}")
        connection.execute("DELETE FROM schema_metadata WHERE key LIKE 'synthetic_%'")


def seed_internal_lan_story(repository: TopoLiteRepository) -> dict[str, Any]:
    _clear_runtime_state(repository)

    host_rows = []
    for index, item in enumerate(INTERNAL_LAN_STORY, start=1):
        timestamp = f"2026-04-01T00:{index:02d}:00Z"
        host = repository.upsert_host(
            ip=item.ip,
            mac=item.mac,
            vendor=item.vendor,
            hostname=item.hostname,
            status=item.status,
            seen_at=timestamp,
        )
        host_rows.append(host)
        repository.record_observation(
            host_id=int(host["id"]),
            source=SYNTHETIC_SOURCE,
            observed_at=f"2026-04-01T00:{index:02d}:10Z",
            payload={
                "ip": item.ip,
                "subnet": "172.16.0.0/24",
                "kind": item.observation_kind,
                "segment": item.segment,
                "synthetic": True,
                "scenario": SYNTHETIC_SCENARIO,
            },
        )
        repository.set_classification(
            host_id=int(host["id"]),
            label=item.role,
            confidence=item.confidence,
            updated_at=f"2026-04-01T00:{index:02d}:20Z",
            reason={
                "source": SYNTHETIC_SOURCE,
                "scenario": SYNTHETIC_SCENARIO,
                "vendor": item.vendor,
                "ports": [port for port, _state in item.services],
            },
        )
        override = repository.create_override(
            host_id=int(host["id"]),
            fixed_label=item.label,
            fixed_role=item.role,
            fixed_icon=item.icon,
            ignored=False,
            note="synthetic internal-lan story",
            created_at=f"2026-04-01T00:{index:02d}:25Z",
        )
        repository.update_override(
            int(override["id"]),
            fixed_label=item.label,
            fixed_role=item.role,
            fixed_icon=item.icon,
            ignored=False,
            note="synthetic internal-lan story",
            updated_at=f"2026-04-01T00:{index:02d}:30Z",
        )
        for port, state in item.services:
            repository.upsert_service(
                host_id=int(host["id"]),
                proto="tcp",
                port=port,
                state=state,
                seen_at=f"2026-04-01T00:{index:02d}:40Z",
            )

    discovery_run = repository.create_scan_run(
        scan_kind="arp_discovery",
        status="started",
        started_at="2026-04-01T00:10:00Z",
        details={"source": SYNTHETIC_SOURCE, "synthetic": True, "scenario": SYNTHETIC_SCENARIO},
    )
    repository.finish_scan_run(
        int(discovery_run["id"]),
        status="completed",
        finished_at="2026-04-01T00:10:05Z",
        details={
            "interface": "br0",
            "subnets": ["172.16.0.0/24"],
            "source": SYNTHETIC_SOURCE,
            "synthetic": True,
            "scenario": SYNTHETIC_SCENARIO,
            "host_count": len(host_rows),
            "observation_count": len(host_rows),
            "source_counts": {SYNTHETIC_SOURCE: len(host_rows)},
            "discovered_hosts": [
                {
                    "host_id": int(row["id"]),
                    "ip": row["ip"],
                    "mac": row["mac"],
                    "vendor": row["vendor"],
                    "subnet": "172.16.0.0/24",
                    "synthetic": True,
                }
                for row in host_rows
            ],
            "supplemental_hosts": [],
            "errors": [],
        },
    )

    services = []
    for row, item in zip(host_rows, INTERNAL_LAN_STORY, strict=True):
        for port, state in item.services:
            services.append(
                {
                    "host_id": int(row["id"]),
                    "ip": row["ip"],
                    "proto": "tcp",
                    "port": port,
                    "state": state,
                    "source": SYNTHETIC_SOURCE,
                    "attempts": 1,
                    "duration_ms": 10.0,
                    "synthetic": True,
                }
            )

    probe_run = repository.create_scan_run(
        scan_kind="service_probe",
        status="started",
        started_at="2026-04-01T00:12:00Z",
        details={"source": SYNTHETIC_SOURCE, "synthetic": True, "scenario": SYNTHETIC_SCENARIO},
    )
    repository.finish_scan_run(
        int(probe_run["id"]),
        status="completed",
        finished_at="2026-04-01T00:12:08Z",
        details={
            "target_ports": [22, 53, 80, 123, 139, 443, 445, 631, 3389, 5353, 8000, 8080, 8443, 9100],
            "timeout_seconds": 2,
            "concurrency": 32,
            "retry_count": 1,
            "retry_backoff_seconds": 0.25,
            "batch_size": 64,
            "service_count": len(services),
            "host_count": len(host_rows),
            "target_count": len(services),
            "duration_ms": 8000.0,
            "average_attempts": 1.0,
            "state_counts": {"open": len(services), "closed": 0, "timeout": 0},
            "banner_summary": {"observation_count": 0, "errors": [], "sources": [SYNTHETIC_SOURCE]},
            "classification_summary": {"host_count": len(host_rows), "summary": {"network_device": 2, "desktop": 1, "iot": 1, "printer": 1, "server": 1}},
            "services": services,
            "errors": [],
            "synthetic": True,
            "scenario": SYNTHETIC_SCENARIO,
        },
    )

    events = (
        ("new_host", int(host_rows[5]["id"]), "medium", "new host discovered: 172.16.0.80", "2026-04-01T00:15:00Z"),
        ("service_added", int(host_rows[5]["id"]), "high", "service added on 172.16.0.80: tcp/445", "2026-04-01T00:18:00Z"),
        ("service_added", int(host_rows[1]["id"]), "high", "service added on 172.16.0.1: tcp/22", "2026-04-01T00:20:00Z"),
        ("hostname_changed", int(host_rows[2]["id"]), "low", "hostname changed on 172.16.0.21: 'soc-console-temp' -> 'soc-console-01'", "2026-04-01T00:24:00Z"),
        ("host_missing", int(host_rows[3]["id"]), "medium", "host missing after 2 scans: 172.16.0.31", "2026-04-01T00:27:00Z"),
        ("role_changed", int(host_rows[4]["id"]), "low", "role changed on 172.16.0.42: 'unknown' -> 'printer'", "2026-04-01T00:30:00Z"),
    )
    for event_type, host_id, severity, summary, created_at in events:
        repository.create_event(
            event_type=event_type,
            host_id=host_id,
            severity=severity,
            summary=summary,
            created_at=created_at,
        )

    repository.set_metadata("synthetic_active", "true")
    repository.set_metadata("synthetic_source", SYNTHETIC_SOURCE)
    repository.set_metadata("synthetic_scenario", SYNTHETIC_SCENARIO)
    repository.set_metadata("synthetic_label", "Synthetic internal LAN sample")

    return {
        "synthetic": True,
        "scenario": SYNTHETIC_SCENARIO,
        "host_count": len(host_rows),
        "event_count": len(events),
        "scan_runs": 2,
        "subnets": ["172.16.0.0/24"],
    }
