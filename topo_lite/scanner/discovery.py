from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class DiscoveryJob:
    interface: str = "eth0"
    subnets: list[str] = field(default_factory=list)
    target_ports: list[int] = field(default_factory=lambda: [22, 80, 443])
    interval_seconds: int = 300


def build_default_job() -> DiscoveryJob:
    return DiscoveryJob()

