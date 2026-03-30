from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from configuration import ExposureConfig


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    reason: str


def evaluate_remote_access(remote_addr: str | None, exposure: ExposureConfig) -> AccessDecision:
    if not remote_addr:
        return AccessDecision(False, "missing_remote_addr")

    try:
        address = ipaddress.ip_address(remote_addr)
    except ValueError:
        return AccessDecision(False, "invalid_remote_addr")

    if address.is_loopback:
        return AccessDecision(True, "loopback_allowed")

    if exposure.local_only:
        return AccessDecision(False, "local_only")

    if not exposure.allowed_cidrs:
        return AccessDecision(True, "open_access")

    for cidr in exposure.allowed_cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        if address in network:
            return AccessDecision(True, f"allowed_cidr:{cidr}")

    return AccessDecision(False, "outside_allowed_cidrs")
