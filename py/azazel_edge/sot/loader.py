from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class SoTValidationError(ValueError):
    pass


REQUIRED_TOP_LEVEL = ('devices', 'networks', 'services', 'expected_paths')
REQUIRED_DEVICE = ('id', 'hostname', 'ip', 'mac', 'criticality', 'allowed_networks')
REQUIRED_NETWORK = ('id', 'cidr', 'zone', 'gateway')
REQUIRED_SERVICE = ('id', 'proto', 'port', 'owner', 'exposure')
REQUIRED_PATH = ('src', 'dst', 'service_id', 'via', 'policy')


def _ensure_list(payload: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise SoTValidationError(f'{key}_must_be_list')
    return [item for item in value if isinstance(item, dict)]


def _ensure_required(item: Dict[str, Any], required: tuple[str, ...], prefix: str) -> None:
    missing = [field for field in required if field not in item]
    if missing:
        raise SoTValidationError(f'{prefix}_missing:' + ','.join(missing))


@dataclass(frozen=True)
class SoTConfig:
    devices: List[Dict[str, Any]]
    networks: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    expected_paths: List[Dict[str, Any]]

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> 'SoTConfig':
        if not isinstance(payload, dict):
            raise SoTValidationError('sot_root_must_be_dict')
        for key in REQUIRED_TOP_LEVEL:
            if key not in payload:
                raise SoTValidationError(f'missing_top_level:{key}')

        devices = _ensure_list(payload, 'devices')
        networks = _ensure_list(payload, 'networks')
        services = _ensure_list(payload, 'services')
        expected_paths = _ensure_list(payload, 'expected_paths')

        for item in devices:
            _ensure_required(item, REQUIRED_DEVICE, 'device')
            if not isinstance(item.get('allowed_networks'), list):
                raise SoTValidationError('device_allowed_networks_must_be_list')

        for item in networks:
            _ensure_required(item, REQUIRED_NETWORK, 'network')

        for item in services:
            _ensure_required(item, REQUIRED_SERVICE, 'service')

        for item in expected_paths:
            _ensure_required(item, REQUIRED_PATH, 'expected_path')

        return cls(
            devices=deepcopy(devices),
            networks=deepcopy(networks),
            services=deepcopy(services),
            expected_paths=deepcopy(expected_paths),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'devices': deepcopy(self.devices),
            'networks': deepcopy(self.networks),
            'services': deepcopy(self.services),
            'expected_paths': deepcopy(self.expected_paths),
        }

    def device_by_id(self, device_id: str) -> Optional[Dict[str, Any]]:
        return self._find(self.devices, 'id', device_id)

    def device_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        return self._find(self.devices, 'ip', ip)

    def network_by_id(self, network_id: str) -> Optional[Dict[str, Any]]:
        return self._find(self.networks, 'id', network_id)

    def service_by_id(self, service_id: str) -> Optional[Dict[str, Any]]:
        return self._find(self.services, 'id', service_id)

    def expected_path(self, src: str, dst: str, service_id: str) -> Optional[Dict[str, Any]]:
        for item in self.expected_paths:
            if str(item.get('src')) == src and str(item.get('dst')) == dst and str(item.get('service_id')) == service_id:
                return deepcopy(item)
        return None

    @staticmethod
    def _find(items: List[Dict[str, Any]], key: str, value: str) -> Optional[Dict[str, Any]]:
        for item in items:
            if str(item.get(key)) == value:
                return deepcopy(item)
        return None


def load_sot_file(path: str | Path) -> SoTConfig:
    source = Path(path)
    raw = source.read_text(encoding='utf-8')
    if source.suffix.lower() in {'.yaml', '.yml'}:
        payload = yaml.safe_load(raw)
    elif source.suffix.lower() == '.json':
        payload = json.loads(raw)
    else:
        raise SoTValidationError('unsupported_sot_format')
    return SoTConfig.from_dict(payload)
