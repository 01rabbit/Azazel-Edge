from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from configuration import ValidationError, load_config


class ConfigurationTests(unittest.TestCase):
    def test_load_config_from_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text(
                textwrap.dedent(
                    """
                    interface: wlan0
                    subnets:
                      - 10.0.0.0/24
                    target_ports: [22, 443]
                    database_path: test.sqlite3
                    scan_intervals:
                      discovery_seconds: 120
                      probe_seconds: 600
                      deep_probe_seconds: 30
                    probe:
                      timeout_seconds: 5
                      concurrency: 16
                      retry_count: 2
                      retry_backoff_seconds: 0.5
                      batch_size: 32
                    notification:
                      enabled: true
                      provider: ntfy
                      endpoint: https://ntfy.local/topic
                    auth:
                      enabled: true
                      mode: local
                      token_required: true
                    retention_period:
                      observations_days: 7
                      events_days: 14
                      scan_runs_days: 3
                    exposure:
                      backend_bind_host: 127.0.0.1
                      frontend_bind_host: 0.0.0.0
                      local_only: false
                      allowed_cidrs:
                        - 10.0.0.0/24
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            config = load_config(config_path)

        self.assertEqual(config.interface, "wlan0")
        self.assertEqual(config.target_ports, [22, 443])
        self.assertEqual(config.probe.timeout_seconds, 5)
        self.assertEqual(config.probe.concurrency, 16)
        self.assertEqual(config.probe.retry_count, 2)
        self.assertEqual(config.probe.retry_backoff_seconds, 0.5)
        self.assertEqual(config.probe.batch_size, 32)
        self.assertEqual(config.notification.endpoint, "https://ntfy.local/topic")
        self.assertEqual(config.retention_period.scan_runs_days, 3)
        self.assertEqual(config.logging.app_log_path, "logs/app.jsonl")
        self.assertEqual(config.auth.admin_username, "admin")
        self.assertEqual(config.exposure.frontend_bind_host, "0.0.0.0")
        self.assertEqual(config.exposure.allowed_cidrs, ["10.0.0.0/24"])

    def test_env_overrides_take_precedence(self) -> None:
        config = load_config(
            None,
            env={
                "AZAZEL_TOPO_LITE_INTERFACE": "br0",
                "AZAZEL_TOPO_LITE_TARGET_PORTS": "22,8080,8443",
                "AZAZEL_TOPO_LITE_RETENTION_EVENTS_DAYS": "21",
                "AZAZEL_TOPO_LITE_APP_LOG_PATH": "/tmp/app.jsonl",
                "AZAZEL_TOPO_LITE_PROBE_TIMEOUT_SECONDS": "7",
                "AZAZEL_TOPO_LITE_PROBE_RETRY_COUNT": "3",
                "AZAZEL_TOPO_LITE_PROBE_RETRY_BACKOFF_SECONDS": "0.75",
                "AZAZEL_TOPO_LITE_PROBE_BATCH_SIZE": "48",
                "AZAZEL_TOPO_LITE_AUTH_ADMIN_API_TOKEN": "override-admin-token",
                "AZAZEL_TOPO_LITE_FRONTEND_HOST": "0.0.0.0",
                "AZAZEL_TOPO_LITE_LOCAL_ONLY": "false",
                "AZAZEL_TOPO_LITE_ALLOWED_CIDRS": "192.168.40.0/24,10.0.0.0/24",
            },
        )
        self.assertEqual(config.interface, "br0")
        self.assertEqual(config.target_ports, [22, 8080, 8443])
        self.assertEqual(config.retention_period.events_days, 21)
        self.assertEqual(config.logging.app_log_path, "/tmp/app.jsonl")
        self.assertEqual(config.probe.timeout_seconds, 7)
        self.assertEqual(config.probe.retry_count, 3)
        self.assertEqual(config.probe.retry_backoff_seconds, 0.75)
        self.assertEqual(config.probe.batch_size, 48)
        self.assertEqual(config.auth.admin_api_token, "override-admin-token")
        self.assertEqual(config.exposure.frontend_bind_host, "0.0.0.0")
        self.assertEqual(config.exposure.allowed_cidrs, ["192.168.40.0/24", "10.0.0.0/24"])
        self.assertEqual(config.exposure.local_only, False)

    def test_invalid_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text(
                "interface: ''\nsubnets: []\ntarget_ports: [70000]\nexposure:\n  allowed_cidrs: ['not-a-cidr']\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValidationError):
                load_config(config_path)


if __name__ == "__main__":
    unittest.main()
