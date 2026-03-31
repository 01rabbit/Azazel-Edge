from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from scanner.discovery import (
    ArpDiscoveryResult,
    DiscoveryRunError,
    SupplementalDiscoveryResult,
    build_arp_scan_command,
    build_job_from_config,
    discover_supplemental_hosts,
    discover_hosts,
    parse_dhcp_leases,
    parse_ip_neigh_output,
    parse_arp_scan_output,
    run_arp_scan,
)


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "discovery.sqlite3"
        self.logs_dir = Path(self.temp_dir.name) / "logs"
        self.repository = TopoLiteRepository(self.database_path)
        self.config = default_config()
        self.config.database_path = str(self.database_path)
        self.config.logging.app_log_path = str(self.logs_dir / "app.jsonl")
        self.config.logging.access_log_path = str(self.logs_dir / "access.jsonl")
        self.config.logging.audit_log_path = str(self.logs_dir / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.logs_dir / "scanner.jsonl")
        self.loggers = configure_logging(self.config.logging)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_parse_arp_scan_output_skips_non_result_lines(self) -> None:
        output = """
Interface: br0, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 172.16.0.254
Starting arp-scan 1.10.0 with 256 hosts
172.16.0.1\t00:11:22:33:44:55\tGateway Vendor
172.16.0.20  aa:bb:cc:dd:ee:20   Printer Vendor
2 packets received by filter
        """.strip()

        results = parse_arp_scan_output(output, subnet="172.16.0.0/24")

        self.assertEqual(
            results,
            [
                ArpDiscoveryResult(
                    ip="172.16.0.1",
                    mac="00:11:22:33:44:55",
                    vendor="Gateway Vendor",
                    subnet="172.16.0.0/24",
                ),
                ArpDiscoveryResult(
                    ip="172.16.0.20",
                    mac="aa:bb:cc:dd:ee:20",
                    vendor="Printer Vendor",
                    subnet="172.16.0.0/24",
                ),
            ],
        )

    def test_build_command_uses_interface_and_subnet(self) -> None:
        self.assertEqual(
            build_arp_scan_command("br0", "172.16.0.0/24"),
            ["arp-scan", "--interface", "br0", "172.16.0.0/24"],
        )

    def test_discover_hosts_persists_hosts_observations_and_scan_run(self) -> None:
        def fake_runner(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
            self.assertEqual(command[-1], "172.16.0.0/24")
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout="172.16.0.1\t00:11:22:33:44:55\tGateway Vendor\n",
                stderr="",
            )

        result = discover_hosts(
            config=self.config,
            repository=self.repository,
            runner=fake_runner,
            loggers=self.loggers,
            arp_cache_reader=lambda: "",
            dhcp_lease_reader=lambda: "",
        )

        hosts = self.repository.list_hosts()
        observations = self.repository.list_observations()
        scan_runs = self.repository.list_scan_runs()

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["host_count"], 1)
        self.assertEqual(result["subnets_scanned"], 1)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["vendor"], "Gateway Vendor")
        self.assertEqual(len(observations), 1)
        payload = json.loads(observations[0]["payload_json"])
        self.assertEqual(payload["source"], "arp-scan")
        self.assertEqual(payload["subnet"], "172.16.0.0/24")
        self.assertEqual(len(scan_runs), 1)
        self.assertEqual(scan_runs[0]["status"], "completed")

    def test_discover_hosts_marks_partial_failure_when_one_subnet_times_out(self) -> None:
        self.config.subnets = ["172.16.0.0/24", "172.16.1.0/24"]

        def fake_runner(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
            subnet = command[-1]
            if subnet == "172.16.1.0/24":
                raise subprocess.TimeoutExpired(command, timeout)
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout="172.16.0.10\t00:aa:bb:cc:dd:10\tWorkstation Vendor\n",
                stderr="",
            )

        result = discover_hosts(
            config=self.config,
            repository=self.repository,
            runner=fake_runner,
            loggers=self.loggers,
            arp_cache_reader=lambda: "",
            dhcp_lease_reader=lambda: "",
        )

        self.assertEqual(result["status"], "partial_failed")
        self.assertEqual(result["host_count"], 1)
        self.assertEqual(len(result["errors"]), 1)
        scan_run = self.repository.get_scan_run(result["scan_run_id"])
        self.assertEqual(scan_run["status"], "partial_failed")

    def test_discover_hosts_fails_when_all_subnets_fail(self) -> None:
        def failing_runner(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(command, timeout)

        result = discover_hosts(
            config=self.config,
            repository=self.repository,
            runner=failing_runner,
            loggers=self.loggers,
            arp_cache_reader=lambda: "",
            dhcp_lease_reader=lambda: "",
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["host_count"], 0)
        self.assertEqual(len(result["errors"]), 1)

    def test_build_job_from_config_uses_current_settings(self) -> None:
        self.config.interface = "enp1s0"
        self.config.subnets = ["10.0.0.0/24"]
        self.config.scan_intervals.discovery_seconds = 123

        job = build_job_from_config(self.config)

        self.assertEqual(job.interface, "enp1s0")
        self.assertEqual(job.subnets, ["10.0.0.0/24"])
        self.assertEqual(job.interval_seconds, 123)

    def test_run_arp_scan_raises_on_invalid_return_code(self) -> None:
        with self.assertRaises(DiscoveryRunError):
            run_arp_scan(
                interface=self.config.interface,
                subnet=self.config.subnets[0],
                runner=lambda command, timeout: subprocess.CompletedProcess(
                    args=command,
                    returncode=2,
                    stdout="",
                    stderr="permission denied",
                ),
            )

    def test_discover_hosts_records_failed_scan_run_on_invalid_return_code(self) -> None:
        result = discover_hosts(
            config=self.config,
            repository=self.repository,
            runner=lambda command, timeout: subprocess.CompletedProcess(
                args=command,
                returncode=2,
                stdout="",
                stderr="permission denied",
            ),
            loggers=self.loggers,
            arp_cache_reader=lambda: "",
            dhcp_lease_reader=lambda: "",
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["errors"]), 1)

    def test_discover_hosts_records_failed_scan_run_when_arp_scan_is_missing(self) -> None:
        result = discover_hosts(
            config=self.config,
            repository=self.repository,
            runner=lambda command, timeout: (_ for _ in ()).throw(FileNotFoundError(2, "No such file", "arp-scan")),
            loggers=self.loggers,
            arp_cache_reader=lambda: "",
            dhcp_lease_reader=lambda: "",
        )

        self.assertEqual(result["status"], "failed")
        self.assertIn("arp-scan is not installed", result["errors"][0]["error"])

    def test_parse_ip_neigh_output_and_dhcp_leases(self) -> None:
        arp_cache = "172.16.0.50 dev br0 lladdr aa:bb:cc:dd:ee:50 REACHABLE\n"
        dhcp_leases = """
lease 172.16.0.60 {
  hardware ethernet aa:bb:cc:dd:ee:60;
  client-hostname "sensor-60";
}
        """.strip()

        arp_results = parse_ip_neigh_output(arp_cache, self.config.subnets)
        dhcp_results = parse_dhcp_leases(dhcp_leases, self.config.subnets)

        self.assertEqual(
            arp_results,
            [
                SupplementalDiscoveryResult(
                    ip="172.16.0.50",
                    source="arp-cache",
                    subnet="172.16.0.0/24",
                    mac="aa:bb:cc:dd:ee:50",
                )
            ],
        )
        self.assertEqual(dhcp_results[0].hostname, "sensor-60")
        self.assertEqual(dhcp_results[0].source, "dhcp-lease")

    def test_discover_supplemental_hosts_collects_multiple_sources(self) -> None:
        results, errors = discover_supplemental_hosts(
            config=self.config,
            known_ips={"172.16.0.1"},
            include_active_sources=True,
            arp_cache_reader=lambda: "172.16.0.10 dev br0 lladdr aa:bb:cc:dd:ee:10 REACHABLE\n",
            dhcp_lease_reader=lambda: 'lease 172.16.0.20 {\n  client-hostname "sensor-20";\n}\n',
            ping_runner=lambda ip, timeout: ip == "172.16.0.30",
            tcp_discovery_runner=lambda ip, ports, timeout: 443 if ip == "172.16.0.40" else None,
        )

        by_source = {item.source: item for item in results}
        self.assertEqual(len(errors), 0)
        self.assertEqual(by_source["arp-cache"].ip, "172.16.0.10")
        self.assertEqual(by_source["dhcp-lease"].hostname, "sensor-20")
        self.assertEqual(by_source["icmp-ping"].ip, "172.16.0.30")
        self.assertEqual(by_source["tcp-connect-discovery"].metadata["open_port"], 443)

    def test_discover_hosts_persists_supplemental_observations(self) -> None:
        result = discover_hosts(
            config=self.config,
            repository=self.repository,
            runner=lambda command, timeout: subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr=""),
            loggers=self.loggers,
            arp_cache_reader=lambda: "172.16.0.10 dev br0 lladdr aa:bb:cc:dd:ee:10 REACHABLE\n",
            dhcp_lease_reader=lambda: "",
            ping_runner=lambda ip, timeout: False,
            tcp_discovery_runner=lambda ip, ports, timeout: None,
        )

        self.assertIn("source_counts", result)
        self.assertEqual(result["source_counts"]["arp-cache"], 1)
        observations = self.repository.list_observations()
        payloads = [json.loads(item["payload_json"]) for item in observations]
        self.assertTrue(any(payload.get("source") == "arp-cache" for payload in payloads))


if __name__ == "__main__":
    unittest.main()
