"""Dummy Suricata EVE event generator.

Generates realistic eve.json alert lines for the AZAZEL rule set
(security/suricata/azazel-lite.rules) without needing Suricata or real
traffic. Intended for:

- macOS/dev-host verification of the detection chain
  (eve.json -> azazel-edge-core -> ai agent -> web UI)
- live demos (staged attack flows, continuous background noise)

Event shape mirrors tests/benchmark/corpus/*.jsonl so the tactical scorer
sees exactly the calibrated SID/classtype combinations.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence


@dataclass(frozen=True)
class AlertTemplate:
    signature_id: int
    signature: str
    category: str
    attack_type: str
    severity: int = 2
    proto: str = "TCP"
    dest_ports: Sequence[int] = (80,)
    external_src: bool = False
    external_dst: bool = False


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    templates: Sequence[AlertTemplate]
    description: str = ""


# --- scenario definitions -------------------------------------------------
# SIDs / classtypes pinned to security/suricata/azazel-lite.rules and
# tests/benchmark/corpus (see test_scorer_calibration_v1 / test_scorer_wiring_v1).

_SCENARIOS: Dict[str, Scenario] = {}


def _register(scenario: Scenario) -> None:
    _SCENARIOS[scenario.scenario_id] = scenario


_register(
    Scenario(
        scenario_id="recon_probe",
        title="OpenCanary decoy probe (recon)",
        description="SYN probes against decoy SSH/HTTP ports.",
        templates=[
            AlertTemplate(9901101, "AZAZEL OPENCANARY SSH probe", "attempted-recon", "recon_probe", dest_ports=(12222,)),
            AlertTemplate(9901102, "AZAZEL OPENCANARY HTTP probe", "attempted-recon", "recon_probe", dest_ports=(18080,)),
            AlertTemplate(9901103, "AZAZEL OPENCANARY repeated access", "attempted-recon", "recon_probe", dest_ports=(12222, 18080)),
        ],
    )
)

_register(
    Scenario(
        scenario_id="port_scan",
        title="Rapid port scan",
        description="External rapid port scan against shelter network.",
        templates=[
            AlertTemplate(9901222, "AZAZEL SCAN external rapid port scan on shelter network", "network-scan", "port_scan", dest_ports=(22, 80, 443, 445, 3389, 8080)),
            AlertTemplate(9901221, "AZAZEL SCAN internal host rapid port scan", "network-scan", "port_scan", dest_ports=(22, 80, 443, 139, 445)),
        ],
    )
)

_register(
    Scenario(
        scenario_id="arp_spoof",
        title="ARP spoof (gateway impersonation)",
        description="Gateway impersonation pattern on local segment.",
        templates=[
            AlertTemplate(9901211, "AZAZEL ARP spoof - gateway impersonation detected", "bad-unknown", "arp_spoof", proto="ARP", dest_ports=(0,)),
        ],
    )
)

_register(
    Scenario(
        scenario_id="dns_exfil",
        title="DNS exfiltration / tunnel",
        description="Long or high-frequency DNS queries to external resolver.",
        templates=[
            AlertTemplate(9901231, "AZAZEL DNS exfil - unusually long DNS query", "policy-violation", "dns_exfil", proto="UDP", dest_ports=(53,), external_dst=True),
            AlertTemplate(9901232, "AZAZEL DNS tunnel - high-frequency DNS queries", "policy-violation", "dns_exfil", proto="UDP", dest_ports=(53,), external_dst=True),
        ],
    )
)

_register(
    Scenario(
        scenario_id="cred_harvest",
        title="Credential harvesting",
        description="Password field observed in cleartext GET request.",
        templates=[
            AlertTemplate(9901241, "AZAZEL CREDENTIAL harvest - password field in GET request", "policy-violation", "cred_harvest", dest_ports=(80,)),
        ],
    )
)

_register(
    Scenario(
        scenario_id="c2_beacon",
        title="C2 beacon",
        description="Periodic small HTTP POST to external host.",
        templates=[
            AlertTemplate(9901251, "AZAZEL C2 beacon - periodic small HTTP POST", "trojan-activity", "c2_beacon", dest_ports=(443, 80), external_dst=True),
        ],
    )
)

_register(
    Scenario(
        scenario_id="phishing",
        title="Disaster phishing",
        description="Fake government / relief portal indicators.",
        templates=[
            AlertTemplate(9901201, "AZAZEL DISASTER phishing - fake government domain", "social-engineering", "phishing", dest_ports=(80,)),
            AlertTemplate(9901202, "AZAZEL DISASTER phishing - fake MyNumber portal", "social-engineering", "phishing", dest_ports=(80,)),
            AlertTemplate(9901203, "AZAZEL DISASTER phishing - fake disaster relief site", "social-engineering", "phishing", dest_ports=(80,)),
        ],
    )
)

_register(
    Scenario(
        scenario_id="benign",
        title="Benign background noise",
        description="Normal DNS / HTTPS / NTP activity (severity 3, sid 0).",
        templates=[
            AlertTemplate(0, "informational outbound TLS session", "not-suspicious", "web_browse", severity=3, dest_ports=(443,), external_dst=True),
            AlertTemplate(0, "informational DNS lookup", "not-suspicious", "dns_lookup", severity=3, proto="UDP", dest_ports=(53,), external_dst=True),
            AlertTemplate(0, "informational NTP sync", "not-suspicious", "ntp_sync", severity=3, proto="UDP", dest_ports=(123,), external_dst=True),
        ],
    )
)

# Default staged flow for demos: quiet baseline, recon, scan, then impact.
DEFAULT_FLOW: Sequence[str] = (
    "benign",
    "recon_probe",
    "port_scan",
    "c2_beacon",
    "dns_exfil",
)

EXTERNAL_DST_POOL = ("203.0.113.10", "203.0.113.25", "198.51.100.7", "8.8.8.8")


@dataclass
class EveGenerator:
    src_prefix: str = "10.0.0."
    dst_ip: str = "172.16.0.1"
    rng: random.Random = field(default_factory=random.Random)

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")

    def _src_ip(self) -> str:
        return f"{self.src_prefix}{self.rng.randint(2, 254)}"

    def build_event(self, template: AlertTemplate, src_ip: Optional[str] = None) -> Dict[str, Any]:
        dest_ip = self.rng.choice(EXTERNAL_DST_POOL) if template.external_dst else self.dst_ip
        return {
            "timestamp": self._timestamp(),
            "event_type": "alert",
            "src_ip": src_ip or self._src_ip(),
            "src_port": self.rng.randint(1024, 65000),
            "dest_ip": dest_ip,
            "dest_port": int(self.rng.choice(list(template.dest_ports))),
            "proto": template.proto,
            "attack_type": template.attack_type,
            "alert": {
                "signature_id": template.signature_id,
                "signature": template.signature,
                "severity": template.severity,
                "category": template.category,
            },
        }

    def iter_scenario(self, scenario_id: str, count: int, sticky_src: bool = True) -> Iterator[Dict[str, Any]]:
        scenario = _SCENARIOS.get(scenario_id)
        if scenario is None:
            raise KeyError(f"unknown_scenario:{scenario_id}")
        # One attacking host per burst reads better on the dashboard / correlation.
        src_ip = self._src_ip() if sticky_src and scenario_id != "benign" else None
        for i in range(max(1, count)):
            template = scenario.templates[i % len(scenario.templates)]
            yield self.build_event(template, src_ip=src_ip)


def list_scenarios() -> List[Dict[str, str]]:
    return [
        {
            "scenario_id": s.scenario_id,
            "title": s.title,
            "description": s.description,
            "signature_ids": ",".join(str(t.signature_id) for t in s.templates),
        }
        for s in _SCENARIOS.values()
    ]


def _default_eve_path() -> Path:
    return Path(os.environ.get("AZAZEL_EVE_PATH", "/var/log/suricata/eve.json"))


class EveWriter:
    def __init__(self, path: Optional[Path], dry_run: bool = False):
        self.path = path
        self.dry_run = dry_run
        if path is not None and not dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        if self.dry_run or self.path is None:
            print(line)
            return
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()


def cmd_list(_args: argparse.Namespace) -> int:
    for item in list_scenarios():
        print(f"{item['scenario_id']:<14} sids=[{item['signature_ids']}] {item['title']}")
    return 0


def cmd_emit(args: argparse.Namespace) -> int:
    gen = EveGenerator(src_prefix=args.src_prefix, dst_ip=args.dst_ip, rng=random.Random(args.seed))
    writer = EveWriter(Path(args.eve_path) if args.eve_path else _default_eve_path(), dry_run=args.dry_run)
    sent = 0
    for event in gen.iter_scenario(args.scenario, args.count):
        writer.write(event)
        sent += 1
        if not args.dry_run:
            print(f"emitted sid={event['alert']['signature_id']} {event['attack_type']} src={event['src_ip']} -> {event['dest_ip']}:{event['dest_port']}")
        if args.interval > 0 and sent < args.count:
            time.sleep(args.interval)
    print(f"done: scenario={args.scenario} emitted={sent}")
    return 0


def cmd_flow(args: argparse.Namespace) -> int:
    gen = EveGenerator(src_prefix=args.src_prefix, dst_ip=args.dst_ip, rng=random.Random(args.seed))
    writer = EveWriter(Path(args.eve_path) if args.eve_path else _default_eve_path(), dry_run=args.dry_run)
    stages = [s.strip() for s in args.stages.split(",") if s.strip()] or list(DEFAULT_FLOW)
    for index, scenario_id in enumerate(stages):
        print(f"[stage {index + 1}/{len(stages)}] {scenario_id} (count={args.count})")
        for event in gen.iter_scenario(scenario_id, args.count):
            writer.write(event)
            if args.interval > 0:
                time.sleep(args.interval)
        if index < len(stages) - 1 and args.hold > 0:
            time.sleep(args.hold)
    print(f"done: flow stages={len(stages)}")
    return 0


def cmd_stream(args: argparse.Namespace) -> int:
    gen = EveGenerator(src_prefix=args.src_prefix, dst_ip=args.dst_ip, rng=random.Random(args.seed))
    writer = EveWriter(Path(args.eve_path) if args.eve_path else _default_eve_path(), dry_run=args.dry_run)
    attack_ids = [s for s in _SCENARIOS if s != "benign"]
    interval = 1.0 / max(0.1, args.rate)
    next_attack = time.monotonic() + args.attack_every
    print(f"streaming benign noise at {args.rate}/s, attack burst every {args.attack_every}s (Ctrl-C to stop)")
    try:
        while True:
            writer.write(next(gen.iter_scenario("benign", 1)))
            now = time.monotonic()
            if args.attack_every > 0 and now >= next_attack:
                scenario_id = gen.rng.choice(attack_ids)
                print(f"attack burst: {scenario_id}")
                for event in gen.iter_scenario(scenario_id, args.burst):
                    writer.write(event)
                next_attack = now + args.attack_every
            time.sleep(interval)
    except KeyboardInterrupt:
        print("stream stopped")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-dummy-eve",
        description="Generate dummy Suricata EVE alerts for dev verification and demos.",
    )
    parser.add_argument("--eve-path", default="", help="Output eve.json path (default: $AZAZEL_EVE_PATH or /var/log/suricata/eve.json)")
    parser.add_argument("--src-prefix", default="10.0.0.", help="Attacker/client source IP prefix")
    parser.add_argument("--dst-ip", default="172.16.0.1", help="Internal target IP")
    parser.add_argument("--seed", type=int, default=None, help="Random seed (reproducible demos)")
    parser.add_argument("--dry-run", action="store_true", help="Print events to stdout instead of writing")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List available scenarios")

    p_emit = sub.add_parser("emit", help="Emit N events for one scenario")
    p_emit.add_argument("--scenario", required=True, choices=sorted(_SCENARIOS.keys()))
    p_emit.add_argument("--count", type=int, default=5)
    p_emit.add_argument("--interval", type=float, default=0.5, help="Seconds between events")

    p_flow = sub.add_parser("flow", help="Run a staged attack flow (demo)")
    p_flow.add_argument("--stages", default=",".join(DEFAULT_FLOW), help="Comma-separated scenario ids")
    p_flow.add_argument("--count", type=int, default=5, help="Events per stage")
    p_flow.add_argument("--interval", type=float, default=0.5, help="Seconds between events")
    p_flow.add_argument("--hold", type=float, default=8.0, help="Pause between stages")

    p_stream = sub.add_parser("stream", help="Continuous benign noise with periodic attack bursts")
    p_stream.add_argument("--rate", type=float, default=0.5, help="Benign events per second")
    p_stream.add_argument("--attack-every", type=float, default=45.0, help="Seconds between attack bursts (0=never)")
    p_stream.add_argument("--burst", type=int, default=6, help="Events per attack burst")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "emit":
        return cmd_emit(args)
    if args.command == "flow":
        return cmd_flow(args)
    if args.command == "stream":
        return cmd_stream(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
