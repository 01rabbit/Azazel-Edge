from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from .bus import EvidenceBus
from .noc_probe import NocProbeAdapter
from .schema import EvidenceEvent
from .suricata import read_suricata_jsonl
from .syslog_min import adapt_syslog_line


class EvidencePlaneService:
    def __init__(self, bus: EvidenceBus):
        self.bus = bus

    def dispatch_events(self, events: List[EvidenceEvent]) -> List[Dict[str, object]]:
        return self.bus.publish_many(events)

    def dispatch_suricata_jsonl(self, path: Path, limit: Optional[int] = None) -> List[Dict[str, object]]:
        return self.dispatch_events(read_suricata_jsonl(path, limit=limit))

    def dispatch_noc_probe(self, adapter: Optional[NocProbeAdapter] = None, snapshot: Optional[Dict[str, object]] = None) -> List[Dict[str, object]]:
        probe = adapter or NocProbeAdapter()
        return self.dispatch_events(probe.collect(snapshot=snapshot if isinstance(snapshot, dict) else None))

    def dispatch_syslog_line(self, line: str) -> Dict[str, object]:
        return self.bus.publish(adapt_syslog_line(line))
