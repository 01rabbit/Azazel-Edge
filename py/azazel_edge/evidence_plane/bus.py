from __future__ import annotations

import json
import queue
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .schema import EvidenceEvent


class EvidenceBus:
    def __init__(self, fanout_path: Optional[Path] = None, queue_max: int = 1024):
        self.fanout_path = Path(fanout_path) if fanout_path else None
        self.queue: 'queue.Queue[Dict[str, object]]' = queue.Queue(maxsize=max(1, int(queue_max)))

    def publish(self, event: EvidenceEvent | Dict[str, object]) -> Dict[str, object]:
        payload = event.to_dict() if isinstance(event, EvidenceEvent) else EvidenceEvent.from_dict(event).to_dict()
        self.queue.put_nowait(payload)
        if self.fanout_path is not None:
            self.fanout_path.parent.mkdir(parents=True, exist_ok=True)
            with self.fanout_path.open('a', encoding='utf-8') as fh:
                fh.write(json.dumps(payload, ensure_ascii=False) + '\n')
        return payload

    def publish_many(self, events: Iterable[EvidenceEvent | Dict[str, object]]) -> List[Dict[str, object]]:
        return [self.publish(item) for item in events]

    def drain(self, limit: Optional[int] = None) -> List[Dict[str, object]]:
        items: List[Dict[str, object]] = []
        max_items = limit if isinstance(limit, int) and limit > 0 else None
        while True:
            if max_items is not None and len(items) >= max_items:
                break
            try:
                items.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return items

    def read_fanout(self, limit: Optional[int] = None) -> List[Dict[str, object]]:
        if self.fanout_path is None or not self.fanout_path.exists():
            return []
        rows = self.fanout_path.read_text(encoding='utf-8').splitlines()
        if isinstance(limit, int) and limit > 0:
            rows = rows[-limit:]
        items: List[Dict[str, object]] = []
        for row in rows:
            row = row.strip()
            if not row:
                continue
            try:
                items.append(EvidenceEvent.from_dict(json.loads(row)).to_dict())
            except Exception:
                continue
        return items
