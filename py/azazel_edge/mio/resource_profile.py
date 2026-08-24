"""Small, optional resource sampler for model-comparison/HIL runs.

It is intentionally not used by the offline CI corpus: host measurements are
provenance, not portable performance claims.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import os
import resource
import sys
import time
from typing import Any


@dataclass(frozen=True)
class ResourceSample:
    elapsed_ms: float
    peak_rss_kib: int
    pid: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ResourceTimer:
    def __enter__(self) -> "ResourceTimer":
        self._started = time.perf_counter()
        return self

    def __exit__(self, *_args: object) -> None:
        raw_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # macOS reports bytes; Linux reports KiB. Normalize the artifact field.
        peak_rss_kib = raw_rss // 1024 if sys.platform == "darwin" else raw_rss
        self.sample = ResourceSample(
            elapsed_ms=round((time.perf_counter() - self._started) * 1000, 3),
            peak_rss_kib=peak_rss_kib,
            pid=os.getpid(),
        )
