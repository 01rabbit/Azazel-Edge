from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .adapter import from_rust_event
from .contracts import ShadowMode


DEFAULT_INPUT = "/var/log/azazel-edge/normalized-events.jsonl"
DEFAULT_OUTPUT = "/var/log/azazel-edge/outcome-shadow.jsonl"


class ShadowOutcomeObserver:
    """Passive observer for the existing Rust event-engine output.

    It has no reference to an executor and therefore cannot authorize, retry, release,
    or override a defensive action.
    """

    def __init__(self, mode: ShadowMode = ShadowMode.SHADOW_RECORD) -> None:
        self.mode = mode

    def observe(self, event: Mapping[str, Any]) -> dict[str, Any] | None:
        if self.mode is ShadowMode.OFF:
            return None
        bundle = from_rust_event(event)
        record = bundle.to_dict()
        record["observer_mode"] = self.mode.value
        # SHADOW_ASSESS is intentionally not automatic here: tactical assessment
        # requires a policy-owned EffectObjective and a post-action observation window.
        record["effect_assessment"] = None
        return record


def iter_jsonl(path: Path, *, follow: bool = False, poll_seconds: float = 0.25) -> Iterator[Mapping[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        while True:
            line = stream.readline()
            if line:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, Mapping):
                    yield value
                continue
            if not follow:
                return
            time.sleep(max(0.05, poll_seconds))


def append_jsonl(path: Path, values: Iterable[Mapping[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("a", encoding="utf-8", buffering=1) as stream:
        for value in values:
            stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
            count += 1
    return count


def _mode_from_env(value: str | None) -> ShadowMode:
    raw = (value or ShadowMode.SHADOW_RECORD.value).strip().lower()
    try:
        return ShadowMode(raw)
    except ValueError as exc:
        raise ValueError(f"invalid outcome observer mode: {raw}") from exc


def run(
    *,
    input_path: Path,
    output_path: Path,
    mode: ShadowMode,
    follow: bool,
    poll_seconds: float,
) -> int:
    observer = ShadowOutcomeObserver(mode)
    if mode is ShadowMode.OFF:
        return 0

    def records() -> Iterator[Mapping[str, Any]]:
        for event in iter_jsonl(input_path, follow=follow, poll_seconds=poll_seconds):
            try:
                record = observer.observe(event)
            except ValueError:
                continue
            if record is not None:
                yield record

    return append_jsonl(output_path, records())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passive Azazel Outcome-as-Evidence shadow observer")
    parser.add_argument("--input", default=os.environ.get("AZAZEL_OUTCOME_INPUT", DEFAULT_INPUT))
    parser.add_argument("--output", default=os.environ.get("AZAZEL_OUTCOME_OUTPUT", DEFAULT_OUTPUT))
    parser.add_argument(
        "--mode",
        default=os.environ.get("AZAZEL_OUTCOME_MODE", ShadowMode.SHADOW_RECORD.value),
        choices=[mode.value for mode in ShadowMode],
    )
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    args = parser.parse_args(argv)
    mode = _mode_from_env(args.mode)
    run(
        input_path=Path(args.input),
        output_path=Path(args.output),
        mode=mode,
        follow=args.follow,
        poll_seconds=args.poll_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
