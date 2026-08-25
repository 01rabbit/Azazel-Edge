from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from .adapter import from_rust_event
from .contracts import ShadowMode


DEFAULT_INPUT = "/var/log/azazel-edge/normalized-events.jsonl"
DEFAULT_OUTPUT = "/var/log/azazel-edge/outcome-shadow.jsonl"
DEFAULT_MAX_OUTPUT_BYTES = 50 * 1024 * 1024


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


def iter_jsonl(
    path: Path,
    *,
    follow: bool = False,
    poll_seconds: float = 0.25,
    start_at_end: bool = False,
) -> Iterator[Mapping[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        if follow and start_at_end:
            stream.seek(0, 2)
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


def _ensure_capacity(path: Path, incoming_bytes: int, max_bytes: int) -> bool:
    if max_bytes <= 0:
        return True
    if incoming_bytes > max_bytes:
        # One pathological record must not defeat the retention bound.
        return False
    if not path.exists():
        return True
    try:
        current_bytes = path.stat().st_size
    except OSError:
        return False
    if current_bytes + incoming_bytes <= max_bytes:
        return True

    archive = Path(f"{path}.1")
    try:
        archive.unlink(missing_ok=True)
        path.replace(archive)
    except OSError:
        # Shadow evidence may be dropped; uncontrolled disk growth is worse.
        return False
    return True


def append_jsonl(
    path: Path,
    values: Iterable[Mapping[str, Any]],
    *,
    max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    for value in values:
        line = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        encoded_bytes = len(line.encode("utf-8"))
        if not _ensure_capacity(path, encoded_bytes, max_bytes):
            continue
        try:
            with path.open("a", encoding="utf-8", buffering=1) as stream:
                stream.write(line)
        except OSError:
            # The observer is best-effort. It must not become a control-path dependency.
            continue
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
    from_start: bool = False,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> int:
    observer = ShadowOutcomeObserver(mode)
    if mode is ShadowMode.OFF:
        return 0

    def records() -> Iterator[Mapping[str, Any]]:
        for event in iter_jsonl(
            input_path,
            follow=follow,
            poll_seconds=poll_seconds,
            start_at_end=follow and not from_start,
        ):
            try:
                record = observer.observe(event)
            except (ValueError, TypeError):
                continue
            if record is not None:
                yield record

    return append_jsonl(output_path, records(), max_bytes=max_output_bytes)


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
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="When following, process existing input before waiting for new records.",
    )
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument(
        "--max-output-bytes",
        type=int,
        default=int(os.environ.get("AZAZEL_OUTCOME_MAX_BYTES", str(DEFAULT_MAX_OUTPUT_BYTES))),
        help="Rotate outcome-shadow.jsonl to .1 before this bound is exceeded; <=0 disables rotation.",
    )
    args = parser.parse_args(argv)
    mode = _mode_from_env(args.mode)
    run(
        input_path=Path(args.input),
        output_path=Path(args.output),
        mode=mode,
        follow=args.follow,
        poll_seconds=args.poll_seconds,
        from_start=args.from_start,
        max_output_bytes=args.max_output_bytes,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
