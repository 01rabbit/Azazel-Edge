"""Bounded Linux lab measurements; no runtime or efficacy authority."""

import hashlib
import json
from pathlib import Path
import stat

NORMALIZED = (
    "src_ip",
    "dst_ip",
    "attack_type",
    "severity",
    "target_port",
    "protocol",
    "sid",
    "category",
    "event_type",
    "action",
    "confidence",
    "risk_score",
    "technique_ids",
)
DEFENSE = ("action", "reason", "policy_reason", "delay_ms", "target")
ENFORCEMENT = (
    "mode",
    "selected_action",
    "target",
    "policy_reason",
    "command_plan",
    "rollback_plan",
    "executed_count",
    "failed_count",
    "errors",
    "rollback_hint",
    "result",
)
STATUS = (
    "enforce_enabled",
    "enforce_level",
    "dry_run",
    "high_impact_auto",
    "allowed_actions",
)


def semantics(rows, expected_sids):
    """Exact ordered input coverage before comparing explicit semantic fields.

    Omit timestamps/ingest epoch/trace IDs and variable release metadata. All
    failure counts, errors, selected actions and requested commands remain.
    """
    if [r["normalized"]["sid"] for r in rows] != list(expected_sids):
        raise ValueError("incomplete, reordered or duplicate decision coverage")
    projected = []
    for row in rows:
        if row["pipeline"] != "rust_event_engine_v1" or row["source"] != "suricata_eve":
            raise ValueError("unexpected decision producer")
        if (
            row["enforcement_status"]["enforce_enabled"] is not False
            or row["enforcement_status"]["dry_run"] is not True
        ):
            raise ValueError("measurement cannot enable enforcement")
        projected.append(
            {
                name: {key: row[name][key] for key in keys}
                for name, keys in (
                    ("normalized", NORMALIZED),
                    ("defense", DEFENSE),
                    ("enforcement", ENFORCEMENT),
                    ("enforcement_status", STATUS),
                )
            }
        )
    return projected


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _text(path):
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError("proc sample byte bound")
    return raw.decode()


def process_sample(pid, *, expected_start=None, proc_root=Path("/proc")):
    """PID/start-time pin, Linux ticks and KiB; no zero substitution on loss."""
    try:
        root = proc_root / str(pid)

        def identity():
            fields = _text(root / "stat").rsplit(")", 1)[1].split()
            if fields[0] == "Z":
                raise ValueError("process exited")
            return fields, int(fields[19])

        fields, start = identity()
        if expected_start is not None and start != expected_start:
            raise ValueError("PID identity changed")
        status = dict(
            line.split(":", 1)
            for line in _text(root / "status").splitlines()
            if ":" in line
        )
        io = dict(line.split(":", 1) for line in _text(root / "io").splitlines())
        if identity()[1] != start:
            raise ValueError("PID identity changed during sample")
        return dict(
            available=True,
            pid=pid,
            start_ticks=start,
            cpu_ticks=int(fields[11]) + int(fields[12]),
            rss_kib=int(status["VmRSS"].split()[0]),
            kernel_hwm_kib=int(status["VmHWM"].split()[0]),
            read_bytes=int(io["read_bytes"]),
            write_bytes=int(io["write_bytes"]),
        )
    except (OSError, ValueError, KeyError, IndexError, UnicodeError):
        return dict(
            available=False,
            pid=pid,
            start_ticks=expected_start
            if expected_start is not None
            else locals().get("start"),
            cpu_ticks=None,
            rss_kib=None,
            kernel_hwm_kib=None,
            read_bytes=None,
            write_bytes=None,
        )


def process_summary(samples, ticks_per_second):
    valid = [s for s in samples if s["available"]]
    complete = bool(valid) and len(valid) == len(samples)
    return dict(
        coverage="complete" if complete else "incomplete",
        samples=len(samples),
        available_samples=len(valid),
        cpu_seconds=(valid[-1]["cpu_ticks"] - valid[0]["cpu_ticks"]) / ticks_per_second
        if complete
        else None,
        sampled_peak_rss_kib=max((s["rss_kib"] for s in valid), default=None),
        kernel_hwm_kib=max((s["kernel_hwm_kib"] for s in valid), default=None),
        read_bytes_delta=valid[-1]["read_bytes"] - valid[0]["read_bytes"]
        if complete
        else None,
        write_bytes_delta=valid[-1]["write_bytes"] - valid[0]["write_bytes"]
        if complete
        else None,
        final=samples[-1] if samples else None,
    )


def store_bytes(root):
    """Logical sizes, bounded inventory; unavailable if any path is unsafe/lost."""
    try:
        paths = list(root.rglob("*"))
        if len(paths) > 128:
            raise ValueError("store inventory bound")
        total = 0
        for path in paths:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
            elif not stat.S_ISDIR(info.st_mode):
                # Witness Unix socket is not on-disk payload.
                if not stat.S_ISSOCK(info.st_mode):
                    raise ValueError("unexpected store entry")
        return total
    except (OSError, ValueError):
        return None
