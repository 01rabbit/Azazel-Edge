"""Real unprivileged Core shutdown/file controls; no enforcement or safety claim."""

import json
import os
from pathlib import Path
import subprocess
import time

import pytest


@pytest.mark.parametrize(
    "unsafe_audit", [False, True], ids=["persist-admitted-tail", "refuse-symlink-write"]
)
def test_real_core_admitted_only_shutdown_is_prospective_and_bounded(
    rust_core_bin, tmp_path, unsafe_audit
):
    eve, events = tmp_path / "eve.json", tmp_path / "normalized.jsonl"
    audit, err = tmp_path / "ingress-audit.jsonl", tmp_path / "core.stderr"
    eve.write_bytes(b"")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AZAZEL_")}
    env.update(
        AZAZEL_EVE_PATH=str(eve),
        AZAZEL_NORMALIZED_EVENT_LOG=str(events),
        AZAZEL_DEFENSE_RELEASE_LEDGER=str(tmp_path / "ledger.json"),
        AZAZEL_FORWARD_AI="false",
        AZAZEL_DEFENSE_ENFORCE="false",
        AZAZEL_EVENT_STDOUT="off",
        AZAZEL_REDIRECT_POLICY_PATH=str(
            Path(__file__).resolve().parents[1] / "config/redirect_policy.yaml"
        ),
    )
    with err.open("w") as output:
        proc = subprocess.Popen(
            [str(rust_core_bin)],
            cwd=tmp_path,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=output,
        )
        try:
            until = time.monotonic() + 8
            while "azazel-edge-core started" not in err.read_text():
                assert proc.poll() is None, err.read_text()
                assert time.monotonic() < until, "Core startup unavailable"
                time.sleep(0.02)
            with eve.open("a") as stream:
                for i in range(3):
                    stream.write(
                        json.dumps(
                            dict(
                                timestamp="2026-11-13T00:00:00Z",
                                event_type="alert",
                                src_ip="192.0.2.1",
                                dest_ip="192.0.2.2",
                                dest_port=22,
                                proto="TCP",
                                alert=dict(
                                    signature_id=910000 + i,
                                    severity=3,
                                    signature="shutdown counter control",
                                ),
                            )
                        )
                        + "\n"
                    )
                stream.flush()
                os.fsync(stream.fileno())
            until = time.monotonic() + 8
            while not events.exists() or len(events.read_bytes().splitlines()) < 3:
                assert proc.poll() is None, err.read_text()
                assert time.monotonic() < until, (
                    "Original admitted observations unavailable"
                )
                time.sleep(0.02)
            original = events.read_bytes()
            # More than the unchanged periodic audit interval, with no new input.
            time.sleep(1.25)
            assert not audit.exists(), "No new periodic admission-only chatter"
            canary = tmp_path / "canary"
            if unsafe_audit:
                canary.write_bytes(b"original controlled file\n")
                audit.symlink_to(canary)
            proc.terminate()
            proc.wait(timeout=12)
            assert proc.returncode == 0, err.read_text()
            assert events.read_bytes() == original
            if unsafe_audit:
                assert canary.read_bytes() == b"original controlled file\n"
                assert "ingress audit write failed" in err.read_text()
            else:
                rows = [json.loads(line) for line in audit.read_bytes().splitlines()]
                assert len(rows) == 1
                row = rows[0]["ingress_shed"]
                assert row["interval_end"] == "shutdown"
                assert row["examined"] == row["admitted"] == row["alerts_admitted"] == 3
                assert row["shed_total"] == row["alerts_shed"] == 0
                assert not audit.with_name(audit.name + ".1").exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
