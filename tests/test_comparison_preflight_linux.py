"""Actual unprivileged offline execution of pure software; no live comparison."""

import os
import sys
import json
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() == 0,
    reason="offline Linux unprivileged process required, not a measurement pass",
)


def test_offline_unprivileged_preflight_replays_originals_without_launching(tmp_path):
    from run_comparison_preflight import run

    destination = os.environ.get("EDGE_PREFLIGHT_PUBLIC_DIR", str(tmp_path / "public"))
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    assert all(
        int(status[name].strip(), 16) == 0 for name in ("CapEff", "CapPrm", "CapAmb")
    )
    assert status["NoNewPrivs"].strip() == "1"
    # Fail any accidental launch or network attempt during either pure pipeline.
    with (
        patch("subprocess.Popen", side_effect=AssertionError("unexpected launch")),
        patch("socket.socket", side_effect=AssertionError("unexpected network")),
    ):
        result = run(destination)
    assert result["actual_comparison_started"] is False
    assert result["comparison_qualified"] is False
    assert result["qualified_safety_count"] is None
    assert result["preflight"]["assigned_runs"] == 36
    assert len(result["preflight"]["missing_assignments"]) == 36
    assert result["preflight"]["comparison_result"] is None
    assert result["original_synthetic_pilot"]["scenarios"] == 9
    assert result["original_synthetic_pilot"]["assigned_runs"] == 36
    assert result["original_synthetic_pilot"]["claim_status"] == "mechanical_only"
    assert result["original_synthetic_pilot"]["canonical_causal_promotions"] == 0
    boundary = dict(
        uid=os.geteuid(),
        gid=os.getegid(),
        pid=os.getpid(),
        capabilities={
            name: status[name].strip() for name in ("CapEff", "CapPrm", "CapAmb")
        },
        no_new_privs=1,
        data_kind="ACTUAL_LINUX_PROCESS_BOUNDARY_NOT_COMPARISON",
    )
    with (Path(destination) / "process-boundary.json").open("x") as stream:
        json.dump(boundary, stream, sort_keys=True)
        stream.write("\n")
