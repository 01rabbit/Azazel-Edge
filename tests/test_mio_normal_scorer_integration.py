from __future__ import annotations

import json
from importlib.metadata import distribution
from pathlib import Path
import re
import sys
from unittest.mock import patch

import azazel_mio.fast_assessment as mio_fast_assessment  # missing pin must fail, not skip

from azazel_edge.tactics_engine import TacticalScorer
from azazel_edge_ai import agent


class _DecisionLayers:
    def enrich_with_second_pass(self, event: dict, advisory: dict) -> dict:
        return {"stage": "second_pass", "engine": "evidence_plane_soc_v1", "status": "completed"}


class _DecisionLogger:
    def log_decision(self, record: object) -> bool:
        return True


def test_normal_advisory_path_uses_real_mio_fast_assessment() -> None:
    runtime_requirements = Path(__file__).resolve().parents[1] / "requirements/runtime.txt"
    pin_lines = [
        line.strip()
        for line in runtime_requirements.read_text(encoding="utf-8").splitlines()
        if line.strip().lower().startswith("azazel-mio @ ")
    ]
    assert len(pin_lines) == 1, "runtime.txt must declare exactly one MIO pin"
    pin_match = re.fullmatch(
        r"azazel-mio @ git\+https://github\.com/01rabbit/Azazel-MIO\.git@([0-9a-f]{40})",
        pin_lines[0],
    )
    assert pin_match is not None, "runtime.txt MIO dependency must use a full immutable Git SHA"
    declared_mio_commit = pin_match.group(1)

    installed_mio = distribution("azazel-mio")
    assert installed_mio.version == "0.1.0.dev20261106+gitbb6dcfd", (
        "Edge and Nexus must identify the same MIO development package"
    )
    direct_url_text = installed_mio.read_text("direct_url.json")
    assert direct_url_text is not None, "MIO must be installed from its immutable VCS source pin"
    direct_url = json.loads(direct_url_text)
    vcs_info = direct_url.get("vcs_info")
    installed_mio_commit = vcs_info.get("commit_id") if isinstance(vcs_info, dict) else None
    assert installed_mio_commit == declared_mio_commit, (
        "installed MIO source commit must match requirements/runtime.txt"
    )
    assert sys.modules.get("azazel_mio.fast_assessment") is mio_fast_assessment
    assert mio_fast_assessment.assess_fast.__module__ == "azazel_mio.fast_assessment"
    assert Path(mio_fast_assessment.__file__).resolve() == Path(
        installed_mio.locate_file("azazel_mio/fast_assessment.py")
    ).resolve()

    event = {
        "normalized": {
            "ts": "2026-11-04T00:00:00Z",
            "src_ip": "203.0.113.9",
            "dst_ip": "192.168.40.10",
            "attack_type": "ET SCAN Nmap port scan",
            "severity": 2,
            "target_port": 22,
            "protocol": "TCP",
            "sid": 2402000,
            "category": "network-scan",
            "event_type": "alert",
            "action": "allowed",
        },
        "defense": {"action": "notify", "reason": "fixture"},
        "enforcement": {"trace_id": "trace-real-scorer"},
    }
    adapter_result = {
        "schema_version": "azazel.mio_auxiliary.v1",
        "status": "unavailable",
        "reason": "test_isolation",
        "authority": "read_only_advisory",
        "source": "mio_shared_core",
        "generation": "",
        "max_age_seconds": 10.0,
        "trace_id": "",
        "provenance": {"observations": [], "derived_signals": []},
        "knowledge": {"status": "not_provided", "refs": []},
        "advisory": None,
    }

    # Keep the product scorer and installed MIO kernel real. Patch only unrelated
    # second-pass, logging, correlation, metrics and async-worker side effects.
    assert type(agent.SCORER) is TacticalScorer
    with patch.object(agent, "DECISION_LAYERS", _DecisionLayers()), patch.object(
        agent, "DECISION_LOGGER", _DecisionLogger()
    ), patch.object(agent.LIVE_MIO_AUXILIARY, "submit", return_value=adapter_result), patch.object(
        agent, "_evaluate_correlation", return_value={"force_llm": False}
    ), patch.object(agent, "_metrics_inc"), patch.object(
        agent, "_LAST_RISK_SCORE", 0
    ), patch.object(agent, "_LAST_STATE_NAME", "NORMAL"):
        advisory = agent._build_advisory(event)

    comparison = advisory["mio_score_comparison"]
    assert comparison["authority"] == "comparison_only"
    assert comparison["status"] == "complete", comparison
    assert comparison["matches"] is True
    assert type(comparison["mio_score"]) is int
    assert comparison["mio_score"] == comparison["edge_score"] == advisory["risk_score"]
    assert comparison["mio_score"] > 0
    assert comparison["mio_factors"] == advisory["score_factors"]
    assert "threat_class=scan(36)" in comparison["mio_factors"]
    assert "admin_port=22" in comparison["mio_factors"]
    assert advisory["score_engine"] == "tactical_scorer_v1"
    assert advisory["decision_pipeline"]["first_pass"]["engine"] == "tactical_scorer_v1"
