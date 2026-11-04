"""Complete ordered-result parity for the optional MIO shadow kernel.

Run with a reviewed Azazel-MIO source checkout on PYTHONPATH.
"""
import importlib.abc
import importlib.machinery
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from azazel_edge.tactics_engine.eve_parser import EVEParser
from azazel_edge.tactics_engine.scorer import TacticalScorer, DECEPTION_SIDS

try:
    import azazel_mio.fast_assessment  # noqa: F401
    MIO_AVAILABLE = True
except ImportError:
    MIO_AVAILABLE = False

requires_mio = pytest.mark.skipif(
    not MIO_AVAILABLE, reason="optional pinned MIO source required")

CORPUS = Path(__file__).parent / "corpus"


def assert_parity(features):
    result = TacticalScorer().score(features)
    assert result.shadow == {
        "authority": "comparison_only", "mode": "shadow", "status": "complete",
        "score": result.score, "factors": result.factors, "matches": True,
    }


@requires_mio
@pytest.mark.parametrize("path", sorted(CORPUS.glob("*.jsonl")), ids=lambda p: p.stem)
def test_all_supported_corpus_rows(path):
    parser = EVEParser()
    compared = 0
    for line in path.read_text().splitlines():
        parsed = parser.parse_line(line)
        assert parsed is not None
        features = parser.extract_scorer_features(parsed)
        if features is not None:
            assert_parity(features)
            compared += 1
    assert compared > 0


@requires_mio
@pytest.mark.parametrize("severity", [1, 2, 3, 4, 0, -1, 5, "bad", None])
@pytest.mark.parametrize("features", [
    {},
    {"suricata_category": "unknown", "target_port": 445},
    {"suricata_signature": "c2 beacon", "target_port": 443},
    {"suricata_signature": "password reset c2", "suricata_category": "bad-unknown"},
    {"suricata_category": "network-scan", "suricata_signature": "exfil c2 brute phish poison"},
    {"suricata_sid": "bad", "target_port": "bad", "suricata_action": None},
] + [{"suricata_sid": sid} for sid in sorted(DECEPTION_SIDS)])
@pytest.mark.parametrize("port", [0, 22, 23, 445, 3389, 5900, 80, 443, 53, 12222, 18080, "bad"])
@pytest.mark.parametrize("action", ["allowed", "blocked", "drop", "rejected", "BLOCKED", "unknown"])
def test_normalization_and_corner_boundaries(severity, features, port, action):
    assert_parity({**features, "suricata_sev": severity,
                   "target_port": port, "suricata_action": action})


@requires_mio
def test_shadow_failure_or_mismatch_never_replaces_edge_result():
    from azazel_mio.fast_assessment import FastAssessment
    features = {"suricata_sid": 9901251, "suricata_sev": 2, "target_port": 443}
    expected = TacticalScorer().score_with_features(features)
    with patch("azazel_mio.fast_assessment.assess_fast", return_value=FastAssessment(0, ("different",))):
        result = TacticalScorer().score(features)
        assert (result.score, result.factors) == expected
        assert result.shadow["matches"] is False
    with patch("azazel_mio.fast_assessment.assess_fast", side_effect=RuntimeError("broken")):
        result = TacticalScorer().score(features)
        assert (result.score, result.factors) == expected
        assert result.shadow["status"] == "degraded"


class MissingPackageFinder(importlib.abc.MetaPathFinder):
    """Make azazel_mio (and its submodules) look uninstalled, regardless of PYTHONPATH."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "azazel_mio" or fullname.startswith("azazel_mio."):
            raise ModuleNotFoundError(f"No module named {fullname!r}", name=fullname)
        return None


def test_shadow_package_unavailable_falls_back_to_edge_result():
    features = {"suricata_sid": 9901251, "suricata_sev": 2, "target_port": 443}
    expected = TacticalScorer().score_with_features(features)
    with patch.dict(sys.modules):
        sys.modules.pop("azazel_mio", None)
        sys.modules.pop("azazel_mio.fast_assessment", None)
        with patch("sys.meta_path", [MissingPackageFinder(), *sys.meta_path]):
            result = TacticalScorer().score(features)
        assert (result.score, result.factors) == expected
        assert result.shadow["status"] == "unavailable"


def test_shadow_failed_package_initialization_falls_back_to_edge_result():
    features = {"suricata_sid": 9901251, "suricata_sev": 2, "target_port": 443}
    expected = TacticalScorer().score_with_features(features)

    class FailingPackageLoader(importlib.abc.Loader):
        def create_module(self, spec):
            return None

        def exec_module(self, module):
            raise RuntimeError("initialization failed")

    class FailingPackageFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "azazel_mio":
                return importlib.machinery.ModuleSpec(
                    fullname, FailingPackageLoader(), is_package=True)
            return None

    # Exercise importlib's package initialization without creating files in the checkout.
    with patch.dict(sys.modules):
        sys.modules.pop("azazel_mio", None)
        sys.modules.pop("azazel_mio.fast_assessment", None)
        with patch("sys.meta_path", [FailingPackageFinder(), *sys.meta_path]):
            result = TacticalScorer().score(features)
        assert (result.score, result.factors) == expected
        assert result.source == "edge_local"
        assert result.shadow == {
            "authority": "comparison_only", "mode": "shadow",
            "status": "degraded", "reason": "import_failed",
        }
