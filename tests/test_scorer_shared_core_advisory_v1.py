"""Shared-core advisory use on the ordinary scorer path (normal unit discovery).

These tests do NOT require the optional Azazel-MIO package: a fake
``azazel_mio.fast_assessment`` module is injected into ``sys.modules`` so that the
exact-match, mismatch, and package/error fallback branches are all exercised
deterministically. Exact-corpus parity against the real pinned package stays in
tests/benchmark/test_scorer_mio_shadow.py.
"""

from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch

ROOT_PY = __import__("pathlib").Path(__file__).resolve().parents[1] / "py"
if str(ROOT_PY) not in sys.path:
    sys.path.insert(0, str(ROOT_PY))

from azazel_edge.tactics_engine.scorer import TacticalScorer  # noqa: E402


FEATURES = {"suricata_sid": 9901251, "suricata_sev": 2, "target_port": 443}
BENIGN = {"suricata_category": "unknown", "suricata_sev": 3, "target_port": 445}


def _fake_module(assess):
    """Build a fake azazel_mio.fast_assessment with a given assess_fast callable."""
    pkg = types.ModuleType("azazel_mio")
    mod = types.ModuleType("azazel_mio.fast_assessment")
    mod.FastAssessmentInput = lambda **kwargs: kwargs
    mod.PortSignal = lambda kind, port: (kind, port)
    mod.assess_fast = assess
    pkg.fast_assessment = mod
    return {"azazel_mio": pkg, "azazel_mio.fast_assessment": mod}


def _result(score, factors):
    return types.SimpleNamespace(score=score, factors=tuple(factors))


class SharedCoreAdvisoryTests(unittest.TestCase):
    def setUp(self):
        # Reference values from Edge's local calculation with the package absent.
        with patch.dict(sys.modules, {"azazel_mio.fast_assessment": None}):
            self.ref = {}
            for name, feats in (("c2", FEATURES), ("benign", BENIGN)):
                breakdown = TacticalScorer().score(feats)
                self.ref[name] = (breakdown.score, list(breakdown.factors))

    def test_exact_match_uses_shared_core(self):
        score, factors = self.ref["c2"]
        seen = {}

        def assess(inputs):
            seen["inputs"] = inputs
            return _result(score, factors)

        with patch.dict(sys.modules, _fake_module(assess)):
            result = TacticalScorer().score(FEATURES)

        self.assertIn("inputs", seen)
        self.assertEqual(result.source, "shared_core")
        self.assertEqual((result.score, result.factors), (score, factors))
        self.assertIsInstance(result.factors, list)
        self.assertEqual(result.shadow["status"], "complete")
        self.assertIs(result.shadow["matches"], True)
        self.assertEqual(result.shadow["authority"], "comparison_only")

    def test_mismatch_falls_back_to_local_and_degrades(self):
        score, factors = self.ref["c2"]
        for bad in (_result(score + 1, factors), _result(score, factors[:-1] + ["other"])):
            with self.subTest(bad=bad):
                with patch.dict(sys.modules, _fake_module(lambda _i, b=bad: b)):
                    result = TacticalScorer().score(FEATURES)
                self.assertEqual(result.source, "edge_local")
                self.assertEqual((result.score, result.factors), (score, factors))
                self.assertEqual(result.shadow["status"], "degraded")
                self.assertEqual(result.shadow["reason"], "parity_mismatch")
                self.assertIs(result.shadow["matches"], False)

    def test_non_int_shared_score_is_a_mismatch(self):
        score, factors = self.ref["c2"]
        with patch.dict(sys.modules, _fake_module(lambda _i: _result(float(score), factors))):
            result = TacticalScorer().score(FEATURES)
        self.assertEqual(result.source, "edge_local")
        self.assertIs(result.shadow["matches"], False)
        self.assertEqual(result.shadow["status"], "degraded")

    def test_package_error_falls_back_to_local(self):
        score, factors = self.ref["c2"]

        def boom(_i):
            raise RuntimeError("kernel failure")

        with patch.dict(sys.modules, _fake_module(boom)):
            result = TacticalScorer().score(FEATURES)
        self.assertEqual(result.source, "edge_local")
        self.assertEqual((result.score, result.factors), (score, factors))
        self.assertEqual(result.shadow, {"authority": "comparison_only", "mode": "shadow",
                                         "status": "degraded", "reason": "assessment_failed"})

    def test_malformed_package_return_falls_back_to_local(self):
        score, factors = self.ref["c2"]
        with patch.dict(sys.modules, _fake_module(lambda _i: None)):
            result = TacticalScorer().score(FEATURES)
        self.assertEqual(result.source, "edge_local")
        self.assertEqual((result.score, result.factors), (score, factors))
        self.assertEqual(result.shadow["status"], "degraded")

    def test_missing_package_keeps_local_and_is_unavailable(self):
        score, factors = self.ref["benign"]
        with patch.dict(sys.modules, {"azazel_mio.fast_assessment": None}):
            result = TacticalScorer().score(BENIGN)
        self.assertEqual(result.source, "edge_local")
        self.assertEqual((result.score, result.factors), (score, factors))
        self.assertEqual(result.shadow, {"authority": "comparison_only", "mode": "shadow",
                                         "status": "unavailable", "reason": "package_unavailable"})

    def test_score_with_features_tuple_unchanged_on_fallback(self):
        score, factors = self.ref["c2"]
        with patch.dict(sys.modules, {"azazel_mio.fast_assessment": None}):
            self.assertEqual(TacticalScorer().score_with_features(FEATURES), (score, factors))


if __name__ == "__main__":
    unittest.main()
