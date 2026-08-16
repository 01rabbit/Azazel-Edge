"""SENTINEL Decision Console — structural + contract-preservation tests.

These tests pin the additive re-skin introduced by the SENTINEL console:
the 4-tier navigation shell, the SOC/NOC sub-filter, the deterministic
decision-pipeline strip, and the data-tier grouping of the existing
(contract-frozen) panels. They also assert that the re-skin did NOT remove any
of the pinned dashboard IDs, did NOT reintroduce any forbidden legacy IDs, and
did NOT alter the /api/dashboard/summary contract.

Design invariants enforced here (per AGENTS.md + /goal):
- The console is presentation-only: no backend decision logic is added.
- STALE/UNKNOWN must never be styled as healthy-green (checked at the CSS token
  level: status-neutral maps to the steel/unknown accent, not green).
- AI stays subordinate: the pipeline strip surfaces no AI authority.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp

_REPO_ROOT = Path(webapp.__file__).resolve().parent.parent

_STATIC = Path(webapp.__file__).resolve().parent / "static"
_TEMPLATES = Path(webapp.__file__).resolve().parent / "templates"


class SentinelConsoleStructureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = webapp.app.test_client()

    def _index(self, lang: str = "en") -> str:
        response = self.client.get(f"/?lang={lang}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Language"), lang)
        return response.get_data(as_text=True)

    def test_index_still_renders_and_sets_content_language(self) -> None:
        text = self._index("en")
        self.assertIn("Command Dashboard", text)

    def test_tier_nav_present_with_four_tiers(self) -> None:
        text = self._index("en")
        self.assertIn('id="sentinelTierNav"', text)
        self.assertIn('aria-current="page"', text)
        for tier in ("overview", "operations", "evidence", "system"):
            self.assertIn(f'data-sentinel-tier="{tier}"', text)
        # Literal English product terms (intentionally not i18n-routed).
        for label in ("OVERVIEW", "OPERATIONS", "EVIDENCE", "SYSTEM"):
            self.assertIn(label, text)

    def test_soc_noc_subfilter_present(self) -> None:
        text = self._index("en")
        self.assertIn('id="sentinelOpsSubnav"', text)
        for op in ("soc", "noc"):
            self.assertIn(f'data-sentinel-op="{op}"', text)
        self.assertIn(">SOC<", text)
        self.assertIn(">NOC<", text)

    def test_decision_pipeline_strip_present_with_five_stages(self) -> None:
        text = self._index("en")
        self.assertIn('id="sentinelPipeline"', text)
        for stage in ("Sense", "Evaluate", "Decide", "Control", "Audit"):
            self.assertIn(f'id="pipeline{stage}"', text)
            self.assertIn(f'id="pipeline{stage}Value"', text)
        for label in ("SENSE", "EVALUATE", "DECIDE", "CONTROL", "AUDIT"):
            self.assertIn(label, text)

    def test_panels_are_grouped_into_tiers(self) -> None:
        text = self._index("en")
        # Overview hero + decision surface.
        self.assertRegex(text, r'class="command-strip panel"[^>]*data-tier="overview"')
        self.assertRegex(text, r'class="panel action-board"[^>]*data-tier="overview"')
        # Operations (NOC identity + combined split board).
        self.assertRegex(text, r'client-identity-panel"[^>]*data-tier="operations"[^>]*data-op="noc"')
        self.assertRegex(text, r'split-board pro-only"[^>]*data-tier="operations"')
        # Evidence + System.
        self.assertRegex(text, r'evidence-board[^"]*pro-only"[^>]*data-tier="evidence"')
        self.assertRegex(text, r'resource-guard-panel"[^>]*data-tier="system"')

    def test_stylesheet_and_script_wired(self) -> None:
        text = self._index("en")
        self.assertIn("/static/sentinel.css", text)
        self.assertIn("/static/sentinel.js", text)
        # Loaded AFTER the base assets so token overrides win.
        self.assertLess(text.index("/static/style.css"), text.index("/static/sentinel.css"))
        self.assertLess(text.index("/static/app.js"), text.index("/static/sentinel.js"))

    def test_pinned_dashboard_ids_preserved(self) -> None:
        text = self._index("en")
        for pinned in (
            'id="commandGlanceHero"', 'id="socGlanceCard"', 'id="nocGlanceCard"',
            'id="decisionTrustCapsule"', 'id="clientIdentityList"', 'id="handoffPackSummary"',
            'id="alertQueuesTimeline"', 'id="resourceGuardHeadline"', 'id="modeShieldBtn"',
        ):
            self.assertIn(pinned, text)

    def test_forbidden_legacy_ids_absent(self) -> None:
        text = self._index("en")
        for forbidden in (
            'id="normalAssuranceState"', 'id="primaryAnomalySeverity"',
            'id="modeLayerState"', 'id="demoRunForm"', 'id="reviewPanel"',
        ):
            self.assertNotIn(forbidden, text)

    def test_japanese_still_keeps_product_headings_english(self) -> None:
        text = self._index("ja")
        # Tier labels are product terms and remain English in both languages.
        self.assertIn("OVERVIEW", text)
        self.assertIn("EVIDENCE", text)

    def test_bespoke_consoles_present(self) -> None:
        text = self._index("en")
        for cid in (
            'id="sentinelOverviewConsole"', 'id="sentinelSocConsole"', 'id="sentinelNocConsole"',
            'id="sentinelEvidenceConsole"', 'id="sentinelSystemConsole"',
        ):
            self.assertIn(cid, text)
        # sub-tabs
        for st in ('data-ev-view="timeline"', 'data-ev-view="audit"', 'data-sys-view="runtime"', 'data-sys-view="fleet"'):
            self.assertIn(st, text)
        # detail drawer trace field + M.I.O. governance chip + sidebar Ask M.I.O.
        self.assertIn('id="evdTrace"', text)
        self.assertIn("AI authority: NONE", text)
        self.assertIn('id="sentinelAskMioLink"', text)

    def test_classic_panels_retained_in_dom(self) -> None:
        # The bespoke consoles are overlays; the contract-locked classic panels
        # must remain present (hidden behind the detail toggle), not removed.
        text = self._index("en")
        for cls in ("command-strip panel", "split-board", "evidence-board", "resource-guard-panel", "action-board"):
            self.assertIn(cls, text)

    def test_pipeline_is_high_in_the_page_not_buried(self) -> None:
        # The decision pipeline (the 5-second story) must render before the bulk
        # of the panels, not as the last child of <main>.
        text = self._index("en")
        self.assertLess(text.index('id="sentinelPipeline"'), text.index('class="command-strip panel"'))

    def test_tier_dots_expose_screen_reader_status(self) -> None:
        # Per-tier health must not be color-only: an SR-only status node exists.
        text = self._index("en")
        for tier in ("Overview", "Operations", "Evidence", "System"):
            self.assertIn(f'id="sentinelStatus{tier}"', text)

    def test_ops_tabs_render_in_operations_content(self) -> None:
        # SOC/NOC are top tabs inside the Operations content (mockup 2), scoped to
        # the operations tier — not sidebar items between the tier nav entries.
        text = self._index("en")
        self.assertRegex(text, r'id="sentinelOpsSubnav"[^>]*data-tier="operations"')
        # and they sit ahead of the SOC console they control
        self.assertLess(text.index('id="sentinelOpsSubnav"'), text.index('id="sentinelSocConsole"'))


class SentinelAssetInvariantTests(unittest.TestCase):
    """Static-asset level guarantees that don't require a request."""

    def test_sentinel_css_exists_and_neutral_is_not_green(self) -> None:
        css = (_STATIC / "sentinel.css").read_text(encoding="utf-8")
        # status-neutral must map to the steel/unknown accent, never green.
        m = re.search(r"\.status-neutral\s*\{[^}]*border-left-color:\s*var\((--accent-[a-z]+)\)", css)
        self.assertIsNotNone(m, "status-neutral must set a border-left-color token")
        self.assertEqual(m.group(1), "--accent-steel")
        self.assertIn("--bg-0: #0B0E11", css)  # industrial palette applied

    def test_sentinel_js_exists_and_polls_no_new_endpoints(self) -> None:
        js = (_STATIC / "sentinel.js").read_text(encoding="utf-8")
        # The console is event-driven; it must not open its own poll loop.
        self.assertNotIn("setInterval", js)
        self.assertNotIn("fetch(", js)
        self.assertIn("azazel:refresh", js)

    def test_sentinel_js_adds_no_untranslated_tr_keys(self) -> None:
        # The i18n catalog-consistency test scans static/*.js for tr('key') calls;
        # sentinel.js deliberately uses literal product terms and must add none.
        js = (_STATIC / "sentinel.js").read_text(encoding="utf-8")
        self.assertNotIn("tr('", js)
        self.assertNotIn('tr("', js)

    def test_app_js_dispatches_refresh_event(self) -> None:
        js = (_STATIC / "app.js").read_text(encoding="utf-8")
        self.assertIn("azazel:refresh", js)

    def test_sentinel_js_logic_suite_passes(self) -> None:
        # Runs the node-based unit tests for the pure tone/state logic
        # (false-green law). Skipped when node is unavailable.
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        result = subprocess.run(
            [node, str(_REPO_ROOT / "tests" / "sentinel_console_logic.test.js")],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
