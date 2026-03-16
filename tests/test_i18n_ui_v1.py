import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = PROJECT_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.i18n import (
    localize_runbook_steps,
    localize_runbook_title,
    localize_runbook_user_message,
    normalize_lang,
    translate_review_text,
)
from azazel_edge.runbooks import get_runbook
from azazel_edge.runbook_review import review_runbook_id
from azazel_edge_web.app import _extract_mattermost_context_and_text, app


class I18nUiV1Test(unittest.TestCase):
    def test_normalize_lang(self):
        self.assertEqual(normalize_lang("ja-JP"), "ja")
        self.assertEqual(normalize_lang("en-US"), "en")
        self.assertEqual(normalize_lang(""), "ja")

    def test_runbook_user_message_localized(self):
        runbook = get_runbook("rb.user.reconnect-guide", lang="en")
        self.assertIn("Turn Wi-Fi off once", localize_runbook_user_message(runbook, lang="en"))
        self.assertIn("Wi-Fiを一度オフ", localize_runbook_user_message(runbook, lang="ja"))

    def test_runbook_title_and_steps_localized(self):
        runbook = get_runbook("rb.noc.service.status.check", lang="ja")
        self.assertEqual(localize_runbook_title(runbook, lang="ja"), "サービス状態確認")
        steps = localize_runbook_steps(runbook, lang="ja")
        self.assertTrue(steps)
        self.assertIn("影響している機能", steps[0])

    def test_review_text_localized(self):
        translated = translate_review_text("Runbook has no steps.", lang="ja")
        self.assertEqual(translated, "Runbook に steps がありません。")

    def test_runbook_review_returns_ja_findings(self):
        result = review_runbook_id("rb.noc.default-route.check", context={"lang": "ja"})
        self.assertTrue(result["ok"])
        self.assertIsInstance(result["findings"], list)

    def test_dashboard_template_renders_english(self):
        client = app.test_client()
        res = client.get("/?lang=en")
        self.assertEqual(res.status_code, 200)
        body = res.get_data(as_text=True)
        self.assertIn("Azazel-Edge Command Dashboard", body)
        self.assertIn('id="langEnBtn" class="audience-btn active lang-active-en"', body)

    def test_ops_comm_template_renders_japanese_toggle(self):
        client = app.test_client()
        res = client.get("/ops-comm?lang=ja")
        self.assertEqual(res.status_code, 200)
        body = res.get_data(as_text=True)
        self.assertIn("M.I.O. Ops Communication", body)
        self.assertIn("Command Workspace", body)
        self.assertIn("日本語", body)
        self.assertIn("English", body)
        self.assertIn('id="langJaBtn" class="audience-btn active lang-active-ja"', body)
        self.assertIn('id="opsProgressSummary"', body)
        self.assertIn('id="opsProgressList"', body)
        self.assertIn('id="opsProgressBlocked"', body)

    def test_dashboard_japanese_keeps_titles_in_english(self):
        client = app.test_client()
        res = client.get("/?lang=ja")
        self.assertEqual(res.status_code, 200)
        body = res.get_data(as_text=True)
        self.assertIn("Current Mission", body)
        self.assertIn("SOC/NOC 向けの状況盤", body)

    def test_mattermost_prefixes_can_switch_audience_and_language(self):
        audience, lang, text = _extract_mattermost_context_and_text("en: temp: DNS is failing")
        self.assertEqual(audience, "beginner")
        self.assertEqual(lang, "en")
        self.assertEqual(text, "DNS is failing")


if __name__ == "__main__":
    unittest.main()
