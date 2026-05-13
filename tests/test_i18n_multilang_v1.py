import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = PROJECT_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.i18n import SUPPORTED_LANGS, translate
try:
    from azazel_edge_web.app import app
except Exception:
    app = None


CAPTIVE_KEYS = (
    "captive.consent.title",
    "captive.consent.monitoring_notice",
    "captive.consent.operator_label",
    "captive.consent.agree_label",
    "captive.consent.submit",
    "captive.consent.footer",
)


class I18nMultilangV1Test(unittest.TestCase):
    def test_supported_langs_contains_es_uk_tl(self):
        self.assertIn("es", SUPPORTED_LANGS)
        self.assertIn("uk", SUPPORTED_LANGS)
        self.assertIn("tl", SUPPORTED_LANGS)

    def test_es_captive_keys_all_present(self):
        for key in CAPTIVE_KEYS:
            value = translate(key, lang="es", default="")
            self.assertTrue(value)

    def test_uk_captive_keys_all_present(self):
        for key in CAPTIVE_KEYS:
            value = translate(key, lang="uk", default="")
            self.assertTrue(value)

    def test_tl_captive_keys_all_present(self):
        for key in CAPTIVE_KEYS:
            value = translate(key, lang="tl", default="")
            self.assertTrue(value)

    def test_fallback_to_en_for_missing_key(self):
        value = translate("dashboard.title", lang="es", default="")
        self.assertEqual(value, "Azazel-Edge Command Dashboard")

    def test_fallback_to_default_when_missing_in_both(self):
        value = translate("nonexistent.key", lang="es", default="fallback-default")
        self.assertEqual(value, "fallback-default")

    def test_unknown_lang_falls_back_to_en(self):
        value = translate("dashboard.title", lang="xx", default="")
        self.assertEqual(value, "Azazel-Edge Command Dashboard")

    @unittest.skipIf(app is None, "flask app unavailable in current environment")
    def test_captive_consent_html_serves_es(self):
        client = app.test_client()
        res = client.get("/captive?lang=es")
        self.assertEqual(res.status_code, 200)
        body = res.get_data(as_text=True)
        self.assertIn("Red de Emergencia - Aviso", body)


if __name__ == "__main__":
    unittest.main()
