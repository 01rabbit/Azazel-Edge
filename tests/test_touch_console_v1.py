"""Touch console (/touch) — route, auth, API surface and secret handling.

The touch console must not widen anything: it is a static shell that calls
only endpoints that already exist, with their existing roles, and it must not
put the token or a Wi-Fi passphrase in a URL, in browser storage or in a log.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp
from azazel_edge.i18n import UI_STRINGS

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WEB = _REPO_ROOT / "azazel_edge_web"
_JS_SOURCE = (_WEB / "static" / "touch.js").read_text(encoding="utf-8")
# Code only: comments describe the rules and would match the scans below.
_JS = re.sub(r"(?m)(^|\s)//(\s.*)?$", r"\1", re.sub(r"/\*.*?\*/", "", _JS_SOURCE, flags=re.S))
_CSS = (_WEB / "static" / "touch.css").read_text(encoding="utf-8")
_HTML = (_WEB / "templates" / "touch.html").read_text(encoding="utf-8")

# Every endpoint the touch console calls, with the method it uses and what the
# existing app answers without a token. These are the existing contracts; the
# test fails if touch.js starts calling anything else.
_USED_API = {
    ("GET", "/api/dashboard/bundle"): 403,
    ("GET", "/api/state/stream"): 403,
    ("POST", "/api/mode"): 403,
    ("GET", "/api/wifi/scan"): None,  # existing: no token required (read-only scan)
    ("POST", "/api/wifi/connect"): 401,
    ("GET", "/api/runbooks/<runbook_id>"): 403,
    ("POST", "/api/runbooks/act"): 403,
}
_SVG_NS = "http://www.w3.org/2000/svg"


class TouchConsoleRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.token_path = Path(self.tmp.name) / "web_token.txt"
        self.token_path.write_text("secret-token", encoding="utf-8")
        self._orig = {
            "TOKEN_FILE": webapp.TOKEN_FILE,
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "AUTH_TOKENS_FILE": webapp.AUTH_TOKENS_FILE,
            "AUTHZ_AUDIT_LOG": webapp.AUTHZ_AUDIT_LOG,
            "send_control_command_with_params": webapp.send_control_command_with_params,
        }
        webapp.TOKEN_FILE = self.token_path
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = Path(self.tmp.name) / "no-auth-tokens.json"
        webapp.AUTHZ_AUDIT_LOG = Path(self.tmp.name) / "authz.jsonl"
        self.sent: list = []

        def fake_send(action, params):
            self.sent.append((action, dict(params or {})))
            return {"ok": True, "aps": []}

        webapp.send_control_command_with_params = fake_send  # type: ignore[assignment]
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        for name, value in self._orig.items():
            setattr(webapp, name, value)
        self.tmp.cleanup()

    def test_touch_page_is_a_static_shell(self) -> None:
        response = self.client.get("/touch")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("/static/touch.js", body)
        self.assertIn("/static/touch.css", body)
        self.assertIn("AI IS NOT DECISION AUTHORITY", body)
        # Both catalogs are embedded so the language switch needs no reload.
        match = re.search(r"catalogs:\s*(\{.*?\}),\s*\n\s*pollMs", body, re.S)
        self.assertIsNotNone(match)
        catalogs = json.loads(match.group(1))
        self.assertEqual(set(catalogs), {"ja", "en"})
        self.assertEqual(catalogs["ja"]["touch.tab_status"], UI_STRINGS["ja"]["touch.tab_status"])
        self.assertTrue(all(key.startswith("touch.") for key in catalogs["en"]))

    def test_touch_page_language_follows_existing_lang_selection(self) -> None:
        body = self.client.get("/touch?lang=ja").get_data(as_text=True)
        self.assertIn('<html lang="ja"', body)
        self.assertIn(UI_STRINGS["ja"]["touch.tab_alerts"], body)
        body = self.client.get("/touch?lang=en").get_data(as_text=True)
        self.assertIn('<html lang="en"', body)

    def test_token_in_url_is_never_echoed(self) -> None:
        body = self.client.get("/touch?token=abc123SECRET").get_data(as_text=True)
        self.assertNotIn("abc123SECRET", body)

    def test_touch_route_is_get_only_and_single(self) -> None:
        rules = [r for r in webapp.app.url_map.iter_rules() if r.endpoint == "touch_console"]
        self.assertEqual([r.rule for r in rules], ["/touch"])
        self.assertEqual(set(rules[0].methods) - {"HEAD", "OPTIONS"}, {"GET"})
        self.assertEqual(self.client.post("/touch").status_code, 405)

    def test_used_endpoints_exist_with_their_methods(self) -> None:
        by_rule: dict = {}
        for rule in webapp.app.url_map.iter_rules():
            by_rule.setdefault(rule.rule, set()).update(rule.methods)
        for method, path in _USED_API:
            self.assertIn(path, by_rule, path)
            self.assertIn(method, by_rule[path], f"{method} {path}")

    def test_used_endpoints_keep_their_existing_auth_answers(self) -> None:
        for (method, path), expected in _USED_API.items():
            if expected is None:
                continue
            url = path.replace("<runbook_id>", "rb.noc.dns.failure.check")
            response = self.client.open(url, method=method, json={} if method == "POST" else None)
            self.assertEqual(response.status_code, expected, f"{method} {path}")
            self.assertEqual(response.get_json().get("error"), "Unauthorized", f"{method} {path}")
        self.assertEqual(self.sent, [], "nothing may reach the control daemon without a token")

    def test_wifi_connect_and_mode_still_need_their_roles_with_a_viewer_token(self) -> None:
        tokens = Path(self.tmp.name) / "auth_tokens.json"
        tokens.write_text(json.dumps({"tokens": [{"token": "viewer-token", "principal": "kiosk", "role": "viewer"}]}), encoding="utf-8")
        webapp.AUTH_TOKENS_FILE = tokens
        headers = {"X-Auth-Token": "viewer-token"}
        self.assertEqual(self.client.post("/api/wifi/connect", json={"ssid": "x", "security": "OPEN"}, headers=headers).status_code, 401)
        self.assertEqual(self.client.post("/api/mode", json={"mode": "portal"}, headers=headers).status_code, 403)
        self.assertEqual(self.client.post("/api/runbooks/act", json={"runbook_id": "x"}, headers=headers).status_code, 403)
        self.assertEqual(self.sent, [])


class TouchConsoleSourceTests(unittest.TestCase):
    def test_js_calls_only_existing_endpoints(self) -> None:
        literals = set(re.findall(r"""['"](/api/[^'"?]*)""", _JS))
        allowed = {path.replace("<runbook_id>", "") for _method, path in _USED_API}
        self.assertTrue(literals, "expected the API table in touch.js")
        self.assertEqual(literals - allowed, set())
        # Only the API table names endpoints; calls go through it.
        self.assertEqual(len(re.findall(r"""['"]/api/""", _JS)), len(_USED_API))
        self.assertNotIn("/api/", _HTML)

    def test_js_methods_match_the_existing_contracts(self) -> None:
        self.assertIn("opRequest('POST', API.mode", _JS)
        self.assertIn("opRequest('POST', API.wifiConnect", _JS)
        self.assertIn("opRequest('POST', API.runbookAct", _JS)
        self.assertIn("request('GET', API.wifiScan", _JS)
        self.assertIn("request('GET', API.bundle", _JS)
        self.assertIn("request('GET', API.runbookGet", _JS)
        self.assertNotRegex(_JS, r"request\('(PUT|PATCH|DELETE)'")
        # /api/action/<x> (contain/release/shutdown/reboot...) is not used.
        self.assertNotIn("/api/action", _JS)

    def test_no_secret_in_storage_url_or_log(self) -> None:
        keys = re.findall(r"setItem\(([^,]+),", _JS)
        self.assertEqual({k.strip() for k in keys}, {"key"})  # only via writePref()
        prefs = set(re.findall(r"writePref\('([^']+)'", _JS))
        self.assertEqual(prefs, {"azazel_lang", "azazel_touch_theme"})
        for forbidden in ("sessionStorage", "document.cookie", "console.", "indexedDB", "searchParams.set(", "searchParams.append("):
            self.assertNotIn(forbidden, _JS, forbidden)
        # The token travels only in the X-Auth-Token header; ?token= is removed, not used.
        self.assertNotRegex(_JS, r"[?&]token=")
        self.assertIn("url.searchParams.delete('token')", _JS)
        self.assertIn("h['X-Auth-Token'] = token", _JS)
        # The passphrase is taken out of the buffer for the request and dropped.
        self.assertIn("passphrase: secret.take()", _JS)
        self.assertIn("body.passphrase = ''", _JS)
        # No <input>: the browser cannot autofill or offer to save the secret.
        self.assertNotIn("<input", _HTML)
        self.assertNotIn("<form", _HTML)

    def test_wifi_connect_sends_only_existing_fields(self) -> None:
        bodies = re.findall(r"\{\s*ssid: [^}]*\}", _JS)
        self.assertTrue(bodies)
        for body in bodies:
            fields = set(re.findall(r"(\w+):", body))
            self.assertLessEqual(fields, {"ssid", "security", "passphrase", "saved", "persist"}, body)

    def test_no_external_resources(self) -> None:
        for name, source in (("touch.js", _JS), ("touch.css", _CSS), ("touch.html", _HTML)):
            urls = set(re.findall(r"https?://[^\s'\"()<>]+", source))
            self.assertLessEqual(urls, {_SVG_NS}, name)
        self.assertNotIn("@import", _CSS)
        self.assertNotIn("url(", _CSS)
        self.assertNotIn("@font-face", _CSS)

    def test_touch_targets_are_at_least_48px(self) -> None:
        self.assertIn("--tap: 48px;", _CSS)
        self.assertIn("--tap-lg: 64px;", _CSS)
        for px in re.findall(r"min-height:\s*(\d+)px", _CSS):
            self.assertGreaterEqual(int(px), 32)  # chips are status, not targets
        self.assertNotIn(":hover", _CSS)

    def test_ai_is_labelled_advisory_in_both_languages(self) -> None:
        for lang in ("ja", "en"):
            self.assertIn("AI IS NOT DECISION AUTHORITY", UI_STRINGS[lang]["touch.mio_label"])
            self.assertIn("AI IS NOT DECISION AUTHORITY", UI_STRINGS[lang]["touch.about_authority"])

    def test_touch_keys_exist_in_ja_and_en(self) -> None:
        used = set(re.findall(r"""tr\(['"](touch\.[a-z0-9_]+)['"]""", _JS + _HTML))
        used |= set(re.findall(r'data-i18n="(touch\.[a-z0-9_]+)"', _HTML))
        self.assertTrue(used)
        for lang in ("ja", "en"):
            missing = sorted(k for k in used if k not in UI_STRINGS[lang])
            self.assertEqual(missing, [], lang)
        self.assertEqual(
            {k for k in UI_STRINGS["ja"] if k.startswith("touch.")},
            {k for k in UI_STRINGS["en"] if k.startswith("touch.")},
        )

    def test_touch_js_logic_suite_passes(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        result = subprocess.run(
            [node, str(_REPO_ROOT / "tests" / "touch_console_logic.test.js")],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
