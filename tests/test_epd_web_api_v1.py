from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class EpdWebApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.state_path = root / "epd_state.json"
        self.last_render_path = root / "epd_last_render.json"
        self._orig = {
            "EPD_STATE_PATH": webapp.EPD_STATE_PATH,
            "EPD_LAST_RENDER_PATH": webapp.EPD_LAST_RENDER_PATH,
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "load_token": webapp.load_token,
            "_epd_renderer": webapp._epd_renderer,
            "_epd_desired_render_spec": webapp._epd_desired_render_spec,
        }
        webapp.EPD_STATE_PATH = self.state_path
        webapp.EPD_LAST_RENDER_PATH = self.last_render_path
        webapp.AUTH_FAIL_OPEN = True  # focus on route behaviour, not token plumbing
        webapp.load_token = lambda: None
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        for key, value in self._orig.items():
            setattr(webapp, key, value)
        self.tmp.cleanup()

    # -- helpers -----------------------------------------------------------
    def _write_state(self, payload: dict) -> None:
        self.state_path.write_text(json.dumps(payload), encoding="utf-8")

    def _write_last_render(self, render: dict) -> None:
        self.last_render_path.write_text(
            json.dumps({"ts": "2026-07-10T00:00:00Z", "render": render}), encoding="utf-8"
        )

    # -- auth contract -----------------------------------------------------
    def test_api_epd_requires_auth(self) -> None:
        webapp.AUTH_FAIL_OPEN = False
        webapp.load_token = lambda: "secret"  # auth material present -> fail closed
        res = self.client.get("/api/epd")
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.get_json(), {"ok": False, "error": "Unauthorized"})

    def test_api_epd_preview_requires_auth(self) -> None:
        webapp.AUTH_FAIL_OPEN = False
        webapp.load_token = lambda: "secret"
        res = self.client.get("/api/epd/preview.png")
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.get_json(), {"ok": False, "error": "Unauthorized"})

    # -- /api/epd JSON shape ----------------------------------------------
    def test_api_epd_json_shape(self) -> None:
        self._write_state({"mode": "shield", "internet": "OK", "ssid": "AzazelNet"})
        self._write_last_render(
            {
                "state": "normal",
                "mode_label": "SHIELD",
                "ssid": "AzazelNet",
                "risk_status": "SAFE",
                "suspicion": 0,
            }
        )
        res = self.client.get("/api/epd")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        for key in (
            "ok",
            "mode",
            "state",
            "panel",
            "panel_source",
            "desired",
            "epd_state",
            "last_render",
            "renderer_available",
            "note",
        ):
            self.assertIn(key, data)
        self.assertTrue(data["ok"])
        self.assertEqual(data["mode"], "shield")
        self.assertEqual(data["epd_state"]["ssid"], "AzazelNet")
        self.assertEqual(data["last_render"]["state"], "normal")
        self.assertEqual(data["panel_source"], "last_render")
        self.assertEqual(data["panel"]["state"], "normal")

    def test_api_epd_falls_back_to_desired_when_no_last_render(self) -> None:
        self._write_state({"mode": "shield", "internet": "OK", "ssid": "AzazelNet"})
        res = self.client.get("/api/epd")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["panel_source"], "desired")
        self.assertEqual(data["desired"].get("state"), "normal")

    def test_api_epd_missing_files_fail_safe(self) -> None:
        res = self.client.get("/api/epd")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["epd_state"], {})
        self.assertEqual(data["last_render"], {})
        # With no state file the desired logic still yields a visible WARNING
        # frame (MODE N/A) rather than a blank panel.
        self.assertEqual(data["panel_source"], "desired")
        self.assertEqual(data["panel"]["state"], "warning")

    def test_api_epd_fallback_when_desired_logic_unavailable(self) -> None:
        webapp._epd_desired_render_spec = None
        res = self.client.get("/api/epd")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["desired"], {})
        self.assertEqual(data["panel_source"], "fallback")
        self.assertFalse(data["renderer_available"] is None)

    # -- /api/epd/preview.png ---------------------------------------------
    def _assert_png_for_last_render(self, render: dict) -> None:
        self._write_last_render(render)
        res = self.client.get("/api/epd/preview.png")
        self.assertEqual(res.status_code, 200, msg=render)
        self.assertEqual(res.mimetype, "image/png")
        self.assertTrue(res.get_data().startswith(_PNG_MAGIC))

    def test_preview_png_normal(self) -> None:
        self._assert_png_for_last_render(
            {
                "state": "normal",
                "mode_label": "SHIELD",
                "ssid": "AzazelNet",
                "risk_status": "SAFE",
                "suspicion": 0,
                "signal": -55,
                "uplink_type": "wifi",
            }
        )

    def test_preview_png_warning(self) -> None:
        self._assert_png_for_last_render({"state": "warning", "msg": "CHECK WEB"})

    def test_preview_png_danger(self) -> None:
        self._assert_png_for_last_render({"state": "danger", "msg": "REMOVE", "suspicion": 90})

    def test_preview_png_stale(self) -> None:
        self._assert_png_for_last_render({"state": "stale", "msg": "NO UPDATE"})

    def test_preview_png_503_when_renderer_unavailable(self) -> None:
        self._write_last_render({"state": "warning", "msg": "CHECK WEB"})
        webapp._epd_renderer = None
        res = self.client.get("/api/epd/preview.png")
        self.assertEqual(res.status_code, 503)
        payload = res.get_json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "epd_renderer_unavailable")
        # No stack traces leaked to the client.
        self.assertNotIn("Traceback", json.dumps(payload))

    def test_preview_png_503_when_assets_missing(self) -> None:
        self._write_last_render({"state": "warning", "msg": "CHECK WEB"})

        class _FakeRenderer:
            __file__ = str(Path(self.tmp.name) / "py" / "azazel_edge_epd.py")

        webapp._epd_renderer = _FakeRenderer()  # asset dirs resolve under empty tmp
        res = self.client.get("/api/epd/preview.png")
        self.assertEqual(res.status_code, 503)
        payload = res.get_json()
        self.assertFalse(payload["ok"])
        self.assertIn(payload["error"], {"epd_font_missing", "epd_icon_missing"})

    # -- /dev/epd ----------------------------------------------------------
    def test_dev_epd_page(self) -> None:
        res = self.client.get("/dev/epd")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.mimetype.startswith("text/html"))
        text = res.get_data(as_text=True)
        self.assertIn("/api/epd/preview.png", text)
        self.assertIn("setInterval", text)
        self.assertIn("/api/epd", text)


if __name__ == "__main__":
    unittest.main()
