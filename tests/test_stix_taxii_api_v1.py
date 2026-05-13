from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class STIXTaxiiApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.tokens = root / "auth_tokens.json"
        self.tokens.write_text(
            json.dumps(
                {
                    "tokens": [
                        {"token": "viewer-token", "principal": "viewer-1", "role": "viewer"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.audit_path = root / "triage-audit.jsonl"
        self.audit_path.write_text(
            json.dumps(
                {
                    "ts": "2026-05-13T00:00:00Z",
                    "kind": "action_decision",
                    "trace_id": "trace-1",
                    "action": "notify",
                    "reason": "soc_high_but_noc_fragile",
                    "chosen_evidence_ids": ["ev-1"],
                    "level": "warning",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self._orig = {
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "AUTH_TOKENS_FILE": webapp.AUTH_TOKENS_FILE,
            "TRIAGE_AUDIT_LOG": webapp.TRIAGE_AUDIT_LOG,
            "TRIAGE_AUDIT_FALLBACK_LOG": webapp.TRIAGE_AUDIT_FALLBACK_LOG,
        }
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = self.tokens
        webapp.TRIAGE_AUDIT_LOG = self.audit_path
        webapp.TRIAGE_AUDIT_FALLBACK_LOG = self.audit_path
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.AUTH_FAIL_OPEN = self._orig["AUTH_FAIL_OPEN"]
        webapp.AUTH_TOKENS_FILE = self._orig["AUTH_TOKENS_FILE"]
        webapp.TRIAGE_AUDIT_LOG = self._orig["TRIAGE_AUDIT_LOG"]
        webapp.TRIAGE_AUDIT_FALLBACK_LOG = self._orig["TRIAGE_AUDIT_FALLBACK_LOG"]
        self.tmp.cleanup()

    def _headers(self) -> dict:
        return {"X-AZAZEL-TOKEN": "viewer-token"}

    def test_taxii_discovery_returns_api_roots(self) -> None:
        res = self.client.get("/taxii2/", headers=self._headers())
        self.assertEqual(res.status_code, 200)
        payload = res.get_json()
        self.assertIn("/taxii2/", payload.get("api_roots", []))

    def test_taxii_collections_returns_one_collection(self) -> None:
        res = self.client.get("/taxii2/collections/", headers=self._headers())
        self.assertEqual(res.status_code, 200)
        payload = res.get_json()
        cols = payload.get("collections", [])
        self.assertEqual(len(cols), 1)
        self.assertEqual(cols[0].get("id"), "azazel-edge-decisions")

    def test_taxii_objects_returns_stix_bundle_structure(self) -> None:
        res = self.client.get("/taxii2/collections/azazel-edge-decisions/objects/", headers=self._headers())
        self.assertEqual(res.status_code, 200)
        payload = res.get_json()
        self.assertIn("objects", payload)
        self.assertIn("more", payload)
        self.assertFalse(payload.get("more"))

    def test_taxii_objects_limit_param_respected(self) -> None:
        extra = [
            json.dumps(
                {
                    "ts": "2026-05-13T00:00:0{}Z".format(i),
                    "kind": "action_decision",
                    "trace_id": f"trace-{i+2}",
                    "action": "notify",
                    "reason": "soc_high_but_noc_fragile",
                    "chosen_evidence_ids": [f"ev-{i+2}"],
                    "level": "warning",
                }
            )
            for i in range(3)
        ]
        self.audit_path.write_text(self.audit_path.read_text(encoding="utf-8") + "\n".join(extra) + "\n", encoding="utf-8")
        res = self.client.get("/taxii2/collections/azazel-edge-decisions/objects/?limit=1", headers=self._headers())
        self.assertEqual(res.status_code, 200)
        payload = res.get_json()
        self.assertLessEqual(len(payload.get("objects", [])), 2)

    def test_taxii_endpoints_require_token(self) -> None:
        d = self.client.get("/taxii2/")
        c = self.client.get("/taxii2/collections/")
        o = self.client.get("/taxii2/collections/azazel-edge-decisions/objects/")
        self.assertEqual(d.status_code, 403)
        self.assertEqual(c.status_code, 403)
        self.assertEqual(o.status_code, 403)


if __name__ == "__main__":
    unittest.main()
