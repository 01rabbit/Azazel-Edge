from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class TAXIIPushResult:
    ok: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    objects_pushed: int = 0
    target_url: str = ""


class TAXIIPushClient:
    def __init__(
        self,
        collection_url: str,
        token: str = "",
        verify_tls: bool = True,
        timeout_sec: int = 10,
    ) -> None:
        self.collection_url = str(collection_url or "").strip()
        self.token = str(token or "").strip()
        self.verify_tls = bool(verify_tls)
        self.timeout_sec = max(3, int(timeout_sec))

    def push_bundle(self, stix_bundle: Dict[str, Any]) -> TAXIIPushResult:
        if not self.collection_url:
            return TAXIIPushResult(ok=False, error="collection_url_not_configured")

        objects = list(stix_bundle.get("objects") or [])
        if not objects:
            return TAXIIPushResult(
                ok=True,
                objects_pushed=0,
                target_url=self.collection_url,
                error="empty_bundle_skipped",
            )

        envelope = {"objects": objects}
        payload = json.dumps(envelope, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/taxii+json;version=2.1",
            "Accept": "application/taxii+json;version=2.1",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(self.collection_url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout_sec, context=ctx) as resp:
                status = int(getattr(resp, "status", 0) or 0)
            return TAXIIPushResult(
                ok=(200 <= status < 300),
                status_code=status,
                objects_pushed=len(objects),
                target_url=self.collection_url,
            )
        except urllib.error.HTTPError as exc:
            return TAXIIPushResult(
                ok=False,
                status_code=exc.code,
                error=f"http_error:{exc.code}",
                target_url=self.collection_url,
            )
        except Exception as exc:
            return TAXIIPushResult(ok=False, error=str(exc), target_url=self.collection_url)

    def test_connection(self) -> TAXIIPushResult:
        if not self.collection_url:
            return TAXIIPushResult(ok=False, error="collection_url_not_configured")
        target = self.collection_url
        if target.endswith("/objects/"):
            target = target[:-len("/objects/")] + "/"
        headers = {"Accept": "application/taxii+json;version=2.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(target, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout_sec, context=ctx) as resp:
                status = int(getattr(resp, "status", 0) or 0)
            return TAXIIPushResult(ok=(200 <= status < 300), status_code=status, target_url=self.collection_url)
        except urllib.error.HTTPError as exc:
            return TAXIIPushResult(ok=False, status_code=exc.code, error=f"http_error:{exc.code}", target_url=self.collection_url)
        except Exception as exc:
            return TAXIIPushResult(ok=False, error=str(exc), target_url=self.collection_url)

