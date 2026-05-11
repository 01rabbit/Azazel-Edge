from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Dict, Optional

from .types import TriageSession


TRIAGE_SESSION_DIR = Path(os.environ.get("AZAZEL_TRIAGE_SESSION_DIR", "/run/azazel-edge/triage-sessions"))
TRIAGE_SESSION_FALLBACK_DIR = Path(os.environ.get("AZAZEL_TRIAGE_SESSION_FALLBACK_DIR", "/tmp/azazel-edge/triage-sessions"))


class TriageSessionStore:
    def __init__(self, base_dir: str | Path | None = None):
        preferred_dir = Path(base_dir) if base_dir else TRIAGE_SESSION_DIR
        try:
            preferred_dir.mkdir(parents=True, exist_ok=True)
            self.base_dir = preferred_dir
        except OSError:
            TRIAGE_SESSION_FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
            self.base_dir = TRIAGE_SESSION_FALLBACK_DIR

    def _path_for(self, session_id: str) -> Path:
        return self.base_dir / f"{session_id}.json"

    def create(self, audience: str = "temporary", lang: str = "ja", selected_intent: str = "", current_state: str = "") -> TriageSession:
        now = int(time.time())
        session = TriageSession(
            session_id=uuid.uuid4().hex,
            audience=audience or "temporary",
            lang=lang or "ja",
            selected_intent=selected_intent,
            current_state=current_state,
            created_at=now,
            updated_at=now,
        )
        self.save(session)
        return session

    def save(self, session: TriageSession) -> TriageSession:
        session.updated_at = int(time.time())
        if not session.created_at:
            session.created_at = session.updated_at
        path = self._path_for(session.session_id)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(session.to_dict(), fh, ensure_ascii=False, indent=2, sort_keys=True)
        return session

    def get(self, session_id: str) -> Optional[TriageSession]:
        path = self._path_for(session_id)
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as fh:
            payload: Dict[str, object] = json.load(fh)
        return TriageSession.from_dict(payload)

    def delete(self, session_id: str) -> bool:
        path = self._path_for(session_id)
        if not path.exists():
            return False
        path.unlink()
        return True
