from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PY_ROOT = ROOT / "py"

if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))
