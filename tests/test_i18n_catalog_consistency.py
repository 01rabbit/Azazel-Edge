import re
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = PROJECT_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.i18n import UI_STRINGS
SCAN_PATTERNS = (
    "azazel_edge_web/templates/*.html",
    "azazel_edge_web/static/*.js",
)
TR_KEY_PATTERN = re.compile(r"""tr\(['"]([a-zA-Z0-9_.-]+)['"]""")


def _collect_tr_keys() -> set[str]:
    keys: set[str] = set()
    for pattern in SCAN_PATTERNS:
        for file_path in PROJECT_ROOT.glob(pattern):
            content = file_path.read_text(encoding="utf-8")
            keys.update(TR_KEY_PATTERN.findall(content))
    return keys


class I18nCatalogConsistencyTest(unittest.TestCase):
    def test_all_tr_keys_exist_in_ja_and_en_catalogs(self):
        used_keys = _collect_tr_keys()
        ja_catalog = UI_STRINGS["ja"]
        en_catalog = UI_STRINGS["en"]
        missing_ja = sorted([key for key in used_keys if key not in ja_catalog])
        missing_en = sorted([key for key in used_keys if key not in en_catalog])
        self.assertEqual(missing_ja, [], f"Missing keys in ja catalog: {missing_ja}")
        self.assertEqual(missing_en, [], f"Missing keys in en catalog: {missing_en}")


if __name__ == "__main__":
    unittest.main()
