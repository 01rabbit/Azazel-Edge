from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = PROJECT_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.runbooks import _validate_runbook_doc


RUNBOOK_ROOT = PROJECT_ROOT / "runbooks"
PLACEHOLDER_RE = re.compile(r"\$\{([a-zA-Z0-9_]+)\}")


class RunbooksSchemaQualityGateV1Tests(unittest.TestCase):
    def _all_runbooks(self) -> list[tuple[Path, dict[str, Any]]]:
        rows: list[tuple[Path, dict[str, Any]]] = []
        for path in sorted(RUNBOOK_ROOT.glob("*/*.yaml")):
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertIsInstance(payload, dict, f"Runbook payload must be a map: {path}")
            rows.append((path, payload))
        self.assertGreater(len(rows), 0, "No runbooks found under runbooks/*/*.yaml")
        return rows

    def test_runbook_ids_are_unique(self) -> None:
        seen: dict[str, Path] = {}
        for path, payload in self._all_runbooks():
            runbook_id = str(payload.get("id") or "")
            self.assertTrue(runbook_id, f"runbook id is empty: {path}")
            self.assertNotIn(runbook_id, seen, f"duplicate runbook id: {runbook_id}")
            seen[runbook_id] = path

    def test_args_schema_required_keys_are_declared(self) -> None:
        for path, payload in self._all_runbooks():
            with self.subTest(path=str(path)):
                args_schema = payload.get("args_schema") if isinstance(payload, dict) else {}
                self.assertIsInstance(args_schema, dict)
                props = args_schema.get("properties") if isinstance(args_schema, dict) else {}
                required = args_schema.get("required") if isinstance(args_schema, dict) else []
                self.assertIsInstance(props, dict)
                self.assertIsInstance(required, list)
                for key in required:
                    self.assertIsInstance(key, str)
                    self.assertIn(key, props, f"required key not declared in properties: {key}")

    def test_command_placeholders_exist_in_args_schema(self) -> None:
        for path, payload in self._all_runbooks():
            with self.subTest(path=str(path)):
                args_schema = payload.get("args_schema") if isinstance(payload, dict) else {}
                props = args_schema.get("properties") if isinstance(args_schema, dict) else {}
                self.assertIsInstance(props, dict)
                keys = set(props.keys())
                command = payload.get("command")
                if not isinstance(command, dict):
                    continue
                fragments = [str(command.get("exec") or "")]
                argv = command.get("argv")
                if isinstance(argv, list):
                    fragments.extend(str(item) for item in argv)
                for fragment in fragments:
                    for placeholder in PLACEHOLDER_RE.findall(fragment):
                        self.assertIn(
                            placeholder,
                            keys,
                            f"placeholder '{placeholder}' is not defined in args_schema.properties",
                        )

    def test_controlled_exec_requires_approval(self) -> None:
        for path, payload in self._all_runbooks():
            if payload.get("effect") != "controlled_exec":
                continue
            with self.subTest(path=str(path)):
                self.assertTrue(payload.get("requires_approval"))

    def test_runtime_validator_accepts_all_runbooks(self) -> None:
        for path, payload in self._all_runbooks():
            with self.subTest(path=str(path)):
                doc = dict(payload)
                doc["_path"] = str(path)
                validated = _validate_runbook_doc(doc)
                self.assertEqual(str(validated.get("id") or ""), str(payload.get("id") or ""))


if __name__ == "__main__":
    unittest.main()
