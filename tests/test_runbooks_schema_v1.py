from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml


RUNBOOK_ROOT = Path(__file__).resolve().parents[1] / "runbooks"
RUNBOOK_ID_RE = re.compile(r"^rb\.[a-z0-9_]+\.[a-z0-9_.-]+$")
ALLOWED_AUDIENCE = {"operator", "beginner", "both"}
ALLOWED_EFFECT = {"read_only", "operator_guidance", "controlled_exec"}


class RunbooksSchemaV1Tests(unittest.TestCase):
    def test_all_runbook_yaml_files_exist(self) -> None:
        files = sorted(RUNBOOK_ROOT.glob("*/*.yaml"))
        self.assertGreater(len(files), 0, "No runbook YAML files found under runbooks/*/*.yaml")

    def test_all_runbooks_follow_minimum_contract(self) -> None:
        files = sorted(RUNBOOK_ROOT.glob("*/*.yaml"))
        for path in files:
            with self.subTest(path=str(path)):
                payload = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertIsInstance(payload, dict)

                runbook_id = payload.get("id")
                self.assertIsInstance(runbook_id, str)
                self.assertRegex(runbook_id, RUNBOOK_ID_RE)

                title = payload.get("title")
                self.assertIsInstance(title, str)
                self.assertTrue(title.strip())

                audience = payload.get("audience")
                self.assertIn(audience, ALLOWED_AUDIENCE)

                effect = payload.get("effect")
                self.assertIn(effect, ALLOWED_EFFECT)

                requires_approval = payload.get("requires_approval")
                self.assertIsInstance(requires_approval, bool)

                args_schema = payload.get("args_schema")
                self.assertIsInstance(args_schema, dict)
                self.assertEqual(args_schema.get("type"), "object")
                required = args_schema.get("required", [])
                self.assertIsInstance(required, list)

                steps = payload.get("steps")
                self.assertIsInstance(steps, list)
                self.assertGreater(len(steps), 0)
                for step in steps:
                    self.assertIsInstance(step, str)
                    self.assertTrue(step.strip())

                msg = payload.get("user_message_template")
                self.assertIsInstance(msg, str)
                self.assertTrue(msg.strip())

    def test_controlled_exec_always_requires_approval(self) -> None:
        files = sorted(RUNBOOK_ROOT.glob("*/*.yaml"))
        for path in files:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            if payload.get("effect") != "controlled_exec":
                continue
            with self.subTest(path=str(path)):
                self.assertTrue(payload.get("requires_approval"), "controlled_exec must require approval")


if __name__ == "__main__":
    unittest.main()
