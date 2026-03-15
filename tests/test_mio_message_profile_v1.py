from __future__ import annotations

import unittest

import azazel_edge_web.app as webapp


class MioMessageProfileV1Tests(unittest.TestCase):
    def test_profile_normalizes_audience_and_surface(self) -> None:
        profile = webapp._build_mio_message_profile(audience="temporary", lang="ja-JP", surface="ops_comm")
        self.assertEqual(profile["audience"], "beginner")
        self.assertEqual(profile["lang"], "ja")
        self.assertEqual(profile["surface"], "ops-comm")
        self.assertEqual(profile["style"], "action_first")
        self.assertEqual(profile["max_steps"], 3)

    def test_beginner_ops_comm_message_is_capped_to_three_steps(self) -> None:
        bundle = webapp._compose_mio_message_bundle(
            {
                "answer": "SSID を確認してください。再接続を連打しないでください。状況を継続観察してください。",
                "user_message": "まず端末と SSID を確認してください。落ち着いて順番に対応します。",
                "runbook_id": "rb.user.first-contact.network-issue",
                "handoff": {"ops_comm": "/ops-comm"},
            },
            audience="temporary",
            lang="ja",
            surface="ops-comm",
        )
        message = bundle["surface_messages"]["ops-comm"]
        steps = [line for line in message.splitlines() if line.strip().startswith(("1.", "2.", "3.", "4."))]
        self.assertTrue(steps)
        self.assertLessEqual(len(steps), 3)

    def test_professional_mattermost_message_includes_rationale_and_review(self) -> None:
        bundle = webapp._compose_mio_message_bundle(
            {
                "answer": "Confirm resolver mismatch first.",
                "rationale": ["DNS mismatch is active.", "Gateway is reachable."],
                "runbook_id": "rb.noc.dns.failure.check",
                "runbook_review": {"final_status": "approved"},
                "handoff": {"ops_comm": "/ops-comm"},
            },
            audience="professional",
            lang="en",
            surface="mattermost",
        )
        message = bundle["surface_messages"]["mattermost"]
        self.assertIn("Rationale:", message)
        self.assertIn("Review:", message)
        self.assertIn("Continue:", message)


if __name__ == "__main__":
    unittest.main()
