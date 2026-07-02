from __future__ import annotations

import unittest

from azazel_edge_web import app as webapp


class MattermostPingCacheV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_uncached = webapp._mattermost_ping_uncached
        self._orig_cache = dict(webapp._MATTERMOST_PING_CACHE)
        self._orig_ttl = webapp.MATTERMOST_PING_CACHE_TTL_SEC
        # Force a cold cache for each test.
        webapp._MATTERMOST_PING_CACHE["ts"] = 0.0
        webapp._MATTERMOST_PING_CACHE["value"] = (False, {"error": "not_checked"})

    def tearDown(self) -> None:
        webapp._mattermost_ping_uncached = self._orig_uncached
        webapp._MATTERMOST_PING_CACHE.clear()
        webapp._MATTERMOST_PING_CACHE.update(self._orig_cache)
        webapp.MATTERMOST_PING_CACHE_TTL_SEC = self._orig_ttl

    def _install_counter(self, value):
        self.calls = 0

        def fake():
            self.calls += 1
            return value

        webapp._mattermost_ping_uncached = fake

    def test_ping_result_is_cached_within_ttl(self) -> None:
        webapp.MATTERMOST_PING_CACHE_TTL_SEC = 300
        self._install_counter((True, {"status": "OK"}))
        first = webapp._mattermost_ping()
        for _ in range(9):
            webapp._mattermost_ping()
        self.assertEqual(first, (True, {"status": "OK"}))
        self.assertEqual(self.calls, 1, "reachability ping must hit the network only once within the TTL")

    def test_force_refresh_bypasses_cache(self) -> None:
        webapp.MATTERMOST_PING_CACHE_TTL_SEC = 300
        self._install_counter((True, {"status": "OK"}))
        webapp._mattermost_ping()
        webapp._mattermost_ping(force=True)
        self.assertEqual(self.calls, 2, "force=True must re-probe even inside the TTL")

    def test_expired_cache_triggers_refresh(self) -> None:
        webapp.MATTERMOST_PING_CACHE_TTL_SEC = 0  # everything is immediately stale
        self._install_counter((False, {"error": "unreachable"}))
        webapp._mattermost_ping()
        webapp._mattermost_ping()
        self.assertEqual(self.calls, 2, "an expired cache must re-probe on the next call")


if __name__ == "__main__":
    unittest.main()
