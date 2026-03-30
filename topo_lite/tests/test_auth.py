from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from auth import bootstrap_local_auth, hash_api_token, hash_password, verify_password
from configuration import default_config
from db.repository import TopoLiteRepository


class AuthTests(unittest.TestCase):
    def test_password_hash_round_trip(self) -> None:
        encoded = hash_password("secret-pass")
        self.assertTrue(verify_password("secret-pass", encoded))
        self.assertFalse(verify_password("wrong-pass", encoded))

    def test_bootstrap_local_auth_creates_admin_and_readonly_users(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repository = TopoLiteRepository(Path(tmp_dir) / "auth.sqlite3")
            config = default_config()
            bootstrap_local_auth(repository, config.auth)

            admin = repository.get_user_by_username(config.auth.admin_username)
            readonly = repository.get_user_by_username(config.auth.readonly_username)

            self.assertEqual(admin["role"], "admin")
            self.assertEqual(readonly["role"], "read-only")
            self.assertEqual(
                repository.get_user_by_token_hash(hash_api_token(config.auth.admin_api_token))["id"],
                admin["id"],
            )


if __name__ == "__main__":
    unittest.main()
