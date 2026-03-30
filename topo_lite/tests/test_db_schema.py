from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from db.schema import (
    INITIAL_TABLES,
    SCHEMA_VERSION,
    connect_db,
    fetch_schema_version,
    initialize_database,
    list_tables,
)


class DatabaseSchemaTests(unittest.TestCase):
    def test_initialize_database_creates_all_initial_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database_path = Path(tmp_dir) / "topo_lite.sqlite3"
            initialize_database(database_path)
            with connect_db(database_path) as connection:
                tables = set(list_tables(connection))
                schema_version = fetch_schema_version(connection)

        self.assertTrue(set(INITIAL_TABLES).issubset(tables))
        self.assertIn("schema_metadata", tables)
        self.assertEqual(schema_version, SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()

