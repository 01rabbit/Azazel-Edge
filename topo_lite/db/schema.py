from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path


SCHEMA_VERSION = "0.1.1"

INITIAL_TABLES = (
    "hosts",
    "services",
    "observations",
    "events",
    "edges",
    "scan_runs",
    "classifications",
    "overrides",
)

DDL_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS schema_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE,
        mac TEXT,
        vendor TEXT,
        hostname TEXT,
        status TEXT NOT NULL DEFAULT 'up',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        ignored INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        proto TEXT NOT NULL,
        port INTEGER NOT NULL,
        state TEXT NOT NULL,
        service_name TEXT,
        banner TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(host_id, proto, port),
        FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        source TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE SET NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        summary TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE SET NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS edges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_host_id INTEGER,
        dst_host_id INTEGER,
        edge_type TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        FOREIGN KEY(src_host_id) REFERENCES hosts(id) ON DELETE CASCADE,
        FOREIGN KEY(dst_host_id) REFERENCES hosts(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_kind TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS classifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL UNIQUE,
        label TEXT NOT NULL,
        confidence REAL NOT NULL,
        reason_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS overrides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        fixed_label TEXT,
        fixed_role TEXT,
        fixed_icon TEXT,
        ignored INTEGER NOT NULL DEFAULT 0,
        note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac)",
    "CREATE INDEX IF NOT EXISTS idx_services_host_id ON services(host_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_host_id ON events(host_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON scan_runs(started_at)",
    "CREATE INDEX IF NOT EXISTS idx_observations_host_id ON observations(host_id)",
    "CREATE INDEX IF NOT EXISTS idx_overrides_host_id ON overrides(host_id)",
)


def connect_db(database_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(database_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def ensure_schema(connection: sqlite3.Connection) -> None:
    for statement in DDL_STATEMENTS:
        connection.execute(statement)
    connection.execute(
        """
        INSERT INTO schema_metadata(key, value)
        VALUES('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (SCHEMA_VERSION,),
    )
    connection.commit()


def initialize_database(database_path: str | Path) -> Path:
    database = Path(database_path)
    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect_db(database)) as connection:
        ensure_schema(connection)
    return database


def list_tables(connection: sqlite3.Connection) -> tuple[str, ...]:
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()
    return tuple(row["name"] for row in rows)


def fetch_schema_version(connection: sqlite3.Connection) -> str:
    row = connection.execute(
        "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
    ).fetchone()
    return str(row["value"])
