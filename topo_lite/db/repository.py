from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .schema import connect_db, ensure_schema


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


class TopoLiteRepository:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as connection:
            ensure_schema(connection)

    def connect(self) -> sqlite3.Connection:
        return connect_db(self.database_path)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def upsert_host(
        self,
        *,
        ip: str,
        mac: str | None = None,
        vendor: str | None = None,
        hostname: str | None = None,
        status: str = "up",
        seen_at: str | None = None,
    ) -> dict[str, Any]:
        timestamp = seen_at or utc_now()
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM hosts WHERE ip = ?",
                (ip,),
            ).fetchone()
            if existing is None:
                cursor = connection.execute(
                    """
                    INSERT INTO hosts(ip, mac, vendor, hostname, status, first_seen, last_seen)
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ip, mac, vendor, hostname, status, timestamp, timestamp),
                )
                host_id = int(cursor.lastrowid)
            else:
                host_id = int(existing["id"])
                connection.execute(
                    """
                    UPDATE hosts
                    SET mac = COALESCE(?, mac),
                        vendor = COALESCE(?, vendor),
                        hostname = COALESCE(?, hostname),
                        status = ?,
                        last_seen = ?
                    WHERE id = ?
                    """,
                    (mac, vendor, hostname, status, timestamp, host_id),
                )
            row = connection.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return row_to_dict(row) or {}

    def get_host(self, host_id: int) -> dict[str, Any] | None:
        with closing(self.connect()) as connection:
            row = connection.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return row_to_dict(row)

    def list_hosts(self) -> list[dict[str, Any]]:
        with closing(self.connect()) as connection:
            rows = connection.execute("SELECT * FROM hosts ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def upsert_service(
        self,
        *,
        host_id: int,
        proto: str,
        port: int,
        state: str,
        service_name: str | None = None,
        banner: str | None = None,
        seen_at: str | None = None,
    ) -> dict[str, Any]:
        timestamp = seen_at or utc_now()
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM services WHERE host_id = ? AND proto = ? AND port = ?",
                (host_id, proto, port),
            ).fetchone()
            if existing is None:
                cursor = connection.execute(
                    """
                    INSERT INTO services(host_id, proto, port, state, service_name, banner, first_seen, last_seen)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (host_id, proto, port, state, service_name, banner, timestamp, timestamp),
                )
                service_id = int(cursor.lastrowid)
            else:
                service_id = int(existing["id"])
                connection.execute(
                    """
                    UPDATE services
                    SET state = ?,
                        service_name = COALESCE(?, service_name),
                        banner = COALESCE(?, banner),
                        last_seen = ?
                    WHERE id = ?
                    """,
                    (state, service_name, banner, timestamp, service_id),
                )
            row = connection.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
        return row_to_dict(row) or {}

    def list_services(self, host_id: int | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM services"
        params: tuple[Any, ...] = ()
        if host_id is not None:
            query += " WHERE host_id = ?"
            params = (host_id,)
        query += " ORDER BY host_id, proto, port"
        with closing(self.connect()) as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def create_event(
        self,
        *,
        event_type: str,
        summary: str,
        host_id: int | None = None,
        severity: str = "info",
        created_at: str | None = None,
    ) -> dict[str, Any]:
        timestamp = created_at or utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events(host_id, event_type, severity, summary, created_at)
                VALUES(?, ?, ?, ?, ?)
                """,
                (host_id, event_type, severity, summary, timestamp),
            )
            event_id = int(cursor.lastrowid)
            row = connection.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return row_to_dict(row) or {}

    def list_events(self) -> list[dict[str, Any]]:
        with closing(self.connect()) as connection:
            rows = connection.execute("SELECT * FROM events ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def get_latest_scan_run(
        self,
        scan_kind: str,
        *,
        statuses: tuple[str, ...] | None = None,
    ) -> dict[str, Any] | None:
        query = "SELECT * FROM scan_runs WHERE scan_kind = ?"
        params: list[Any] = [scan_kind]
        if statuses:
            placeholders = ", ".join("?" for _ in statuses)
            query += f" AND status IN ({placeholders})"
            params.extend(statuses)
        query += " ORDER BY id DESC LIMIT 1"
        with closing(self.connect()) as connection:
            row = connection.execute(query, tuple(params)).fetchone()
        return row_to_dict(row)

    def get_scan_run(self, run_id: int) -> dict[str, Any] | None:
        with closing(self.connect()) as connection:
            row = connection.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        return row_to_dict(row)

    def create_scan_run(
        self,
        *,
        scan_kind: str,
        status: str = "started",
        details: dict[str, Any] | None = None,
        started_at: str | None = None,
    ) -> dict[str, Any]:
        timestamp = started_at or utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_runs(scan_kind, status, started_at, details_json)
                VALUES(?, ?, ?, ?)
                """,
                (scan_kind, status, timestamp, json.dumps(details or {}, sort_keys=True)),
            )
            run_id = int(cursor.lastrowid)
            row = connection.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        return row_to_dict(row) or {}

    def finish_scan_run(
        self,
        run_id: int,
        *,
        status: str,
        details: dict[str, Any] | None = None,
        finished_at: str | None = None,
    ) -> dict[str, Any]:
        timestamp = finished_at or utc_now()
        with self.transaction() as connection:
            existing = connection.execute("SELECT details_json FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
            payload = details or json.loads(existing["details_json"]) if existing else {}
            connection.execute(
                """
                UPDATE scan_runs
                SET status = ?, finished_at = ?, details_json = ?
                WHERE id = ?
                """,
                (status, timestamp, json.dumps(payload, sort_keys=True), run_id),
            )
            row = connection.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        return row_to_dict(row) or {}

    def list_scan_runs(self) -> list[dict[str, Any]]:
        with closing(self.connect()) as connection:
            rows = connection.execute("SELECT * FROM scan_runs ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def record_observation(
        self,
        *,
        source: str,
        payload: dict[str, Any],
        host_id: int | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        timestamp = observed_at or utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO observations(host_id, source, observed_at, payload_json)
                VALUES(?, ?, ?, ?)
                """,
                (host_id, source, timestamp, json.dumps(payload, sort_keys=True)),
            )
            row_id = int(cursor.lastrowid)
            row = connection.execute("SELECT * FROM observations WHERE id = ?", (row_id,)).fetchone()
        return row_to_dict(row) or {}

    def list_observations(self, host_id: int | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM observations"
        params: tuple[Any, ...] = ()
        if host_id is not None:
            query += " WHERE host_id = ?"
            params = (host_id,)
        query += " ORDER BY id"
        with closing(self.connect()) as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def set_classification(
        self,
        *,
        host_id: int,
        label: str,
        confidence: float,
        reason: dict[str, Any],
        updated_at: str | None = None,
    ) -> dict[str, Any]:
        timestamp = updated_at or utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO classifications(host_id, label, confidence, reason_json, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(host_id) DO UPDATE SET
                    label = excluded.label,
                    confidence = excluded.confidence,
                    reason_json = excluded.reason_json,
                    updated_at = excluded.updated_at
                """,
                (host_id, label, confidence, json.dumps(reason, sort_keys=True), timestamp),
            )
            row = connection.execute(
                "SELECT * FROM classifications WHERE host_id = ?",
                (host_id,),
            ).fetchone()
        return row_to_dict(row) or {}

    def list_classifications(self) -> list[dict[str, Any]]:
        with closing(self.connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM classifications ORDER BY host_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def cleanup_history(
        self,
        *,
        observations_before: str | None = None,
        events_before: str | None = None,
        scan_runs_before: str | None = None,
    ) -> dict[str, int]:
        deleted = {"observations": 0, "events": 0, "scan_runs": 0}
        with self.transaction() as connection:
            if observations_before is not None:
                cursor = connection.execute(
                    "DELETE FROM observations WHERE observed_at < ?",
                    (observations_before,),
                )
                deleted["observations"] = cursor.rowcount
            if events_before is not None:
                cursor = connection.execute(
                    "DELETE FROM events WHERE created_at < ?",
                    (events_before,),
                )
                deleted["events"] = cursor.rowcount
            if scan_runs_before is not None:
                cursor = connection.execute(
                    "DELETE FROM scan_runs WHERE started_at < ?",
                    (scan_runs_before,),
                )
                deleted["scan_runs"] = cursor.rowcount
        return deleted
