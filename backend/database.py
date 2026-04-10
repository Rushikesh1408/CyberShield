from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Database:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    file_path TEXT,
                    process_name TEXT,
                    metadata TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    fingerprint_match TEXT
                );

                CREATE TABLE IF NOT EXISTS fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    process_name TEXT NOT NULL,
                    file_extension TEXT NOT NULL,
                    modification_rate REAL NOT NULL,
                    access_rate REAL NOT NULL,
                    cpu_spike REAL NOT NULL,
                    signature_hash TEXT NOT NULL UNIQUE,
                    occurrences INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    files_per_second REAL NOT NULL,
                    modifications INTEGER NOT NULL,
                    accesses INTEGER NOT NULL,
                    cpu_percent REAL NOT NULL,
                    status TEXT NOT NULL
                );
                """)
            connection.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def insert_log(
        self,
        level: str,
        message: str,
        *,
        file_path: str | None = None,
        process_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        payload = json.dumps(metadata, sort_keys=True) if metadata else None
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO logs (timestamp, level, message, file_path, process_name, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (self._now(), level.upper(), message, file_path, process_name, payload),
            )
            connection.commit()

    def insert_alert(
        self,
        status: str,
        title: str,
        details: str,
        *,
        severity: str = "medium",
        fingerprint_match: str | None = None,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO alerts (timestamp, status, title, details, severity, fingerprint_match)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (self._now(), status, title, details, severity, fingerprint_match),
            )
            connection.commit()

    def upsert_fingerprint(self, fingerprint: dict[str, Any]) -> None:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT id, occurrences
                FROM fingerprints
                WHERE signature_hash = ?
                """,
                (fingerprint["signature_hash"],),
            )
            row = cursor.fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO fingerprints (
                        timestamp,
                        process_name,
                        file_extension,
                        modification_rate,
                        access_rate,
                        cpu_spike,
                        signature_hash,
                        occurrences
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        self._now(),
                        fingerprint["process_name"],
                        fingerprint["file_extension"],
                        fingerprint["modification_rate"],
                        fingerprint["access_rate"],
                        fingerprint["cpu_spike"],
                        fingerprint["signature_hash"],
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE fingerprints
                    SET occurrences = occurrences + 1,
                        timestamp = ?,
                        process_name = ?,
                        file_extension = ?,
                        modification_rate = ?,
                        access_rate = ?,
                        cpu_spike = ?
                    WHERE id = ?
                    """,
                    (
                        self._now(),
                        fingerprint["process_name"],
                        fingerprint["file_extension"],
                        fingerprint["modification_rate"],
                        fingerprint["access_rate"],
                        fingerprint["cpu_spike"],
                        row["id"],
                    ),
                )
            connection.commit()

    def insert_metrics(
        self,
        files_per_second: float,
        modifications: int,
        accesses: int,
        cpu_percent: float,
        status: str,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO metrics (timestamp, files_per_second, modifications, accesses, cpu_percent, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    self._now(),
                    files_per_second,
                    modifications,
                    accesses,
                    cpu_percent,
                    status,
                ),
            )
            connection.commit()

    def fetch_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT timestamp, level, message, file_path, process_name, metadata
                FROM logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [self._row_to_dict(row) for row in cursor.fetchall()]

    def fetch_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT timestamp, status, title, details, severity, fingerprint_match
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def fetch_fingerprints(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute("""
                SELECT timestamp, process_name, file_extension, modification_rate, access_rate,
                       cpu_spike, signature_hash, occurrences
                FROM fingerprints
                ORDER BY occurrences DESC, timestamp DESC
                """)
            return [dict(row) for row in cursor.fetchall()]

    def fetch_metrics(self, limit: int = 120) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT timestamp, files_per_second, modifications, accesses, cpu_percent, status
                FROM metrics
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in reversed(cursor.fetchall())]

    def fetch_latest_metric(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            cursor = connection.execute("""
                SELECT timestamp, files_per_second, modifications, accesses, cpu_percent, status
                FROM metrics
                ORDER BY id DESC
                LIMIT 1
                """)
            row = cursor.fetchone()
            return dict(row) if row else None

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        if data.get("metadata"):
            try:
                data["metadata"] = json.loads(data["metadata"])
            except json.JSONDecodeError:
                data["metadata"] = {"raw": data["metadata"]}
        return data


def load_database(db_path: str | Path) -> Database:
    return Database(db_path)
