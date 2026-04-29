from __future__ import annotations

import json
import os
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
        self._max_log_rows = 5000
        self._log_prune_every = 50
        self._log_insert_counter = 0
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

                CREATE INDEX IF NOT EXISTS idx_logs_id_desc
                ON logs (id DESC);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    fingerprint_match TEXT,
                    resolved_at TEXT
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

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS attack_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    process_name TEXT,
                    entropy REAL NOT NULL,
                    file_rate REAL NOT NULL,
                    cpu_usage REAL NOT NULL,
                    timing_ms REAL NOT NULL,
                    confidence REAL NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_attack_signatures_timestamp_desc
                ON attack_signatures (timestamp DESC);

                CREATE TABLE IF NOT EXISTS wallet_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    incident_id TEXT,
                    wallet_type TEXT NOT NULL,
                    wallet_address TEXT NOT NULL,
                    source_file TEXT,
                    UNIQUE (wallet_address, source_file)
                );

                CREATE INDEX IF NOT EXISTS idx_wallet_indicators_timestamp_desc
                ON wallet_indicators (timestamp DESC);

                CREATE TABLE IF NOT EXISTS network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    incident_id TEXT,
                    pid INTEGER NOT NULL,
                    process_name TEXT,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    status TEXT,
                    protocol TEXT,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_network_connections_timestamp_desc
                ON network_connections (timestamp DESC);

                CREATE TABLE IF NOT EXISTS persistence_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    incident_id TEXT,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_persistence_findings_timestamp_desc
                ON persistence_findings (timestamp DESC);

                CREATE TABLE IF NOT EXISTS incident_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    signature_id TEXT,
                    report_path TEXT,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_incident_reports_timestamp_desc
                ON incident_reports (timestamp DESC);
                """)

            alert_columns = {
                str(row["name"]).lower()
                for row in connection.execute("PRAGMA table_info(alerts)")
            }
            if "resolved_at" not in alert_columns:
                connection.execute("ALTER TABLE alerts ADD COLUMN resolved_at TEXT")

            connection.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _insert_log_row(
        self,
        *,
        timestamp: str,
        level: str,
        message: str,
        file_path: str | None,
        process_name: str | None,
        metadata: dict[str, Any] | None,
    ) -> None:
        payload = json.dumps(metadata, sort_keys=True) if metadata else None
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO logs (timestamp, level, message, file_path, process_name, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (timestamp, level.upper(), message, file_path, process_name, payload),
            )

            self._log_insert_counter += 1
            if self._log_insert_counter >= self._log_prune_every:
                connection.execute(
                    """
                    DELETE FROM logs
                    WHERE id NOT IN (
                        SELECT id
                        FROM logs
                        ORDER BY id DESC
                        LIMIT ?
                    )
                    """,
                    (self._max_log_rows,),
                )
                self._log_insert_counter = 0

            connection.commit()

    def insert_log(
        self,
        level: str,
        message: str,
        *,
        file_path: str | None = None,
        process_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        metadata_payload = dict(metadata or {})
        metadata_payload.setdefault("event", message)
        metadata_payload.setdefault("event_type", level.lower())
        metadata_payload.setdefault("action", "none")
        metadata_payload.setdefault("file_path", file_path or "")
        metadata_payload.setdefault("file_name", os.path.basename(file_path) if file_path else "")
        metadata_payload.setdefault("cpu_usage", 0.0)
        metadata_payload.setdefault("file_rate", 0.0)
        metadata_payload.setdefault("timestamp", self._now())
        if process_name:
            metadata_payload.setdefault("process_name", process_name)

        self._insert_log_row(
            timestamp=metadata_payload["timestamp"],
            level=metadata_payload["event_type"],
            message=metadata_payload["event"],
            file_path=metadata_payload["file_path"] or None,
            process_name=metadata_payload.get("process_name"),
            metadata=metadata_payload,
        )

    def log_event(self, data: dict[str, Any]) -> None:
        payload = dict(data)
        payload["event"] = str(payload.get("event") or "unknown_event")
        payload["event_type"] = str(payload.get("event_type") or "info").lower()
        payload["action"] = str(payload.get("action") or "none").lower()
        payload["file_path"] = str(payload.get("file_path") or "")
        payload["file_name"] = str(payload.get("file_name") or os.path.basename(payload["file_path"]))
        payload["cpu_usage"] = float(payload.get("cpu_usage") or 0.0)
        payload["file_rate"] = float(payload.get("file_rate") or 0.0)
        payload["timestamp"] = str(payload.get("timestamp") or self._now())
        process_name = payload.get("process_name")

        self._insert_log_row(
            timestamp=payload["timestamp"],
            level=payload["event_type"],
            message=payload["event"],
            file_path=payload["file_path"] or None,
            process_name=str(process_name) if process_name else None,
            metadata=payload,
        )

    def insert_alert(
        self,
        status: str,
        title: str,
        details: str,
        *,
        severity: str = "medium",
        fingerprint_match: str | None = None,
    ) -> None:
        normalized_status = str(status or "").upper()
        resolved_at = self._now() if normalized_status == "SAFE" else None

        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO alerts (timestamp, status, title, details, severity, fingerprint_match, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (self._now(), status, title, details, severity, fingerprint_match, resolved_at),
            )
            connection.commit()

    def resolve_alerts(self, statuses: list[str] | None = None) -> int:
        with self._lock, self._connect() as connection:
            if statuses:
                normalized_statuses = [str(status).upper() for status in statuses]
                placeholders = ", ".join("?" for _ in normalized_statuses)
                cursor = connection.execute(
                    f"""
                    UPDATE alerts
                    SET resolved_at = ?
                    WHERE resolved_at IS NULL
                      AND UPPER(status) IN ({placeholders})
                    """,
                    (self._now(), *normalized_statuses),
                )
            else:
                cursor = connection.execute(
                    """
                    UPDATE alerts
                    SET resolved_at = ?
                    WHERE resolved_at IS NULL
                      AND UPPER(status) <> 'SAFE'
                    """,
                    (self._now(),),
                )

            connection.commit()
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

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

    def fetch_latest_event_timestamp(self, event_name: str) -> str | None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT timestamp
                FROM logs
                WHERE message = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (event_name,),
            )
            row = cursor.fetchone()
            return str(row["timestamp"]) if row else None

    def clear_logs(self) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute("DELETE FROM logs")
            connection.commit()
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def fetch_alerts(self, limit: int = 50, *, active_only: bool = False) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if active_only:
                cursor = connection.execute(
                    """
                    SELECT timestamp, status, title, details, severity, fingerprint_match, resolved_at
                    FROM alerts
                    WHERE resolved_at IS NULL
                      AND UPPER(status) <> 'SAFE'
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            else:
                cursor = connection.execute(
                    """
                    SELECT timestamp, status, title, details, severity, fingerprint_match, resolved_at
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

    def upsert_attack_signature(self, signature: dict[str, Any]) -> int:
        signature_id = str(signature.get("signature_id") or "").strip()
        if not signature_id:
            raise ValueError("signature_id_required")

        metadata = json.dumps(signature.get("metadata") or {}, sort_keys=True)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO attack_signatures (
                    signature_id,
                    timestamp,
                    process_name,
                    entropy,
                    file_rate,
                    cpu_usage,
                    timing_ms,
                    confidence,
                    occurrences,
                    metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(signature_id) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    process_name = excluded.process_name,
                    entropy = excluded.entropy,
                    file_rate = excluded.file_rate,
                    cpu_usage = excluded.cpu_usage,
                    timing_ms = excluded.timing_ms,
                    confidence = excluded.confidence,
                    metadata = excluded.metadata,
                    occurrences = attack_signatures.occurrences + 1
                """,
                (
                    signature_id,
                    self._now(),
                    str(signature.get("process_name") or "unknown"),
                    float(signature.get("entropy") or 0.0),
                    float(signature.get("file_rate") or 0.0),
                    float(signature.get("cpu_usage") or 0.0),
                    float(signature.get("timing_ms") or 0.0),
                    float(signature.get("confidence") or 0.0),
                    metadata,
                ),
            )
            cursor = connection.execute(
                "SELECT id FROM attack_signatures WHERE signature_id = ? LIMIT 1",
                (signature_id,),
            )
            row = cursor.fetchone()
            connection.commit()
            return int(row["id"]) if row else 0

    def fetch_attack_signatures(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT id, signature_id, timestamp, process_name, entropy, file_rate,
                       cpu_usage, timing_ms, confidence, occurrences, metadata
                FROM attack_signatures
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            rows: list[dict[str, Any]] = []
            for row in cursor.fetchall():
                item = dict(row)
                if item.get("metadata"):
                    try:
                        item["metadata"] = json.loads(str(item["metadata"]))
                    except json.JSONDecodeError:
                        item["metadata"] = {}
                rows.append(item)
            return rows

    def insert_wallet_indicators(
        self,
        wallets: list[dict[str, str]],
        *,
        incident_id: str | None = None,
    ) -> int:
        inserted = 0
        with self._lock, self._connect() as connection:
            for wallet in wallets:
                wallet_address = str(wallet.get("address") or "").strip()
                wallet_type = str(wallet.get("type") or "unknown").strip().lower()
                source_file = str(wallet.get("source_file") or "").strip()
                if not wallet_address:
                    continue
                connection.execute(
                    """
                    INSERT INTO wallet_indicators (timestamp, incident_id, wallet_type, wallet_address, source_file)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(wallet_address, source_file) DO NOTHING
                    """,
                    (
                        self._now(),
                        incident_id,
                        wallet_type,
                        wallet_address,
                        source_file,
                    ),
                )
                inserted += 1
            connection.commit()
        return inserted

    def fetch_wallet_indicators(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT timestamp, incident_id, wallet_type, wallet_address, source_file
                FROM wallet_indicators
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            return [dict(row) for row in cursor.fetchall()]

    def insert_network_events(
        self,
        events: list[dict[str, Any]],
        *,
        incident_id: str | None = None,
    ) -> int:
        inserted = 0
        with self._lock, self._connect() as connection:
            for event in events:
                metadata = json.dumps(event.get("metadata") or {}, sort_keys=True)
                connection.execute(
                    """
                    INSERT INTO network_connections (
                        timestamp,
                        incident_id,
                        pid,
                        process_name,
                        remote_ip,
                        remote_port,
                        status,
                        protocol,
                        metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._now(),
                        incident_id,
                        int(event.get("pid") or 0),
                        str(event.get("process_name") or ""),
                        str(event.get("remote_ip") or ""),
                        int(event.get("remote_port") or 0),
                        str(event.get("status") or "unknown"),
                        str(event.get("protocol") or "unknown"),
                        metadata,
                    ),
                )
                inserted += 1
            connection.commit()
        return inserted

    def fetch_network_events(self, limit: int = 250) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT timestamp, incident_id, pid, process_name, remote_ip, remote_port, status, protocol, metadata
                FROM network_connections
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            rows: list[dict[str, Any]] = []
            for row in cursor.fetchall():
                item = dict(row)
                if item.get("metadata"):
                    try:
                        item["metadata"] = json.loads(str(item["metadata"]))
                    except json.JSONDecodeError:
                        item["metadata"] = {}
                rows.append(item)
            return rows

    def insert_persistence_findings(
        self,
        findings: list[dict[str, Any]],
        *,
        incident_id: str | None = None,
    ) -> int:
        inserted = 0
        with self._lock, self._connect() as connection:
            for finding in findings:
                connection.execute(
                    """
                    INSERT INTO persistence_findings (timestamp, incident_id, finding_type, severity, details, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._now(),
                        incident_id,
                        str(finding.get("finding_type") or "unknown"),
                        str(finding.get("severity") or "medium"),
                        str(finding.get("details") or ""),
                        json.dumps(finding.get("metadata") or {}, sort_keys=True),
                    ),
                )
                inserted += 1
            connection.commit()
        return inserted

    def fetch_persistence_findings(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT timestamp, incident_id, finding_type, severity, details, metadata
                FROM persistence_findings
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            rows: list[dict[str, Any]] = []
            for row in cursor.fetchall():
                item = dict(row)
                if item.get("metadata"):
                    try:
                        item["metadata"] = json.loads(str(item["metadata"]))
                    except json.JSONDecodeError:
                        item["metadata"] = {}
                rows.append(item)
            return rows

    def upsert_incident_report(self, report: dict[str, Any]) -> None:
        incident_id = str(report.get("incident_id") or "").strip()
        if not incident_id:
            raise ValueError("incident_id_required")

        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO incident_reports (
                    incident_id,
                    timestamp,
                    status,
                    severity,
                    signature_id,
                    report_path,
                    metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    status = excluded.status,
                    severity = excluded.severity,
                    signature_id = excluded.signature_id,
                    report_path = excluded.report_path,
                    metadata = excluded.metadata
                """,
                (
                    incident_id,
                    self._now(),
                    str(report.get("status") or "UNDER_ATTACK"),
                    str(report.get("severity") or "high"),
                    str(report.get("signature_id") or ""),
                    str(report.get("report_path") or ""),
                    json.dumps(report.get("metadata") or {}, sort_keys=True),
                ),
            )
            connection.commit()

    def fetch_incident_reports(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT incident_id, timestamp, status, severity, signature_id, report_path, metadata
                FROM incident_reports
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            rows: list[dict[str, Any]] = []
            for row in cursor.fetchall():
                item = dict(row)
                if item.get("metadata"):
                    try:
                        item["metadata"] = json.loads(str(item["metadata"]))
                    except json.JSONDecodeError:
                        item["metadata"] = {}
                rows.append(item)
            return rows

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, value, self._now()),
            )
            connection.commit()

    def get_setting(self, key: str, default: str = "") -> str:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT value
                FROM settings
                WHERE key = ?
                LIMIT 1
                """,
                (key,),
            )
            row = cursor.fetchone()
            return str(row["value"]) if row else default

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        if data.get("metadata"):
            try:
                data["metadata"] = json.loads(data["metadata"])
            except json.JSONDecodeError:
                data["metadata"] = {"raw": data["metadata"]}

        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        data["event"] = metadata.get("event") or data.get("message") or "unknown_event"
        data["event_type"] = (metadata.get("event_type") or str(data.get("level") or "INFO").lower()).lower()
        file_path_value = metadata.get("file_path")
        if file_path_value in {None, ""}:
            file_path_value = data.get("file_path")
        data["file_path"] = str(file_path_value or "")

        file_name_value = metadata.get("file_name")
        if file_name_value in {None, ""}:
            file_name_value = os.path.basename(data["file_path"])
        data["file_name"] = str(file_name_value or "")
        data["cpu_usage"] = float(metadata.get("cpu_usage") or 0.0)
        data["file_rate"] = float(metadata.get("file_rate") or 0.0)
        data["action"] = str(metadata.get("action") or "none")
        data["timestamp"] = str(metadata.get("timestamp") or data.get("timestamp") or "")
        if metadata.get("process_name") and not data.get("process_name"):
            data["process_name"] = metadata["process_name"]
        return data


def load_database(db_path: str | Path) -> Database:
    return Database(db_path)
