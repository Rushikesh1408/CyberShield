from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))
    from backend.backup import BackupManager
    from backend.database import Database
    from backend.detection import DetectionEngine
    from backend.fingerprint import FingerprintManager
    from backend.process_killer import ProcessKiller
else:
    from .backup import BackupManager
    from .database import Database
    from .detection import DetectionEngine
    from .fingerprint import FingerprintManager
    from .process_killer import ProcessKiller

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKUP_ROOT = PROJECT_ROOT / "backup"
DATA_ROOT = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_ROOT / "cybershield.db"
ATTACK_REPORT_PATH = DATA_ROOT / "attack_report.txt"
FALLBACK_PROTECTED_FOLDER = PROJECT_ROOT / "protected_folder"


def _existing_directories(candidates: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if not resolved.exists() or not resolved.is_dir():
            continue
        key = str(resolved).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(resolved)
    return unique


def _normalize_contact_value(value: str) -> str:
    return " ".join(value.strip().split())


def discover_protected_directories() -> list[Path]:
    home = Path.home()
    candidates = [
        home / "Documents",
        home / "Downloads",
        home / "Desktop",
    ]
    protected = _existing_directories(candidates)
    if protected:
        return protected

    FALLBACK_PROTECTED_FOLDER.mkdir(parents=True, exist_ok=True)
    return [FALLBACK_PROTECTED_FOLDER.resolve()]


class SystemController:
    def __init__(self) -> None:
        self.database = Database(DATABASE_PATH)
        self.protected_directories = discover_protected_directories()
        self.backup_manager: BackupManager | None = None
        self.fingerprint_manager: FingerprintManager | None = None
        self.process_killer: ProcessKiller | None = None
        self.engine: DetectionEngine | None = None
        self._start_engine()

    def _start_engine(self) -> None:
        self.backup_manager = BackupManager(self.protected_directories, BACKUP_ROOT)
        self.fingerprint_manager = FingerprintManager(self.database)
        self.process_killer = ProcessKiller(allowlist={"python.exe", "python", "code.exe", "explorer.exe"})
        self.engine = DetectionEngine(
            monitored_paths=self.protected_directories,
            report_file_path=ATTACK_REPORT_PATH,
            backup_manager=self.backup_manager,
            database=self.database,
            fingerprint_manager=self.fingerprint_manager,
            process_killer=self.process_killer,
        )
        self.engine.start()

    def restart(self) -> dict[str, Any]:
        if self.engine is not None and self.engine.is_monitoring:
            return self.snapshot()

        self.protected_directories = discover_protected_directories()
        self._start_engine()
        return self.snapshot()

    def stop(self) -> dict[str, Any]:
        if self.engine is not None and self.engine.is_monitoring:
            self.engine.stop()
        return self.snapshot()

    def backup_status(self) -> dict[str, Any]:
        if self.backup_manager is None:
            return {
                "status": "Inactive",
                "files_secured": 0,
                "backup_versions": 0,
                "last_backup_time": None,
                "recent_files": [],
                "backup_root": str(BACKUP_ROOT),
            }

        status = self.backup_manager.backup_status()
        # Backup service availability is independent of monitor start/stop toggle.
        status["status"] = "Active"

        if not status.get("last_backup_time"):
            status["last_backup_time"] = self.database.fetch_latest_event_timestamp("backup_snapshot_created")

        return status

    def run_backup(self) -> dict[str, Any]:
        if self.backup_manager is None:
            return {"message": "backup_unavailable", "created": 0, "backup_status": self.backup_status()}

        results = self.backup_manager.snapshot_folder()
        latest_metric = self.database.fetch_latest_metric() or {}
        self.database.log_event(
            {
                "event": "backup_snapshot_created",
                "event_type": "info",
                "action": "none",
                "file_name": "",
                "file_path": "",
                "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                "file_rate": float(latest_metric.get("files_per_second") or 0.0),
                "created_files": len(results),
            }
        )
        return {
            "message": "backup_completed",
            "created": len(results),
            "backup_status": self.backup_status(),
        }

    def recover_file(self, file_path: str) -> Path | None:
        if self.backup_manager is None:
            return None

        restored = self.backup_manager.restore_file(file_path)
        latest_metric = self.database.fetch_latest_metric() or {}
        event_type = "info" if restored is not None else "warning"
        event_name = "file_restored" if restored is not None else "restore_failed"
        action = "restored" if restored is not None else "none"
        self.database.log_event(
            {
                "event": event_name,
                "event_type": event_type,
                "action": action,
                "file_name": Path(file_path).name,
                "file_path": file_path,
                "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                "file_rate": float(latest_metric.get("files_per_second") or 0.0),
            }
        )
        return restored

    def set_emergency_contact(self, phone: str) -> str:
        normalized_phone = _normalize_contact_value(phone)
        self.database.set_setting("emergency_contact", normalized_phone)

        latest_metric = self.database.fetch_latest_metric() or {}
        self.database.log_event(
            {
                "event": "emergency_contact_saved",
                "event_type": "info",
                "action": "none",
                "file_name": "",
                "file_path": "",
                "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                "file_rate": float(latest_metric.get("files_per_second") or 0.0),
                "phone": normalized_phone,
            }
        )
        return normalized_phone

    def get_emergency_contact(self) -> str:
        return self.database.get_setting("emergency_contact", "")

    @staticmethod
    def get_attack_report_path() -> Path:
        return ATTACK_REPORT_PATH

    def snapshot(self) -> dict[str, Any]:
        if self.engine is None:
            payload: dict[str, Any] = {
                "status": "SAFE",
                "is_monitoring": False,
                "metrics": {
                    "files_per_second": 0.0,
                    "modifications": 0,
                    "accesses": 0,
                    "cpu_percent": 0.0,
                    "status": "SAFE",
                },
                "alerts": [],
                "logs": [],
                "fingerprints": [],
                "monitored_paths": [str(path) for path in self.protected_directories],
            }
        else:
            payload = self.engine.snapshot()
        payload["monitor_paths"] = [str(path) for path in self.protected_directories]
        payload["monitoring_message"] = "Monitoring: Protected System Directories (Auto-configured)"
        payload["backup_root"] = str(BACKUP_ROOT)
        payload["database_path"] = str(DATABASE_PATH)
        return payload


controller = SystemController()


def create_app() -> Flask:
    app = Flask(__name__)

    @app.after_request
    def add_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, x-api-key"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    @app.route("/api/health", methods=["GET"])
    def health() -> Any:
        snapshot = controller.snapshot()
        return jsonify({"ok": True, "status": snapshot["status"]})

    @app.route("/api/status", methods=["GET"])
    def status() -> Any:
        data = controller.snapshot()
        return jsonify(
            {
                "status": data["status"],
                "is_monitoring": data.get("is_monitoring", False),
                "monitor_paths": data["monitor_paths"],
                "monitoring_message": data["monitoring_message"],
                "backup_root": data["backup_root"],
                "metrics": data["metrics"],
            }
        )

    @app.route("/api/metrics", methods=["GET"])
    def metrics() -> Any:
        data = controller.snapshot()
        return jsonify(
            {
                "metrics": data["metrics"],
                "history": controller.database.fetch_metrics(120),
            }
        )

    @app.route("/api/alerts", methods=["GET"])
    def alerts() -> Any:
        return jsonify({"alerts": controller.database.fetch_alerts(50)})

    @app.route("/api/logs", methods=["GET"])
    def logs() -> Any:
        return jsonify({"logs": controller.database.fetch_logs(100)})

    @app.route("/api/logs/clear", methods=["POST"])
    def clear_logs() -> Any:
        deleted = controller.database.clear_logs()
        return jsonify({"message": "logs_cleared", "deleted": deleted})

    @app.route("/api/fingerprints", methods=["GET"])
    def fingerprints() -> Any:
        return jsonify({"fingerprints": controller.database.fetch_fingerprints()})

    @app.route("/api/backup/status", methods=["GET"])
    def backup_status() -> Any:
        return jsonify(controller.backup_status())

    @app.route("/api/backup/run", methods=["POST"])
    def run_backup() -> Any:
        return jsonify(controller.run_backup())

    @app.route("/api/backup/recover", methods=["POST"])
    def backup_recover() -> Any:
        body = request.get_json(silent=True) or {}
        file_path = str(body.get("file_path") or "").strip()
        if not file_path:
            return jsonify({"message": "file_path_required"}), 400

        restored = controller.recover_file(file_path)
        if restored is None:
            return jsonify({"message": "backup_not_found", "file_path": file_path}), 404

        return jsonify(
            {
                "message": "restored",
                "file_path": file_path,
                "restored_path": str(restored),
                "backup_status": controller.backup_status(),
            }
        )

    @app.route("/api/backup/restore", methods=["POST"])
    def backup_restore() -> Any:
        return backup_recover()

    @app.route("/api/emergency/contact", methods=["GET"])
    def get_emergency_contact() -> Any:
        return jsonify({"contact": controller.get_emergency_contact()})

    @app.route("/api/emergency/contact", methods=["POST"])
    def save_emergency_contact() -> Any:
        body = request.get_json(silent=True) or {}
        phone = str(body.get("phone") or body.get("contact") or "").strip()
        if not phone:
            return jsonify({"message": "phone_required"}), 400

        saved_phone = controller.set_emergency_contact(phone)
        return jsonify({"message": "contact_saved", "contact": saved_phone})

    @app.route("/api/settings/contact", methods=["GET"])
    def get_settings_contact() -> Any:
        return get_emergency_contact()

    @app.route("/api/settings/contact", methods=["POST"])
    def save_settings_contact() -> Any:
        return save_emergency_contact()

    @app.route("/api/report", methods=["GET"])
    def get_report() -> Any:
        report_path = controller.get_attack_report_path()
        if not report_path.exists():
            return jsonify({"message": "report_not_found"}), 404

        return send_file(
            report_path,
            as_attachment=False,
            mimetype="text/plain",
        )

    @app.route("/api/report/download", methods=["GET"])
    def download_report() -> Any:
        report_path = controller.get_attack_report_path()
        if not report_path.exists():
            return jsonify({"message": "report_not_found"}), 404

        return send_file(
            report_path,
            as_attachment=True,
            download_name="attack_report.txt",
            mimetype="text/plain",
        )

    @app.route("/api/start", methods=["POST"])
    def start_monitoring() -> Any:
        snapshot = controller.restart()
        return jsonify({"message": "monitoring_started", "snapshot": snapshot})

    @app.route("/api/stop", methods=["POST"])
    def stop_monitoring() -> Any:
        snapshot = controller.stop()
        return jsonify({"message": "monitoring_stopped", "snapshot": snapshot})

    @app.route("/api/restore", methods=["POST"])
    def restore_now() -> Any:
        body = request.get_json(silent=True) or {}
        paths = body.get("paths") or []
        if controller.backup_manager is None:
            return jsonify({"message": "restore_unavailable", "restored": []}), 503

        restored = controller.backup_manager.restore_many(paths)
        latest_metric = controller.database.fetch_latest_metric() or {}
        controller.database.log_event(
            {
                "event": "manual_restore_requested",
                "event_type": "info",
                "action": "restored",
                "file_name": "",
                "file_path": "",
                "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                "file_rate": float(latest_metric.get("files_per_second") or 0.0),
                "paths": paths,
                "restored": restored,
            }
        )
        return jsonify({"message": "restored", "restored": restored})

    @app.route("/api/config", methods=["GET"])
    def config() -> Any:
        return jsonify(
            {
                "monitor_paths": [str(path) for path in controller.protected_directories],
                "monitoring_message": "Monitoring: Protected System Directories (Auto-configured)",
                "backup_root": str(BACKUP_ROOT),
                "database_path": str(DATABASE_PATH),
            }
        )

    @app.route("/api/ping", methods=["GET"])
    def ping() -> Any:
        return jsonify({"message": "CyberShield AI is running"})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
        use_reloader=False,
    )
