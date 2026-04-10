from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

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
FALLBACK_PROTECTED_FOLDER = PROJECT_ROOT / "protected_folder"


def discover_protected_directories() -> list[Path]:
    home = Path.home()
    candidates = [
        home / "Documents",
        home / "Downloads",
        home / "Desktop",
    ]
    protected = [path.resolve() for path in candidates if path.exists() and path.is_dir()]
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
            backup_manager=self.backup_manager,
            database=self.database,
            fingerprint_manager=self.fingerprint_manager,
            process_killer=self.process_killer,
        )
        self.engine.start()

    def restart(self) -> dict[str, Any]:
        if self.engine is not None:
            self.engine.stop()
        self.protected_directories = discover_protected_directories()
        self._start_engine()
        return self.snapshot()

    def stop(self) -> dict[str, Any]:
        if self.engine is not None:
            self.engine.stop()
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        if self.engine is None:
            payload: dict[str, Any] = {
                "status": "SAFE",
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
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
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

    @app.route("/api/fingerprints", methods=["GET"])
    def fingerprints() -> Any:
        return jsonify({"fingerprints": controller.database.fetch_fingerprints()})

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
        controller.database.insert_log(
            "info",
            "Manual restore requested",
            metadata={"paths": paths, "restored": restored},
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
