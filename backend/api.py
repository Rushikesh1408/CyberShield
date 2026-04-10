from __future__ import annotations

import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from backend.config import AppConfig
    from backend.core import CyberShieldPipeline
    from backend.database import Database
else:
    from .config import AppConfig
    from .core import CyberShieldPipeline
    from .database import Database

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
        self.pipeline: CyberShieldPipeline | None = None
        self._pipeline_thread: threading.Thread | None = None
        self._pipeline_stop_event = threading.Event()
        self._attack_active = False
        self._warning_active = False
        self._start_engine()

    def _start_engine(self) -> None:
        self.pipeline = CyberShieldPipeline(
            watch_paths=self.protected_directories,
            backup_root=BACKUP_ROOT,
            network_mode="safe",
        )
        self.pipeline.start()
        self._pipeline_stop_event.clear()
        self._pipeline_thread = threading.Thread(
            target=self._pipeline_loop,
            name="cybershield-pipeline-loop",
            daemon=True,
        )
        self._pipeline_thread.start()
        self.database.log_event(
            {
                "event": "monitoring_started",
                "event_type": "info",
                "action": "none",
                "file_name": "",
                "file_path": "",
                "cpu_usage": 0.0,
                "file_rate": 0.0,
                "paths": [str(path) for path in self.protected_directories],
            }
        )

    def _pipeline_loop(self) -> None:
        while not self._pipeline_stop_event.wait(1.0):
            if self.pipeline is None:
                continue

            try:
                assessment = self.pipeline.run_cycle()
                self._record_pipeline_cycle(assessment)
            except (RuntimeError, ValueError, OSError) as error:
                self.database.insert_log(
                    "error",
                    "pipeline_cycle_failed",
                    metadata={"error": str(error)},
                )

    def _record_pipeline_cycle(self, assessment: dict[str, Any]) -> None:
        metrics = assessment.get("metrics") if isinstance(assessment.get("metrics"), dict) else {}
        score = self._to_int(assessment.get("score"))
        level = str(assessment.get("level") or "LOW")
        triggered = bool(assessment.get("triggered"))
        trigger_threshold = max(1, self._to_int(assessment.get("trigger_threshold") or 70))
        warning_threshold = max(40, trigger_threshold - 20)

        files_per_second = float(metrics.get("file_activity_rate") or 0.0)
        activity_count = self._to_int(metrics.get("file_activity_count"))
        cpu_usage = float(metrics.get("cpu_usage") or 0.0)
        dna_mismatch_count = self._to_int(metrics.get("dna_mismatch_count"))

        status = "UNDER_ATTACK" if triggered else "SAFE"
        self.database.insert_metrics(
            files_per_second,
            activity_count,
            activity_count,
            cpu_usage,
            status,
        )

        if triggered:
            if not self._attack_active:
                self._attack_active = True
                self._warning_active = False
                self.database.insert_alert(
                    "UNDER_ATTACK",
                    "Behavioral attack pattern confirmed",
                    "Pipeline threat score crossed attack threshold.",
                    severity="critical",
                )
                self.database.log_event(
                    {
                        "event": "attack_detected",
                        "event_type": "critical",
                        "action": "flagged",
                        "file_name": "",
                        "file_path": "",
                        "cpu_usage": cpu_usage,
                        "file_rate": files_per_second,
                        "score": score,
                        "level": level,
                        "modifications": activity_count,
                        "accesses": activity_count,
                        "dna_mismatch_count": dna_mismatch_count,
                    }
                )

                actions = assessment.get("actions") if isinstance(assessment.get("actions"), list) else []
                for action_entry in actions:
                    if not isinstance(action_entry, dict):
                        continue
                    if str(action_entry.get("type") or "") != "network_isolation":
                        continue

                    result = action_entry.get("result") if isinstance(action_entry.get("result"), dict) else {}
                    isolated = bool(result.get("isolated"))
                    mode = str(result.get("mode") or "safe")
                    simulated = bool(result.get("simulated"))
                    self.database.log_event(
                        {
                            "event": "active_threat_neutralization",
                            "event_type": "critical",
                            "action": "isolated" if isolated else "attempted",
                            "file_name": "",
                            "file_path": "",
                            "cpu_usage": cpu_usage,
                            "file_rate": files_per_second,
                            "mode": mode,
                            "isolated": isolated,
                            "simulated": simulated,
                        }
                    )
                    self.database.insert_alert(
                        "UNDER_ATTACK",
                        "Active Threat Neutralization",
                        (
                            f"Network isolation {'executed' if isolated else 'attempted'} "
                            f"in {mode} mode."
                        ),
                        severity="high",
                    )
                    break

                self._write_attack_report(
                    score=score,
                    level=level,
                    files_affected=activity_count,
                    files_recovered=0,
                    cpu_usage=cpu_usage,
                    file_rate=files_per_second,
                )
            return

        if self._attack_active:
            self._attack_active = False
            self.database.insert_alert(
                "SAFE",
                "System Safe",
                "Pipeline threat score returned to safe range.",
                severity="medium",
            )
            self.database.log_event(
                {
                    "event": "system_safe",
                    "event_type": "info",
                    "action": "restored",
                    "file_name": "",
                    "file_path": "",
                    "cpu_usage": cpu_usage,
                    "file_rate": files_per_second,
                    "score": score,
                    "level": level,
                }
            )

        if score >= warning_threshold:
            if not self._warning_active:
                self._warning_active = True
                self.database.insert_alert(
                    "UNDER_ATTACK",
                    "Early Threat Detection",
                    (
                        "Threshold-based early warning using behavioral anomalies "
                        "such as CPU spikes and high file access rate."
                    ),
                    severity="medium",
                )
                self.database.log_event(
                    {
                        "event": "early_threat_detection",
                        "event_type": "warning",
                        "action": "flagged",
                        "file_name": "",
                        "file_path": "",
                        "cpu_usage": cpu_usage,
                        "file_rate": files_per_second,
                        "score": score,
                        "level": level,
                        "dna_mismatch_count": dna_mismatch_count,
                    }
                )
        else:
            self._warning_active = False

    def _write_attack_report(
        self,
        *,
        score: int,
        level: str,
        files_affected: int,
        files_recovered: int,
        cpu_usage: float,
        file_rate: float,
    ) -> None:
        report_timestamp = datetime.now(timezone.utc).isoformat()
        report_body = (
            "--- CyberShield Attack Report ---\n\n"
            f"Time: {report_timestamp}\n"
            f"Threat Confidence: {score}%\n"
            f"Threat Level: {level}\n"
            f"CPU Usage: {round(cpu_usage, 2)}%\n"
            f"File Activity Rate: {round(file_rate, 2)} /s\n"
            f"Files Affected: {files_affected}\n"
            f"Files Recovered: {files_recovered}\n\n"
            "Actions Taken:\n"
            "Active Threat Neutralization attempted\n"
            "Automatic System Recovery ready\n\n"
            "Status:\n"
            "System secured and monitoring continues.\n"
        )

        try:
            ATTACK_REPORT_PATH.write_text(report_body, encoding="utf-8")
        except OSError as error:
            self.database.insert_log(
                "warning",
                "attack_report_write_failed",
                metadata={"error": str(error)},
            )
            return

        self.database.log_event(
            {
                "event": "attack_report_generated",
                "event_type": "info",
                "action": "none",
                "file_name": ATTACK_REPORT_PATH.name,
                "file_path": str(ATTACK_REPORT_PATH),
                "cpu_usage": cpu_usage,
                "file_rate": file_rate,
                "files_affected": files_affected,
                "files_recovered": files_recovered,
                "threat_confidence": score,
                "threat_level": level,
                "timestamp": report_timestamp,
            }
        )

    def restart(self) -> dict[str, Any]:
        if self.pipeline is not None and self.pipeline.monitor.is_running:
            return self.snapshot()

        self.protected_directories = discover_protected_directories()
        self._pipeline_stop_event.set()
        if self._pipeline_thread is not None and self._pipeline_thread.is_alive():
            self._pipeline_thread.join(timeout=3)
        self._pipeline_thread = None
        self.pipeline = None
        self._attack_active = False
        self._warning_active = False

        self._start_engine()
        return self.snapshot()

    def stop(self) -> dict[str, Any]:
        if self.pipeline is not None and self.pipeline.monitor.is_running:
            self._pipeline_stop_event.set()
            if self._pipeline_thread is not None and self._pipeline_thread.is_alive():
                self._pipeline_thread.join(timeout=3)
            self._pipeline_thread = None
            self.pipeline.stop()
            self._attack_active = False
            self._warning_active = False

            latest_metric = self.database.fetch_latest_metric() or {}
            self.database.log_event(
                {
                    "event": "monitoring_stopped",
                    "event_type": "info",
                    "action": "none",
                    "file_name": "",
                    "file_path": "",
                    "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                    "file_rate": float(latest_metric.get("files_per_second") or 0.0),
                    "paths": [str(path) for path in self.protected_directories],
                }
            )
        return self.snapshot()

    def backup_status(self) -> dict[str, Any]:
        if self.pipeline is not None:
            status = self.pipeline.snapshot_manager.status()
            status["status"] = "Active"
            if not status.get("last_backup_time"):
                status["last_backup_time"] = self.database.fetch_latest_event_timestamp("backup_snapshot_created")
            return status

        return {
            "status": "Inactive",
            "files_secured": 0,
            "backup_versions": 0,
            "last_backup_time": None,
            "recent_files": [],
            "backup_root": str(BACKUP_ROOT),
        }

    def run_backup(self) -> dict[str, Any]:
        if self.pipeline is None:
            return {"message": "backup_unavailable", "created": 0, "backup_status": self.backup_status()}

        results = self.pipeline.snapshot_folder()
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
        if self.pipeline is None:
            return None

        restored_payload = self.pipeline.restore_file(file_path)
        restored = Path(str(restored_payload["source_path"])) if restored_payload is not None else None
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

    def restore_many(self, paths: list[str]) -> list[str]:
        if self.pipeline is None:
            return []

        restored = self.pipeline.restore_many(paths)
        latest_metric = self.database.fetch_latest_metric() or {}
        self.database.log_event(
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
        if self.pipeline is None:
            payload: dict[str, Any] = {
                "status": "SAFE",
                "confidence": 0,
                "is_monitoring": False,
                "metrics": {
                    "files_per_second": 0.0,
                    "modifications": 0,
                    "accesses": 0,
                    "cpu_percent": 0.0,
                    "threat_confidence": 0,
                    "status": "SAFE",
                },
                "alerts": [],
                "logs": [],
                "fingerprints": [],
                "monitored_paths": [str(path) for path in self.protected_directories],
                "core_pipeline": None,
            }
        else:
            pipeline_state = self.pipeline.status()
            threat = pipeline_state.get("threat") if isinstance(pipeline_state.get("threat"), dict) else {}
            threat_metrics = threat.get("metrics") if isinstance(threat.get("metrics"), dict) else {}

            score = self._to_int(threat.get("score"))
            status = "UNDER_ATTACK" if bool(threat.get("triggered")) else "SAFE"
            files_per_second = float(threat_metrics.get("file_activity_rate") or 0.0)
            activity_count = self._to_int(threat_metrics.get("file_activity_count"))
            cpu_percent = float(threat_metrics.get("cpu_usage") or 0.0)

            payload = {
                "status": status,
                "confidence": score,
                "is_monitoring": bool(pipeline_state.get("is_running", False)),
                "metrics": {
                    "files_per_second": round(files_per_second, 2),
                    "modifications": activity_count,
                    "accesses": activity_count,
                    "cpu_percent": round(cpu_percent, 2),
                    "cpu_percent_raw": round(cpu_percent, 2),
                    "cpu_percent_sampled": round(cpu_percent, 2),
                    "threat_confidence": score,
                    "status": status,
                },
                "alerts": self.database.fetch_alerts(20),
                "logs": self.database.fetch_logs(100),
                "fingerprints": self.database.fetch_fingerprints(),
                "monitored_paths": [str(path) for path in self.protected_directories],
                "core_pipeline": pipeline_state,
            }

        payload["monitor_paths"] = [str(path) for path in self.protected_directories]
        payload["monitoring_message"] = "Monitoring: Protected System Directories (Auto-configured)"
        payload["backup_root"] = str(BACKUP_ROOT)
        payload["database_path"] = str(DATABASE_PATH)
        return payload

    @staticmethod
    def _to_int(value: Any) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0

    def file_stats(self) -> dict[str, int]:
        backup_state = self.backup_status()
        files_protected = self._to_int(backup_state.get("files_secured"))
        files_recovered = 0

        for log in self.database.fetch_logs(500):
            event = str(log.get("event") or "")
            metadata = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
            if event in {"automatic_system_recovery", "files_restored"}:
                files_recovered += self._to_int(metadata.get("restored_count"))
            elif event == "file_restored":
                files_recovered += 1

        return {
            "files_protected": files_protected,
            "files_recovered": files_recovered,
        }

    def attack_summary(self) -> dict[str, int]:
        stats = self.file_stats()
        files_encrypted = 0
        files_recovered = stats["files_recovered"]
        threat_confidence = self._to_int(self.snapshot().get("confidence", 0))

        for log in self.database.fetch_logs(500):
            event = str(log.get("event") or "")
            metadata = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
            if event == "attack_report_generated":
                files_encrypted = self._to_int(metadata.get("files_affected"))
                files_recovered = self._to_int(metadata.get("files_recovered")) or files_recovered
                threat_confidence = self._to_int(metadata.get("threat_confidence")) or threat_confidence
                break
            if event == "attack_detected" and files_encrypted == 0:
                files_encrypted = self._to_int(metadata.get("modifications"))

        return {
            "files_protected": stats["files_protected"],
            "files_encrypted": files_encrypted,
            "files_recovered": files_recovered,
            "threat_confidence": threat_confidence,
        }

    def timeline(self) -> list[dict[str, str]]:
        event_to_state: dict[str, tuple[str, str, str]] = {
            "early_threat_detection": (
                "SUSPICIOUS_ACTIVITY",
                "Early Threat Detection triggered",
                "warning",
            ),
            "pre_attack_warning": (
                "SUSPICIOUS_ACTIVITY",
                "Early Threat Detection triggered",
                "warning",
            ),
            "attack_detected": (
                "ATTACK_DETECTED",
                "Behavioral attack pattern confirmed",
                "critical",
            ),
            "active_threat_neutralization": (
                "PROCESS_TERMINATED",
                "Active Threat Neutralization executed",
                "critical",
            ),
            "process_killed": (
                "PROCESS_TERMINATED",
                "Active Threat Neutralization executed",
                "critical",
            ),
            "automatic_system_recovery": (
                "FILES_RESTORED",
                "Automatic System Recovery restored files",
                "info",
            ),
            "files_restored": (
                "FILES_RESTORED",
                "Automatic System Recovery restored files",
                "info",
            ),
            "system_safe": (
                "SYSTEM_SAFE",
                "System returned to safe state",
                "safe",
            ),
            "recovery_completed": (
                "SYSTEM_SAFE",
                "System returned to safe state",
                "safe",
            ),
        }

        entries: list[dict[str, str]] = [
            {
                "state": "SAFE",
                "title": "System Safe",
                "description": "Monitoring engine is active and stable.",
                "severity": "safe",
                "timestamp": "",
            }
        ]

        for log in reversed(self.database.fetch_logs(500)):
            event = str(log.get("event") or "")
            if event not in event_to_state:
                continue

            state, description, severity = event_to_state[event]
            if entries and entries[-1]["state"] == state:
                continue

            entries.append(
                {
                    "state": state,
                    "title": state.replace("_", " ").title(),
                    "description": description,
                    "severity": severity,
                    "timestamp": str(log.get("timestamp") or ""),
                }
            )

        return entries


def _controller_from_app(flask_app: Flask) -> SystemController:
    controller = flask_app.extensions.get("cybershield_controller")
    if isinstance(controller, SystemController):
        return controller

    controller = SystemController()
    flask_app.extensions["cybershield_controller"] = controller
    return controller


def register_routes(flask_app: Flask) -> None:
    @flask_app.after_request
    def add_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    @flask_app.route("/api/health", methods=["GET"])
    def health() -> Any:
        snapshot = _controller_from_app(flask_app).snapshot()
        return jsonify(
            {
                "ok": True,
                "system": "CyberShield - Ransomware Defense System",
                "status": snapshot["status"],
            }
        )

    @flask_app.route("/api/status", methods=["GET"])
    def status() -> Any:
        data = _controller_from_app(flask_app).snapshot()
        return jsonify(
            {
                "status": data["status"],
                "confidence": int(data.get("confidence") or 0),
                "is_monitoring": data.get("is_monitoring", False),
                "monitor_paths": data["monitor_paths"],
                "monitoring_message": data["monitoring_message"],
                "backup_root": data["backup_root"],
                "metrics": data["metrics"],
                "core_pipeline": data.get("core_pipeline"),
            }
        )

    @flask_app.route("/api/attack/summary", methods=["GET"])
    def attack_summary() -> Any:
        return jsonify(_controller_from_app(flask_app).attack_summary())

    @flask_app.route("/api/file-stats", methods=["GET"])
    def file_stats() -> Any:
        return jsonify(_controller_from_app(flask_app).file_stats())

    @flask_app.route("/api/timeline", methods=["GET"])
    def timeline() -> Any:
        return jsonify({"timeline": _controller_from_app(flask_app).timeline()})

    @flask_app.route("/api/metrics", methods=["GET"])
    def metrics() -> Any:
        controller = _controller_from_app(flask_app)
        data = controller.snapshot()
        return jsonify(
            {
                "metrics": data["metrics"],
                "history": controller.database.fetch_metrics(120),
            }
        )

    @flask_app.route("/api/alerts", methods=["GET"])
    def alerts() -> Any:
        return jsonify({"alerts": _controller_from_app(flask_app).database.fetch_alerts(50)})

    @flask_app.route("/api/logs", methods=["GET"])
    def logs() -> Any:
        return jsonify({"logs": _controller_from_app(flask_app).database.fetch_logs(100)})

    @flask_app.route("/api/logs/clear", methods=["POST"])
    def clear_logs() -> Any:
        deleted = _controller_from_app(flask_app).database.clear_logs()
        return jsonify({"message": "logs_cleared", "deleted": deleted})

    @flask_app.route("/api/fingerprints", methods=["GET"])
    def fingerprints() -> Any:
        return jsonify({"fingerprints": _controller_from_app(flask_app).database.fetch_fingerprints()})

    @flask_app.route("/api/backup/status", methods=["GET"])
    def backup_status() -> Any:
        return jsonify(_controller_from_app(flask_app).backup_status())

    @flask_app.route("/api/backup/run", methods=["POST"])
    def run_backup() -> Any:
        return jsonify(_controller_from_app(flask_app).run_backup())

    @flask_app.route("/api/backup/recover", methods=["POST"])
    def backup_recover() -> Any:
        controller = _controller_from_app(flask_app)
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

    @flask_app.route("/api/backup/restore", methods=["POST"])
    def backup_restore() -> Any:
        return backup_recover()

    @flask_app.route("/api/emergency/contact", methods=["GET"])
    def get_emergency_contact() -> Any:
        return jsonify({"contact": _controller_from_app(flask_app).get_emergency_contact()})

    @flask_app.route("/api/emergency/contact", methods=["POST"])
    def save_emergency_contact() -> Any:
        controller = _controller_from_app(flask_app)
        body = request.get_json(silent=True) or {}
        phone = str(body.get("phone") or body.get("contact") or "").strip()
        if not phone:
            return jsonify({"message": "phone_required"}), 400

        saved_phone = controller.set_emergency_contact(phone)
        return jsonify({"message": "contact_saved", "contact": saved_phone})

    @flask_app.route("/api/settings/contact", methods=["GET"])
    def get_settings_contact() -> Any:
        return get_emergency_contact()

    @flask_app.route("/api/settings/contact", methods=["POST"])
    def save_settings_contact() -> Any:
        return save_emergency_contact()

    @flask_app.route("/api/report", methods=["GET"])
    def get_report() -> Any:
        report_path = _controller_from_app(flask_app).get_attack_report_path()
        if not report_path.exists():
            return jsonify({"message": "report_not_found"}), 404

        return send_file(
            report_path,
            as_attachment=False,
            mimetype="text/plain",
        )

    @flask_app.route("/api/report/download", methods=["GET"])
    def download_report() -> Any:
        report_path = _controller_from_app(flask_app).get_attack_report_path()
        if not report_path.exists():
            return jsonify({"message": "report_not_found"}), 404

        return send_file(
            report_path,
            as_attachment=True,
            download_name="attack_report.txt",
            mimetype="text/plain",
        )

    @flask_app.route("/api/start", methods=["POST"])
    def start_monitoring() -> Any:
        snapshot = _controller_from_app(flask_app).restart()
        return jsonify({"message": "monitoring_started", "snapshot": snapshot})

    @flask_app.route("/api/stop", methods=["POST"])
    def stop_monitoring() -> Any:
        snapshot = _controller_from_app(flask_app).stop()
        return jsonify({"message": "monitoring_stopped", "snapshot": snapshot})

    @flask_app.route("/api/restore", methods=["POST"])
    def restore_now() -> Any:
        controller = _controller_from_app(flask_app)
        body = request.get_json(silent=True) or {}
        paths = body.get("paths") or []
        if controller.pipeline is None:
            return jsonify({"message": "restore_unavailable", "restored": []}), 503

        restored = controller.restore_many(paths)
        return jsonify({"message": "restored", "restored": restored})

    @flask_app.route("/api/config", methods=["GET"])
    def get_runtime_config() -> Any:
        controller = _controller_from_app(flask_app)
        return jsonify(
            {
                "monitor_paths": [str(path) for path in controller.protected_directories],
                "monitoring_message": "Monitoring: Protected System Directories (Auto-configured)",
                "backup_root": str(BACKUP_ROOT),
                "database_path": str(DATABASE_PATH),
            }
        )

    @flask_app.route("/api/ping", methods=["GET"])
    def ping() -> Any:
        return jsonify({"message": "CyberShield is running"})


def create_app() -> Flask:
    app_instance = Flask(__name__)
    config_obj = AppConfig.from_env()
    app_instance.config.from_mapping(config_obj.flask_mapping())
    register_routes(app_instance)
    return app_instance
