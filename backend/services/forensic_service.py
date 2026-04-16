from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.database import Database


class ForensicService:
    def __init__(self, *, database: Database, incident_root: str | Path) -> None:
        self.database = database
        self.incident_root = Path(incident_root).resolve()
        self.incident_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _timestamp_slug() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")

    def generate_incident_package(self, *, evidence: dict[str, Any]) -> dict[str, Any]:
        package_dir = self.incident_root / f"incident_{self._timestamp_slug()}"
        package_dir.mkdir(parents=True, exist_ok=True)

        logs = self.database.fetch_logs(200)
        fingerprints = self.database.fetch_fingerprints()
        report_text = [
            "CyberShield Attack Evidence Package",
            f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
            f"Attack Start Time: {evidence.get('attack_start_time', '')}",
            f"Status: {evidence.get('status', 'SAFE')}",
            f"Threat Score: {evidence.get('threat_score', 0)}",
            f"Confidence: {evidence.get('confidence', 0.0)}",
            f"File Activity Rate: {evidence.get('file_activity_rate', 0.0)}",
            f"Actions: {', '.join(evidence.get('actions', []) or []) or 'none'}",
            f"Affected Files: {len(evidence.get('affected_files', []) or [])}",
            f"Recovered Files: {evidence.get('files_recovered', 0)}",
            f"Entropy: {evidence.get('entropy', 0.0)}",
            f"Entropy Triggered: {bool(evidence.get('entropy_triggered'))}",
            "",
            "Timeline:",
        ]

        for item in evidence.get("timeline", []) or []:
            report_text.append(
                f"- {item.get('state', '')}: {item.get('title', '')} @ {item.get('timestamp', '')}"
            )

        (package_dir / "report.txt").write_text("\n".join(report_text) + "\n", encoding="utf-8")
        self._write_json(package_dir / "logs.json", logs)
        self._write_json(package_dir / "fingerprint.json", fingerprints)
        self._write_json(
            package_dir / "process_info.json",
            {
                "attack_start_time": evidence.get("attack_start_time"),
                "suspicious_processes": evidence.get("suspicious_processes", []),
                "confirmed_processes": evidence.get("confirmed_processes", []),
                "process_tree": evidence.get("process_tree", []),
                "top_process": (evidence.get("confirmed_processes") or evidence.get("suspicious_processes") or [{}])[0],
                "entropy": evidence.get("entropy", 0.0),
                "entropy_triggered": bool(evidence.get("entropy_triggered")),
                "file_activity_rate": evidence.get("file_activity_rate", 0.0),
                "dna_mismatch_count": evidence.get("dna_mismatch_count", 0),
                "affected_files": evidence.get("affected_files", []),
            },
        )

        return {
            "package_dir": str(package_dir),
            "report": str(package_dir / "report.txt"),
            "logs": str(package_dir / "logs.json"),
            "fingerprint": str(package_dir / "fingerprint.json"),
            "process_info": str(package_dir / "process_info.json"),
        }
