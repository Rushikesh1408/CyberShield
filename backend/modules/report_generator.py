from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EvidenceReportGenerator:
    def __init__(self, incident_root: str | Path) -> None:
        self.incident_root = Path(incident_root).resolve()
        self.incident_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")

    @staticmethod
    def _incident_id() -> str:
        # Unique: microseconds + short uuid (HEAD's safer version)
        now = datetime.now(timezone.utc)
        base = now.strftime("%Y%m%dT%H%M%S.%fZ")
        suffix = uuid.uuid4().hex[:8]
        return f"{base}-{suffix}"

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        # Sanitize incident_id: allow only [A-Za-z0-9._-]
        raw_id = str(payload.get("incident_id") or self._incident_id())
        safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", raw_id)
        if not safe_id:
            safe_id = self._incident_id()

        incident_id = safe_id
        folder = self.incident_root / f"incident_{incident_id}"

        # Ensure folder is a child of incident_root (path traversal protection)
        # Path.is_relative_to() is immune to the startswith("/tmp/abc" vs "/tmp/abcdef") false-positive.
        folder_resolved = folder.resolve()
        root_resolved = self.incident_root.resolve()
        if not folder_resolved.is_relative_to(root_resolved):
            raise ValueError("Invalid incident_id: path traversal detected")

        folder.mkdir(parents=True, exist_ok=True)

        report_json = {
            "incident_id": incident_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": payload.get("status", "UNDER_ATTACK"),
            "severity": payload.get("severity", "high"),
            "signature_id": payload.get("signature", {}).get("signature_id", ""),
            "wallets": payload.get("wallets", []),
            "correlation": payload.get("correlation", {}),
            "entry_point": payload.get("entry_point", {}),
        }

        self._write_json(folder / "report.json", report_json)
        self._write_json(folder / "logs.json", payload.get("logs", []))
        self._write_json(folder / "fingerprint.json", payload.get("signature", {}))
        self._write_json(folder / "process_tree.json", payload.get("process_tree", []))
        self._write_json(folder / "network_logs.json", payload.get("network_logs", []))
        self._write_json(folder / "timeline.json", payload.get("timeline", []))

        return {"incident_id": incident_id, "folder": str(folder), "report_path": str(folder / "report.json")}
