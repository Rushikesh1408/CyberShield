from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import psutil

from backend.services.process_service import ProcessService


class PersistenceDetector:
    def __init__(self, process_service: ProcessService) -> None:
        self.process_service = process_service

    def detect(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        findings.extend(self._detect_startup_folder_anomalies())
        findings.extend(self._detect_hidden_background_processes())
        return findings

    @staticmethod
    def _detect_startup_folder_anomalies() -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        app_data = os.environ.get("APPDATA", "")
        startup = Path(app_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if not startup.exists() or not startup.is_dir():
            return findings

        for file_path in startup.glob("*"):
            lower_name = file_path.name.lower()
            if lower_name.endswith((".vbs", ".js", ".cmd", ".bat", ".ps1", ".exe")):
                findings.append(
                    {
                        "finding_type": "startup_entry",
                        "severity": "high",
                        "details": f"Potential autorun artifact: {file_path}",
                        "metadata": {"path": str(file_path)},
                    }
                )

        return findings

    def _detect_hidden_background_processes(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        suspicious_markers = ("appdata", "temp", "\\\\", "powershell", "cmd.exe", "wscript")

        for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                name = self.process_service.safe_name(process).lower()
                executable = self.process_service.safe_exe(process).lower()
                # Support both str and list return types from safe_cmdline
                cmdline_val = self.process_service.safe_cmdline(process)
                if isinstance(cmdline_val, list):
                    cmdline = " ".join(str(x) for x in cmdline_val).lower()
                else:
                    cmdline = str(cmdline_val).lower()
                pid = int(process.pid)
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                continue

            if pid == os.getpid():
                continue

            has_marker = any(marker in executable or marker in cmdline or marker in name for marker in suspicious_markers)
            if not has_marker:
                continue

            try:
                parent_pid = int(process.ppid())
            except (psutil.Error, OSError, TypeError, ValueError):
                parent_pid = 0

            findings.append(
                {
                    "finding_type": "hidden_background_process",
                    "severity": "medium",
                    "details": f"Suspicious background process: {name} ({pid})",
                    "metadata": {"pid": pid, "parent_pid": parent_pid, "path": executable, "cmdline": cmdline},
                }
            )

        return findings[:40]
