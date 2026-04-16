from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.services.process_service import ProcessService


class ProcessTreeTracker:
    def __init__(self, process_service: ProcessService) -> None:
        self.process_service = process_service

    def track_chain(self, pid: int, *, max_depth: int = 8) -> list[dict[str, Any]]:
        chain: list[dict[str, Any]] = []
        visited: set[int] = set()
        current_pid = int(pid)
        depth = 0

        while current_pid > 0 and depth < max_depth and current_pid not in visited:
            visited.add(current_pid)
            process = self.process_service.get_process(current_pid)
            if process is None:
                break

            try:
                created_at = datetime.fromtimestamp(process.create_time(), timezone.utc).isoformat()
            except (OSError, ValueError):
                created_at = ""

            chain.append(
                {
                    "pid": int(process.pid),
                    "name": self.process_service.safe_name(process),
                    "path": self.process_service.safe_exe(process),
                    "cmdline": self.process_service.safe_cmdline(process),
                    "parent_pid": self.process_service.safe_parent_pid(process),
                    "created_at": created_at,
                }
            )

            parent_pid = self.process_service.safe_parent_pid(process)
            if parent_pid <= 0 or parent_pid == current_pid:
                break
            current_pid = parent_pid
            depth += 1

        return chain

    def entry_point(self, pid: int) -> dict[str, Any]:
        chain = self.track_chain(pid)
        if not chain:
            return {
                "entry_pid": int(pid),
                "entry_name": "unknown",
                "entry_path": "",
                "first_execution": "",
            }

        root = chain[-1]
        return {
            "entry_pid": int(root.get("pid") or 0),
            "entry_name": str(root.get("name") or "unknown"),
            "entry_path": str(root.get("path") or ""),
            "first_execution": str(root.get("created_at") or ""),
        }
