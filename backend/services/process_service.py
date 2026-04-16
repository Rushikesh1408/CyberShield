from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

import psutil


SAFE_PROCESSES = [
    "explorer.exe",
    "chrome.exe",
    "code.exe",
    "winword.exe",
    "excel.exe",
]

SUSPICIOUS_PATH_MARKERS = ("appdata", "temp", "downloads")
SCRIPTING_ENGINES = ("powershell", "python", "pythonw", "cmd", "pwsh")


class ProcessService:
    def __init__(self, *, safe_processes: Iterable[str] | None = None, current_pid: int | None = None) -> None:
        self.safe_processes = {str(name).lower() for name in (safe_processes or SAFE_PROCESSES)}
        self.current_pid = int(current_pid or os.getpid())

    @staticmethod
    def _normalize_path_candidates(monitored_paths: Iterable[str | Path] | None) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in monitored_paths or []:
            try:
                resolved = str(Path(value).resolve()).lower()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            normalized.append(resolved)
        return normalized

    @staticmethod
    def _process_name(process: psutil.Process) -> str:
        try:
            name = process.name()
        except (psutil.Error, OSError):
            name = ""
        return str(name or "").strip()

    @staticmethod
    def _process_command_line(process: psutil.Process) -> str:
        try:
            return " ".join(process.cmdline()).strip()
        except (psutil.Error, OSError):
            return ""

    @staticmethod
    def _process_executable(process: psutil.Process) -> str:
        try:
            return str(process.exe() or "")
        except (psutil.Error, OSError):
            return ""

    def get_process(self, pid: int) -> psutil.Process | None:
        try:
            return psutil.Process(int(pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError):
            return None

    def safe_name(self, process: psutil.Process) -> str:
        return self._process_name(process)

    def safe_exe(self, process: psutil.Process) -> str:
        return self._process_executable(process)

    def safe_cmdline(self, process: psutil.Process) -> str:
        return self._process_command_line(process)

    def safe_parent_pid(self, process: psutil.Process) -> int:
        try:
            return int(process.ppid())
        except (psutil.Error, OSError, TypeError, ValueError):
            return 0

    def safe_children(self, process: psutil.Process) -> list[psutil.Process]:
        try:
            return list(process.children(recursive=False))
        except (psutil.Error, OSError):
            return []

    def open_file_paths(self, pid: int) -> list[str]:
        process = self.get_process(pid)
        if process is None:
            return []

        try:
            return [str(item.path) for item in process.open_files() if getattr(item, "path", None)]
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            return []

    @staticmethod
    def _safe_priority_value() -> int | float | None:
        return getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", None)

    def detect_suspicious_processes(
        self,
        *,
        monitored_paths: Iterable[str | Path] | None = None,
        cpu_threshold: float = 65.0,
        open_file_threshold: int = 8,
        score_threshold: float = 25.0,
        candidate_limit: int = 8,
    ) -> list[dict[str, object]]:
        monitored_roots = self._normalize_path_candidates(monitored_paths)
        preliminary_candidates: list[dict[str, object]] = []

        for process in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
            try:
                pid = int(process.info.get("pid") or process.pid)
                if pid == self.current_pid:
                    continue

                name = self._process_name(process)
                lower_name = name.lower()
                if lower_name in self.safe_processes:
                    continue

                command_line = self._process_command_line(process)
                lower_command_line = command_line.lower()
                executable = self._process_executable(process)
                lower_executable = executable.lower()
                cpu_usage = float(process.cpu_percent(interval=0.0) or 0.0)

                command_is_script = any(engine in lower_command_line for engine in SCRIPTING_ENGINES)
                suspicious_path = any(marker in lower_executable for marker in SUSPICIOUS_PATH_MARKERS) or any(
                    marker in lower_command_line for marker in SUSPICIOUS_PATH_MARKERS
                )

                if not (
                    cpu_usage >= cpu_threshold
                    or command_is_script
                    or suspicious_path
                ):
                    continue
                score = 0.0
                if cpu_usage >= cpu_threshold:
                    score += min(40.0, 15.0 + max(0.0, cpu_usage - cpu_threshold) * 0.8)
                elif cpu_usage >= max(15.0, cpu_threshold * 0.6):
                    score += 10.0

                if command_is_script:
                    score += 18.0

                if suspicious_path:
                    score += 20.0
                if "ransom" in lower_name or "encrypt" in lower_command_line or "locker" in lower_command_line:
                    score += 15.0

                preliminary_candidates.append(
                    {
                        "pid": pid,
                        "name": name,
                        "path": executable or command_line,
                        "cpu": round(cpu_usage, 2),
                        "score": round(score, 2),
                        "candidate_key": f"{pid}:{name}:{executable or command_line}",
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue

        preliminary_candidates.sort(key=lambda item: float(item["score"]), reverse=True)
        suspicious: list[dict[str, object]] = []
        for candidate in preliminary_candidates[: max(1, int(candidate_limit))]:
            process = self.get_process(int(candidate.get("pid") or 0))
            if process is None:
                continue

            try:
                open_files = process.open_files()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                open_files = []

            open_file_count = len(open_files)
            file_scope_hit = False
            if monitored_roots:
                for opened_file in open_files:
                    opened_path = str(getattr(opened_file, "path", "") or "").lower()
                    if any(opened_path.startswith(root) or root in opened_path for root in monitored_roots):
                        file_scope_hit = True
                        break

            score = float(candidate["score"])
            if open_file_count >= open_file_threshold:
                score += min(20.0, float(open_file_count) * 1.25)
            if file_scope_hit:
                score += 25.0

            if score < score_threshold and not file_scope_hit and float(candidate.get("cpu") or 0.0) < cpu_threshold:
                continue

            suspicious.append(
                {
                    "pid": int(candidate["pid"]),
                    "name": str(candidate["name"]),
                    "path": str(candidate["path"]),
                    "cpu": float(candidate["cpu"]),
                    "score": round(score, 2),
                }
            )

        suspicious.sort(key=lambda item: float(item["score"]), reverse=True)
        return suspicious

    def suspend_process(self, pid: int) -> dict[str, object]:
        try:
            process = psutil.Process(int(pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError):
            return {"pid": int(pid), "action": "missing", "success": False}

        name = self._process_name(process)
        if name.lower() in self.safe_processes:
            return {"pid": int(pid), "name": name, "action": "monitor_only", "success": True}

        try:
            process.suspend()
            return {"pid": int(pid), "name": name, "action": "suspended", "success": True}
        except (AttributeError, psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            try:
                priority_value = self._safe_priority_value()
                if priority_value is not None:
                    process.nice(priority_value)
                elif os.name == "nt":
                    process.nice(psutil.IDLE_PRIORITY_CLASS)
                else:
                    process.nice(10)
                return {"pid": int(pid), "name": name, "action": "priority_reduced", "success": True}
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                return {"pid": int(pid), "name": name, "action": "failed", "success": False}

    def terminate_process(self, pid: int) -> dict[str, object]:
        try:
            process = psutil.Process(int(pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError):
            return {"pid": int(pid), "action": "missing", "success": False}

        name = self._process_name(process)
        if name.lower() in self.safe_processes:
            return {"pid": int(pid), "name": name, "action": "monitor_only", "success": True}

        try:
            process.terminate()
            try:
                process.wait(timeout=2)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            return {"pid": int(pid), "name": name, "action": "terminated", "success": True}
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            return {"pid": int(pid), "name": name, "action": "failed", "success": False}

    def neutralize_threat(self, process: dict[str, object], *, terminate_threshold: float = 60.0) -> dict[str, object]:
        pid = int(process.get("pid") or 0)
        name = str(process.get("name") or "")
        score = float(process.get("score") or 0.0)

        if name.lower() in self.safe_processes:
            return {"pid": pid, "name": name, "action": "monitor_only", "success": True}

        if score >= float(terminate_threshold):
            return self.terminate_process(pid)

        return self.suspend_process(pid)
