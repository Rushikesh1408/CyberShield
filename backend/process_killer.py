from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import psutil


@dataclass(frozen=True)
class KillResult:
    pid: int
    name: str
    cmdline: str
    reason: str
    success: bool


class ProcessKiller:
    def __init__(self, *, allowlist: Iterable[str] | None = None, current_pid: int | None = None) -> None:
        self.allowlist = {name.lower() for name in (allowlist or [])}
        self.current_pid = current_pid or os.getpid()

    def _score_process(
        self,
        process: psutil.Process,
        target_paths: list[str],
    ) -> tuple[int, str]:
        try:
            name = (process.name() or "").lower()
            cmdline = " ".join(process.cmdline()).lower()
            if process.pid == self.current_pid or name in self.allowlist:
                return 0, "allowed"

            cpu = process.cpu_percent(interval=0.0)
            score = 0
            reason_parts: list[str] = []

            if cpu >= 70:
                score += 3
                reason_parts.append(f"cpu={cpu:.1f}")
            elif cpu >= 25:
                score += 2
                reason_parts.append(f"cpu={cpu:.1f}")

            suspicious_terms = [
                "ransom",
                "encrypt",
                "locker",
                "malware",
                "cipher",
                "lock",
            ]
            if any(term in name or term in cmdline for term in suspicious_terms):
                score += 3
                reason_parts.append("suspicious_name")

            touches_monitored_scope = False
            for target_path in target_paths:
                if target_path in cmdline:
                    touches_monitored_scope = True
                    break
            if touches_monitored_scope:
                score += 2
                reason_parts.append("touches_monitored_scope")

            if process.status() == psutil.STATUS_RUNNING:
                score += 1
                reason_parts.append("running")

            return score, ",".join(reason_parts) or "low_score"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return 0, "unavailable"

    def find_suspicious_process(
        self,
        target_paths: Iterable[str],
    ) -> tuple[psutil.Process | None, str]:
        best_process: psutil.Process | None = None
        best_reason = ""
        best_score = 0
        normalized_targets = [str(Path(target_path).resolve()).lower() for target_path in target_paths]

        for process in psutil.process_iter(["pid", "name", "cmdline"]):
            score, reason = self._score_process(process, normalized_targets)
            if score > best_score:
                best_process = process
                best_reason = reason
                best_score = score

        if best_process is None or best_score < 4:
            return None, "no_high_confidence_process"
        return best_process, best_reason

    def kill_process(self, process: psutil.Process, reason: str) -> KillResult:
        name = process.name()
        cmdline = " ".join(process.cmdline())
        success = False

        try:
            process.terminate()
            try:
                process.wait(timeout=2)
                success = True
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
                success = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            success = False

        return KillResult(process.pid, name, cmdline, reason, success)

    def scan_and_kill(
        self,
        target_paths: Iterable[str],
        *,
        reason: str,
    ) -> KillResult | None:
        process, process_reason = self.find_suspicious_process(target_paths)
        if process is None:
            return None
        return self.kill_process(process, f"{reason};{process_reason}")

    def scan_and_kill_many(
        self,
        target_paths: Iterable[str],
        *,
        reason: str,
        max_kills: int = 5,
        window_seconds: float = 3.0,
    ) -> list[KillResult]:
        killed: list[KillResult] = []
        deadline = time.time() + max(0.5, float(window_seconds))

        while len(killed) < max(1, int(max_kills)) and time.time() < deadline:
            result = self.scan_and_kill(target_paths, reason=reason)
            if result is None:
                break
            if result.success:
                killed.append(result)

        return killed
