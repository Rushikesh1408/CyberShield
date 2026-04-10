from __future__ import annotations

import os
import re
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
    error: str | None = None


SUSPICIOUS_PATTERNS = [
    re.compile(r"\bransom\w*\b"),
    re.compile(r"\bencrypt\w*\b"),
    re.compile(r"\blocker\w*\b"),
    re.compile(r"\bmalware\w*\b"),
    re.compile(r"\bcipher\w*\b"),
]


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

            scan_text = f"{name} {cmdline}"
            if any(pattern.search(scan_text) for pattern in SUSPICIOUS_PATTERNS):
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
        name = "<unknown>"
        cmdline = ""
        success = False
        error: str | None = None

        try:
            name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            name = "<exited>"

        try:
            cmdline = " ".join(process.cmdline())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            cmdline = ""

        try:
            process.terminate()
            try:
                process.wait(timeout=2)
                success = True
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
                success = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as ex:
            success = False
            error = str(ex)

        return KillResult(process.pid, name, cmdline, reason, success, error)

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
        targets = list(target_paths)
        killed: list[KillResult] = []
        deadline = time.time() + max(0.5, float(window_seconds))
        failure_count = 0
        attempts = 0
        max_attempts = max(3, int(max_kills) * 3)

        while len(killed) < max(1, int(max_kills)) and time.time() < deadline and attempts < max_attempts:
            attempts += 1
            result = self.scan_and_kill(targets, reason=reason)
            if result is None:
                break
            if result.success:
                killed.append(result)
                failure_count = 0
            else:
                failure_count += 1
                time.sleep(0.1)
                if failure_count >= 3:
                    break

        return killed
