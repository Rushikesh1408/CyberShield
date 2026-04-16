from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import psutil


@dataclass(frozen=True)
class TerminationResult:
    pid: int | None
    name: str
    success: bool
    status: str
    reason: str
    error: str | None = None


def _normalize_name(name: str) -> str:
    return name.strip().lower()


def _resolve_process(identifier: int | str | psutil.Process) -> psutil.Process | None:
    if isinstance(identifier, psutil.Process):
        return identifier

    if isinstance(identifier, int):
        try:
            return psutil.Process(identifier)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    text = str(identifier).strip()
    if not text:
        return None

    if text.isdigit():
        try:
            return psutil.Process(int(text))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError):
            return None

    target_name = _normalize_name(text)
    for process in psutil.process_iter(["pid", "name"]):
        try:
            process_name = _normalize_name(process.info.get("name") or process.name() or "")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        if process_name == target_name:
            return process

    return None


def _safe_terminate(process: psutil.Process, reason: str) -> TerminationResult:
    try:
        name = process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        name = "<unknown>"

    try:
        process.terminate()
        try:
            process.wait(timeout=2)
            return TerminationResult(process.pid, name, True, "terminated", reason)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
            return TerminationResult(process.pid, name, True, "killed", reason)
    except psutil.NoSuchProcess:
        return TerminationResult(process.pid, name, False, "not_found", reason, "process no longer exists")
    except psutil.AccessDenied as exc:
        return TerminationResult(process.pid, name, False, "access_denied", reason, str(exc))
    except psutil.ZombieProcess as exc:
        return TerminationResult(process.pid, name, False, "zombie", reason, str(exc))
    except Exception as exc:
        return TerminationResult(process.pid, name, False, "error", reason, str(exc))


def terminate_suspicious_process(
    identifier: int | str | psutil.Process,
    *,
    reason: str = "suspicious activity detected",
) -> TerminationResult:
    process = _resolve_process(identifier)
    if process is None:
        return TerminationResult(None, str(identifier), False, "not_found", reason, "process not found")
    return _safe_terminate(process, reason)


def terminate_suspicious_processes(
    identifiers: Iterable[int | str | psutil.Process],
    *,
    reason: str = "suspicious activity detected",
) -> list[TerminationResult]:
    return [terminate_suspicious_process(identifier, reason=reason) for identifier in identifiers]


__all__ = [
    "TerminationResult",
    "terminate_suspicious_process",
    "terminate_suspicious_processes",
]