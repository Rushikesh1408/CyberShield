from __future__ import annotations

import os
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Deque


@dataclass(frozen=True)
class DetectionResult:
    status: str
    reason: str


@dataclass(frozen=True)
class FileEvent:
    path: Path
    process_id: int | None
    event_type: str
    timestamp: float
    destination_path: Path | None = None


class _LRUCache(OrderedDict[str, str]):
    def __init__(self, *, maxsize: int = 10_000) -> None:
        super().__init__()
        self.maxsize = max(1, int(maxsize))

    def __getitem__(self, key: str) -> str:
        value = super().__getitem__(key)
        super().move_to_end(key)
        return value

    def get(self, key: str, default: str | None = None) -> str | None:
        if key not in self:
            return default
        return self[key]

    def __setitem__(self, key: str, value: str) -> None:
        if key in self:
            super().__delitem__(key)
        super().__setitem__(key, value)
        while len(self) > self.maxsize:
            self.popitem(last=False)


class BehaviorDetector:
    def __init__(
        self,
        *,
        modification_window_seconds: float = 5.0,
        modification_threshold: int = 20,
        process_file_threshold: int = 10,
        rename_threshold: int = 4,
    ) -> None:
        self.modification_window_seconds = float(modification_window_seconds)
        self.modification_threshold = int(modification_threshold)
        self.process_file_threshold = int(process_file_threshold)
        self.rename_threshold = int(rename_threshold)

        self._modification_times: Deque[float] = deque()
        self._process_touches: dict[int, Deque[float]] = defaultdict(deque)
        self._rename_times: Deque[float] = deque()
        self._file_extensions = _LRUCache(maxsize=10_000)
        self._file_extensions_lock = Lock()
        self._last_event_time: float | None = None

    @staticmethod
    def _normalize_path(path: str | Path) -> str:
        candidate = Path(path)
        try:
            normalized = candidate.resolve()
        except OSError:
            normalized = candidate.expanduser().absolute()
        return os.path.normcase(str(normalized))

    @staticmethod
    def _extension_for(path: Path) -> str:
        return path.suffix.lower()

    def _trim_queue(self, queue: Deque[float], now: float) -> None:
        cutoff = now - self.modification_window_seconds
        retained = deque(timestamp for timestamp in queue if timestamp >= cutoff)
        queue.clear()
        queue.extend(retained)

    def _trim_process_queue(self, process_id: int, now: float) -> None:
        queue = self._process_touches.get(process_id)
        if queue is None:
            return
        cutoff = now - self.modification_window_seconds
        retained = deque(timestamp for timestamp in queue if timestamp >= cutoff)
        queue.clear()
        queue.extend(retained)
        if not queue:
            self._process_touches.pop(process_id, None)

    def record_event(
        self,
        *,
        path: str | Path,
        event_type: str,
        process_id: int | None = None,
        timestamp: float,
        destination_path: str | Path | None = None,
    ) -> DetectionResult:
        resolved_path = Path(path)
        normalized_path = self._normalize_path(resolved_path)
        destination = Path(destination_path) if destination_path is not None else None

        event_type = event_type.lower().strip()
        self._last_event_time = timestamp

        if event_type in {"modified", "created", "deleted"}:
            self._modification_times.append(timestamp)
            self._trim_queue(self._modification_times, timestamp)

        if process_id is not None:
            self._process_touches[process_id].append(timestamp)
            self._trim_process_queue(process_id, timestamp)

        did_count_rename = False

        if event_type in {"moved", "renamed"}:
            self._rename_times.append(timestamp)
            self._trim_queue(self._rename_times, timestamp)
            did_count_rename = True

        current_extension = self._extension_for(resolved_path)
        with self._file_extensions_lock:
            previous_extension = self._file_extensions.get(normalized_path)
            if previous_extension is None:
                self._file_extensions[normalized_path] = current_extension
            elif previous_extension != current_extension:
                if not did_count_rename:
                    self._rename_times.append(timestamp)
                    self._trim_queue(self._rename_times, timestamp)
                    did_count_rename = True
                self._file_extensions[normalized_path] = current_extension

        if destination is not None:
            destination_normalized = self._normalize_path(destination)
            destination_extension = self._extension_for(destination)
            source_extension = current_extension
            if source_extension != destination_extension and not did_count_rename:
                self._rename_times.append(timestamp)
                self._trim_queue(self._rename_times, timestamp)
                did_count_rename = True
            with self._file_extensions_lock:
                self._file_extensions[destination_normalized] = destination_extension

        return self.evaluate(timestamp=timestamp)

    def evaluate(self, *, timestamp: float | None = None) -> DetectionResult:
        now = timestamp if timestamp is not None else self._last_event_time
        if now is None:
            return DetectionResult(status="SAFE", reason="No file activity observed")

        self._trim_queue(self._modification_times, now)
        self._trim_queue(self._rename_times, now)
        for process_id in list(self._process_touches.keys()):
            self._trim_process_queue(process_id, now)

        modification_count = len(self._modification_times)
        rename_count = len(self._rename_times)
        high_risk_processes = [
            process_id for process_id, touches in self._process_touches.items() if len(touches) >= self.process_file_threshold
        ]

        if modification_count > self.modification_threshold and high_risk_processes:
            return DetectionResult(
                status="ATTACK",
                reason=(
                    f"{modification_count} file modifications in the last {int(self.modification_window_seconds)}s "
                    f"and process(es) {high_risk_processes} touched many files"
                ),
            )

        if modification_count > self.modification_threshold:
            return DetectionResult(
                status="SUSPICIOUS",
                reason=f"{modification_count} file modifications in the last {int(self.modification_window_seconds)}s",
            )

        if high_risk_processes:
            return DetectionResult(
                status="ATTACK",
                reason=f"Process(es) {high_risk_processes} touched many files in the last {int(self.modification_window_seconds)}s",
            )

        if rename_count >= self.rename_threshold:
            return DetectionResult(
                status="SUSPICIOUS",
                reason=f"Rapid rename or extension changes detected ({rename_count} events in the last {int(self.modification_window_seconds)}s)",
            )

        return DetectionResult(status="SAFE", reason="No ransomware-like behavior detected")


__all__ = ["BehaviorDetector", "DetectionResult", "FileEvent"]
