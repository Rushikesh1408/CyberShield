from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Deque, Iterable
import os
from datetime import datetime

import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

# Global event counter for simple diagnostics and hackathon demos.
GLOBAL_EVENT_COUNTER = {"value": 0}
GLOBAL_EVENT_COUNTER_LOCK = threading.Lock()

IGNORED_EXTENSIONS = {'.tmp', '.swp', '.DS_Store', '.part', '.crdownload', '.lnk'}
IGNORED_PREFIXES = {'~', '.'}
IGNORED_DIRS = {'__pycache__', '.git', '.vscode', 'node_modules'}


@dataclass(frozen=True)
class MonitorEvent:
    file: str
    action: str
    timestamp: float


class RealTimeMonitor:
    _ACTIVITY_COUNT_WINDOW_SECONDS = 5.0
    _ACTIVITY_RATE_WINDOW_SECONDS = 1.0

    def __init__(
        self,
        *,
        watch_paths: Iterable[str | Path] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        paths = list(watch_paths) if watch_paths is not None else default_monitor_paths()
        unique_paths: list[Path] = []
        seen: set[str] = set()
        for value in paths:
            resolved = Path(value).resolve()
            key = str(resolved).lower()
            if key in seen:
                continue
            seen.add(key)
            unique_paths.append(resolved)

        if not unique_paths:
            raise ValueError("watch_paths cannot be empty")

        self.watch_paths = unique_paths
        self.on_event = on_event
        self._observer = Observer()
        self._stop_event = threading.Event()
        self._sampling_thread: threading.Thread | None = None
        self._lock = threading.Lock()

        self._recent_events: Deque[MonitorEvent] = deque(maxlen=400)
        self._event_times: Deque[float] = deque(maxlen=5000)

        self._event_counter = 0
        self._last_cpu = 0.0
        self._active_processes = 0
        self.is_running = False

        psutil.cpu_percent(interval=None)

    def start(self) -> bool:
        if self.is_running:
            return False

        handler = _WatchHandler(self)
        scheduled = 0
        for path in self.watch_paths:
            if path.exists() and path.is_dir():
                self._observer.schedule(handler, str(path), recursive=True)
                scheduled += 1

        if scheduled == 0:
            raise RuntimeError("No valid watch paths available")

        self._observer.start()
        self._stop_event.clear()
        self._sampling_thread = threading.Thread(
            target=self._sampling_loop,
            name="cybershield-monitor-sampler",
            daemon=True,
        )
        self._sampling_thread.start()
        self.is_running = True
        return True

    def stop(self) -> bool:
        if not self.is_running:
            return False

        self._stop_event.set()
        if self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=3)

        if self._sampling_thread and self._sampling_thread.is_alive():
            self._sampling_thread.join(timeout=3)

        self.is_running = False
        return True

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            while self._event_times and self._event_times[0] < now - self._ACTIVITY_COUNT_WINDOW_SECONDS:
                self._event_times.popleft()

            recent_events = [
                {
                    "file": event.file,
                    "action": event.action,
                    "timestamp": event.timestamp,
                }
                for event in self._recent_events
            ]
            activity_count = int(len(self._event_times))
            event_rate = float(
                sum(1 for event_time in self._event_times if event_time >= now - self._ACTIVITY_RATE_WINDOW_SECONDS)
            )
            event_counter = int(self._event_counter)
            cpu_usage = round(self._last_cpu, 2)
            active_processes = self._active_processes
            last_event_at = self._recent_events[-1].timestamp if self._recent_events else 0.0

        idle_seconds = float(now - last_event_at) if last_event_at else float(now)
        if idle_seconds < 0.0:
            idle_seconds = 0.0

        return {
            "watch_paths": [str(path) for path in self.watch_paths],
            "is_running": self.is_running,
            "file_activity_count": activity_count,
            "file_activity_rate": event_rate,
            "file_activity_total": event_counter,
            "cpu_usage": cpu_usage,
            "active_processes": active_processes,
            "last_event_at": last_event_at,
            "idle_seconds": idle_seconds,
            "events": recent_events,
        }

    def record_event(self, *, action: str, path: str) -> None:
        timestamp = time.time()
        event = MonitorEvent(file=str(Path(path)), action=action, timestamp=timestamp)
        with self._lock:
            self._event_counter += 1
            self._event_times.append(timestamp)
            self._recent_events.append(event)

        with GLOBAL_EVENT_COUNTER_LOCK:
            GLOBAL_EVENT_COUNTER["value"] += 1

        if self.on_event is None:
            return

        payload = {
            "file": event.file,
            "action": event.action,
            "timestamp": event.timestamp,
        }
        try:
            self.on_event(payload)
        except (RuntimeError, ValueError, TypeError):
            # Callback errors should not stop monitoring.
            return

    def _sampling_loop(self) -> None:
        while not self._stop_event.wait(1.0):
            try:
                cpu = psutil.cpu_percent(interval=None)
                processes = sum(1 for _ in psutil.process_iter(["pid"]))
            except (psutil.Error, OSError):
                cpu = self._last_cpu
                processes = self._active_processes

            with self._lock:
                self._last_cpu = float(cpu)
                self._active_processes = int(processes)


class _WatchHandler(FileSystemEventHandler):
    def __init__(self, monitor: RealTimeMonitor) -> None:
        self.monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor.record_event(action="created", path=event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor.record_event(action="modified", path=event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor.record_event(action="deleted", path=event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        src_path = str(getattr(event, "src_path", "") or "").strip()
        dest_path = str(getattr(event, "dest_path", "") or "").strip()

        # Treat move/rename as delete+create so threat activity reflects encrypted-name churn.
        if src_path:
            self.monitor.record_event(action="deleted", path=src_path)
        if dest_path:
            self.monitor.record_event(action="created", path=dest_path)


# Legacy FileMonitor class kept for backward compatibility
class MonitorHandler(FileSystemEventHandler):
    def __init__(self, event_callback=None):
        self.event_callback = event_callback

    def on_any_event(self, event):
        base = os.path.basename(event.src_path)
        if any(base.endswith(ext) for ext in IGNORED_EXTENSIONS):
            return
        if any(base.startswith(prefix) for prefix in IGNORED_PREFIXES):
            return
        if any(part in IGNORED_DIRS for part in event.src_path.split(os.sep)):
            return
        norm = {
            'event_type': event.event_type,
            'file_path': os.path.abspath(event.src_path),
            'timestamp': datetime.utcnow().isoformat(),
            'is_directory': event.is_directory
        }
        if self.event_callback:
            try:
                self.event_callback(norm)
            except Exception as e:
                import logging
                logging.getLogger("cybershield.monitor").error(
                    f"[MonitorHandler] event_callback raised: {e} — event: {norm}"
                )


class FileMonitor:
    def __init__(self, paths, event_callback=None):
        self.paths = paths if isinstance(paths, list) else [paths]
        self.event_callback = event_callback
        self.observer = Observer()
        self.is_running = False

    def start(self):
        if self.is_running:
            return
        handler = MonitorHandler(self.event_callback)
        for path in self.paths:
            if os.path.exists(path):
                self.observer.schedule(handler, path, recursive=True)
            else:
                print(f"[Monitor] Warning: Path does not exist: {path}")
        self.observer.start()
        self.is_running = True
        print(f"[Monitor] Started monitoring: {self.paths}")

    def stop(self):
        if not self.is_running:
            return
        self.observer.stop()
        self.observer.join(timeout=10)
        if self.observer.is_alive():
            import logging
            logging.getLogger("cybershield.monitor").warning(
                "[FileMonitor] Observer did not stop within timeout"
            )
        self.is_running = False
        print("[Monitor] Stopped monitoring.")


def default_monitor_paths() -> list[Path]:
    home = Path.home()
    candidates = [home / "Documents", home / "Desktop", home / "Downloads"]
    existing: list[Path] = []
    for path in candidates:
        if path.exists() and path.is_dir():
            existing.append(path.resolve())

    if existing:
        return existing

    fallback = Path.cwd() / "protected_folder"
    fallback.mkdir(parents=True, exist_ok=True)
    return [fallback.resolve()]


def global_event_counter() -> int:
    with GLOBAL_EVENT_COUNTER_LOCK:
        return int(GLOBAL_EVENT_COUNTER["value"])
