
"""
Production-grade file system monitor for CyberShield.
Uses watchdog to track file events, normalizes output, ignores temp/system files, and sends events to the detector.
"""

import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

IGNORED_EXTENSIONS = {'.tmp', '.swp', '.DS_Store', '.part', '.crdownload', '.lnk'}
IGNORED_PREFIXES = {'~', '.'}
IGNORED_DIRS = {'__pycache__', '.git', '.vscode', 'node_modules'}

def is_ignored(path):
    base = os.path.basename(path)
    if any(base.endswith(ext) for ext in IGNORED_EXTENSIONS):
        return True
    if any(base.startswith(prefix) for prefix in IGNORED_PREFIXES):
        return True
    if any(part in IGNORED_DIRS for part in path.split(os.sep)):
        return True
    return False

def normalize_event(event):
    return {
        'event_type': event.event_type,
        'file_path': os.path.abspath(event.src_path),
        'timestamp': datetime.utcnow().isoformat(),
        'is_directory': event.is_directory
    }

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, event_callback=None):
        self.event_callback = event_callback

    def on_any_event(self, event):
        if is_ignored(event.src_path):
            return
        norm = normalize_event(event)
        if self.event_callback:
            self.event_callback(norm)

class FileMonitor:
    def __init__(self, paths, event_callback=None):
        self.paths = paths if isinstance(paths, list) else [paths]
        self.event_callback = event_callback
        self.observer = Observer()

    def start(self):
        handler = MonitorHandler(self.event_callback)
        for path in self.paths:
            if os.path.exists(path):
                self.observer.schedule(handler, path, recursive=True)
            else:
                print(f"[Monitor] Warning: Path does not exist: {path}")
        self.observer.start()
        print(f"[Monitor] Started monitoring: {self.paths}")

    def stop(self):
        self.observer.stop()
        self.observer.join()
        print("[Monitor] Stopped monitoring.")

if __name__ == "__main__":
    from detector import DetectionEngine

    detector = DetectionEngine()

    def handle_event(event):
        result = detector.analyze_event(event)
        print(f"Event: {event}\nDetection: {result}")

    monitor = FileMonitor(paths="./protected_folder", event_callback=handle_event)
    monitor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
