
"""
Production-grade rule-based detection engine for CyberShield.
Detects ransomware-like behavior: rapid changes, mass renaming, suspicious extensions, entropy, high I/O.
"""

import os
import time
import threading
from collections import deque, defaultdict

SUSPICIOUS_EXTENSIONS = {'.enc', '.locked', '.crypt', '.encrypted'}
ENTROPY_THRESHOLD = 6.5  # basic heuristic for encrypted files
RAPID_CHANGE_WINDOW = 2  # seconds
RAPID_CHANGE_THRESHOLD = 20  # files
MASS_RENAME_THRESHOLD = 10  # files
HIGH_IO_THRESHOLD = 50  # events in window

def file_entropy(path):
    try:
        with open(path, 'rb') as f:
            data = f.read(4096)
            if not data:
                return 0.0
            import math
            from collections import Counter
            counter = Counter(data)
            total = len(data)
            entropy = -sum(count/total * math.log2(count/total) for count in counter.values())
            return entropy
    except Exception:
        return 0.0

class DetectionEngine:
    def __init__(self):
        self.event_log = deque(maxlen=1000)
        self.rename_log = defaultdict(list)  # {timestamp: [file_paths]}
        self.last_check = time.time()
        self.lock = threading.Lock()

    def _prune_rename_log(self, now: float) -> None:
        """Remove rename_log entries older than RAPID_CHANGE_WINDOW to prevent unbounded growth."""
        stale_keys = [k for k in self.rename_log if now - k > RAPID_CHANGE_WINDOW]
        for k in stale_keys:
            del self.rename_log[k]

    def analyze_event(self, event):
        """
        event: {event_type, file_path, timestamp, is_directory}
        Returns: {threat, reason, severity}

        Entropy check is performed BEFORE acquiring the lock to avoid
        blocking I/O inside the critical section.
        """
        # --- Disk I/O outside the lock ---
        entropy = None
        if event['event_type'] in {'modified', 'created'} and not event['is_directory']:
            entropy = file_entropy(event['file_path'])

        with self.lock:
            now = time.time()
            self.event_log.append((now, event))

            # Rapid file modifications
            recent = [e for t, e in self.event_log if now - t < RAPID_CHANGE_WINDOW and not e['is_directory']]
            if len(recent) >= RAPID_CHANGE_THRESHOLD:
                return {
                    'threat': True,
                    'reason': f"{len(recent)} files changed in {RAPID_CHANGE_WINDOW}s (rapid modification)",
                    'severity': 'high'
                }

            # Mass renaming — prune stale entries before checking
            if event['event_type'] == 'moved':
                self.rename_log[now].append(event['file_path'])
                self._prune_rename_log(now)
                renames = sum(len(v) for v in self.rename_log.values())
                if renames >= MASS_RENAME_THRESHOLD:
                    return {
                        'threat': True,
                        'reason': f"{renames} files renamed in {RAPID_CHANGE_WINDOW}s (mass renaming)",
                        'severity': 'high'
                    }

            # Suspicious extensions
            ext = os.path.splitext(event['file_path'])[1].lower()
            if ext in SUSPICIOUS_EXTENSIONS:
                return {
                    'threat': True,
                    'reason': f"Suspicious extension detected: {ext}",
                    'severity': 'medium'
                }

            # Entropy check result (computed before lock)
            if entropy is not None and entropy > ENTROPY_THRESHOLD:
                return {
                    'threat': True,
                    'reason': f"High entropy file: {event['file_path']} (entropy={entropy:.2f})",
                    'severity': 'medium'
                }

            # High I/O burst
            if len([t for t, _ in self.event_log if now - t < RAPID_CHANGE_WINDOW]) > HIGH_IO_THRESHOLD:
                return {
                    'threat': True,
                    'reason': "High I/O burst detected",
                    'severity': 'medium'
                }

            # No threat detected
            return {
                'threat': False,
                'reason': 'No suspicious activity',
                'severity': 'none'
            }
