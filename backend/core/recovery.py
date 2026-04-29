"""
Production-grade recovery engine for CyberShield.
On detection: stop process, lock directory, restore snapshot, log event.
"""
import os
import shutil
import logging
import threading
from backend.core.snapshot import SnapshotManager
from backend.core.process_manager import ProcessManager

logger = logging.getLogger("cybershield.recovery")


class RecoveryEngine:
    def __init__(self):
        self.snapshot_mgr = SnapshotManager()
        self.locked_dirs = set()
        self.lock = threading.Lock()

    def lock_directory(self, dir_path):
        with self.lock:
            self.locked_dirs.add(dir_path)

    def unlock_directory(self, dir_path):
        with self.lock:
            self.locked_dirs.discard(dir_path)

    def is_locked(self, dir_path):
        with self.lock:
            return dir_path in self.locked_dirs

    def recover(self, file_path, pid=None):
        """
        Stop process, lock dir, restore latest snapshot, log event.
        unlock_directory is guaranteed to run even if copy2 raises.
        """
        dir_path = os.path.dirname(file_path)
        # 1. Stop process
        if pid is not None:
            killed, msg = ProcessManager.kill_process(pid)
        else:
            killed, msg = (None, "No PID provided")
        # 2. Lock directory
        self.lock_directory(dir_path)
        restored = False
        try:
            # 3. Restore latest safe snapshot
            snap_path = self.snapshot_mgr.get_latest_snapshot(file_path)
            if snap_path and os.path.isfile(snap_path):
                shutil.copy2(snap_path, file_path)
                restored = True
        except Exception as exc:
            logger.error(f"[Recovery] copy2 failed for {file_path}: {exc}")
            restored = False
        finally:
            # 4. Always unlock directory after restore attempt
            self.unlock_directory(dir_path)

        logger.info(
            f"[Recovery] Process killed: {killed}, Dir locked: {dir_path}, "
            f"Restored: {restored}, File: {file_path}"
        )
        return {
            'process_killed': killed,
            'kill_msg': msg,
            'dir_locked': dir_path,
            'restored': restored,
            'file': file_path
        }
