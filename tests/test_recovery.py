"""
Unit tests for RecoveryEngine.
Uses tempfile and mocks to avoid touching the real filesystem.
"""
import os
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch, MagicMock

# Adjust path if running from project root
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.core.recovery import RecoveryEngine


class TestRecoveryEngine(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.target_file = os.path.join(self.tmp_dir, "test_file.txt")
        self.snapshot_file = os.path.join(self.tmp_dir, "snapshot.txt")
        with open(self.target_file, "w") as f:
            f.write("original content\n")
        with open(self.snapshot_file, "w") as f:
            f.write("clean snapshot content\n")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # lock_directory / unlock_directory / is_locked
    # ------------------------------------------------------------------

    def test_lock_unlock_directory(self):
        engine = RecoveryEngine()
        engine.lock_directory(self.tmp_dir)
        self.assertTrue(engine.is_locked(self.tmp_dir))
        engine.unlock_directory(self.tmp_dir)
        self.assertFalse(engine.is_locked(self.tmp_dir))

    def test_is_locked_thread_safety(self):
        """Multiple threads locking and unlocking should not corrupt state."""
        engine = RecoveryEngine()
        errors = []

        def _worker():
            try:
                for _ in range(100):
                    engine.lock_directory("/some/dir")
                    engine.unlock_directory("/some/dir")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"Thread safety errors: {errors}")

    # ------------------------------------------------------------------
    # recover — happy path (snapshot exists)
    # ------------------------------------------------------------------

    def test_recover_restores_file_from_snapshot(self):
        engine = RecoveryEngine()
        engine.snapshot_mgr = MagicMock()
        engine.snapshot_mgr.get_latest_snapshot.return_value = self.snapshot_file

        result = engine.recover(self.target_file, pid=None)

        self.assertTrue(result["restored"])
        with open(self.target_file) as f:
            self.assertEqual(f.read(), "clean snapshot content\n")
        # Directory must be unlocked after recovery
        self.assertFalse(engine.is_locked(os.path.dirname(self.target_file)))

    # ------------------------------------------------------------------
    # recover — no snapshot available
    # ------------------------------------------------------------------

    def test_recover_returns_false_when_no_snapshot(self):
        engine = RecoveryEngine()
        engine.snapshot_mgr = MagicMock()
        engine.snapshot_mgr.get_latest_snapshot.return_value = None

        result = engine.recover(self.target_file, pid=None)

        self.assertFalse(result["restored"])
        self.assertFalse(engine.is_locked(os.path.dirname(self.target_file)))

    # ------------------------------------------------------------------
    # recover — copy2 raises; dir must still be unlocked
    # ------------------------------------------------------------------

    def test_recover_unlocks_directory_on_copy_failure(self):
        engine = RecoveryEngine()
        engine.snapshot_mgr = MagicMock()
        engine.snapshot_mgr.get_latest_snapshot.return_value = self.snapshot_file

        with patch("backend.core.recovery.shutil.copy2", side_effect=OSError("disk full")):
            result = engine.recover(self.target_file, pid=None)

        self.assertFalse(result["restored"])
        # The critical guarantee: directory is ALWAYS unlocked
        self.assertFalse(engine.is_locked(os.path.dirname(self.target_file)))

    # ------------------------------------------------------------------
    # recover — process killing (with PID)
    # ------------------------------------------------------------------

    def test_recover_calls_kill_process_when_pid_given(self):
        engine = RecoveryEngine()
        engine.snapshot_mgr = MagicMock()
        engine.snapshot_mgr.get_latest_snapshot.return_value = None

        with patch("backend.core.recovery.ProcessManager.kill_process", return_value=(True, "killed")) as mock_kill:
            result = engine.recover(self.target_file, pid=1234)

        mock_kill.assert_called_once_with(1234)
        self.assertTrue(result["process_killed"])
        self.assertEqual(result["kill_msg"], "killed")

    def test_recover_skips_kill_when_no_pid(self):
        engine = RecoveryEngine()
        engine.snapshot_mgr = MagicMock()
        engine.snapshot_mgr.get_latest_snapshot.return_value = None

        with patch("backend.core.recovery.ProcessManager.kill_process") as mock_kill:
            result = engine.recover(self.target_file, pid=None)

        mock_kill.assert_not_called()
        self.assertIsNone(result["process_killed"])
        self.assertEqual(result["kill_msg"], "No PID provided")


if __name__ == "__main__":
    unittest.main()
