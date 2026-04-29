"""
Production-grade process manager for CyberShield.
Safely terminates suspicious processes, avoids system-critical processes.
"""
import psutil
import os
import logging

logger = logging.getLogger("cybershield.process_manager")

SYSTEM_CRITICAL = {0, 1, 2, 3, 4}  # System PIDs (init, system, etc.)
SYSTEM_NAMES = {'System', 'init', 'systemd', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe'}

class ProcessManager:
    @staticmethod
    def is_critical_process(proc):
        try:
            if proc.pid in SYSTEM_CRITICAL:
                return True
            name = proc.name().lower()
            if name in (n.lower() for n in SYSTEM_NAMES):
                return True
            username = proc.username() or ""
            username_upper = username.upper()
            # Match Unix 'root', Windows 'SYSTEM' and domain-qualified 'NT AUTHORITY\SYSTEM'
            if username_upper in ("ROOT", "SYSTEM") or username_upper.endswith("\\SYSTEM"):
                return True
            return False
        except Exception:
            return True  # If in doubt, do not kill

    @staticmethod
    def kill_process(pid):
        try:
            proc = psutil.Process(pid)
            if ProcessManager.is_critical_process(proc):
                return False, "Refused to kill system-critical process"
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
                # Verify the process actually exited after kill()
                try:
                    proc.wait(timeout=2)
                except psutil.TimeoutExpired:
                    logger.error(f"Process {pid} still alive after kill() — may require manual intervention.")
                    return False, f"Process {pid} did not exit after SIGKILL"
            return True, f"Process {pid} terminated"
        except Exception as e:
            return False, str(e)
