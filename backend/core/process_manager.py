"""
Production-grade process manager for CyberShield.
Safely terminates suspicious processes, avoids system-critical processes.
"""
import psutil
import os

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
            username = proc.username()
            if username is not None:
                uname = username.upper()
                # Unix root or Windows SYSTEM (domain-qualified)
                if uname == 'ROOT' or uname == 'SYSTEM' or uname.endswith('\\SYSTEM'):
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
            return True, f"Process {pid} terminated"
        except Exception as e:
            return False, str(e)
