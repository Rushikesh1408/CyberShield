import pytest
from backend.core.process_manager import ProcessManager

def test_process_manager_safe_kill():
    manager = ProcessManager()
    # Simulate a non-critical process (do not actually kill)
    assert manager.is_critical_process("notepad.exe") is False
    # Simulate a critical process
    assert manager.is_critical_process("system") is True
