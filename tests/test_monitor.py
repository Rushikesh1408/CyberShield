import pytest
from backend.core.monitor import RealTimeMonitor

def test_monitor_init():
    monitor = RealTimeMonitor(watch_paths=["/tmp"])
    assert monitor is not None
    assert hasattr(monitor, "start")
    assert hasattr(monitor, "stop")
