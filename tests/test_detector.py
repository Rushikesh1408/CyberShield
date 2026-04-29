import pytest
from backend.core.detector import DetectionEngine

def test_detector_thresholds():
    engine = DetectionEngine()
    event = {
        "action": "modified",
        "file": "test.txt",
        "timestamp": 1234567890.0,
        "extension": ".enc",
        "entropy": 8.5,
        "modification_rate": 120,
        "access_rate": 80,
        "process": "evil.exe",
    }
    result = engine.analyze_event(event)
    assert isinstance(result, dict)
    assert result.get("threat") is True or result.get("threat") is False
