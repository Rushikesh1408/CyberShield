import pytest
from backend.core.explainer import explain_event

def test_explainer_human_log():
    event = {
        "action": "mass_rename",
        "count": 150,
        "duration": 2,
        "result": "ransomware pattern detected",
        "process": "malware.exe"
    }
    log = explain_event(event)
    assert isinstance(log, str)
    assert "ransomware pattern detected" in log
