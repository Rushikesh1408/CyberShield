import pytest
from backend.core.pipeline import CyberShieldPipeline

def test_pipeline_start_stop():
    pipeline = CyberShieldPipeline()
    assert pipeline.start() is True
    assert pipeline.stop() is True

def test_pipeline_status():
    pipeline = CyberShieldPipeline()
    pipeline.start()
    status = pipeline.status()
    assert isinstance(status, dict)
    assert "threat" in status
    pipeline.stop()
