import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"

def test_status():
    resp = client.get("/api/status")
    assert resp.status_code == 200
    assert "threat" in resp.json()
