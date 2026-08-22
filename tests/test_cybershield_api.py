from __future__ import annotations

from pathlib import Path

from backend import api as backend_api


class _FakeDatabase:
    def fetch_logs(self, limit: int = 100):
        return [{"event": "attack_detected", "timestamp": "2026-04-16T00:00:00Z"}]

    def fetch_alerts(self, limit: int = 50):
        return [{"title": "Test Alert", "severity": "high"}]

    def fetch_fingerprints(self):
        return [{"signature_hash": "sig-123", "process_name": "ransom.exe"}]


class _FakeController:
    def __init__(self, report_path: Path) -> None:
        self.database = _FakeDatabase()
        self._report_path = report_path

    def restart(self):
        return {"status": "SAFE", "confidence": 0}

    def stop(self):
        return {"status": "SAFE", "confidence": 0}

    def timeline(self):
        return [{"state": "SAFE", "title": "System Safe", "description": "ok", "severity": "safe", "timestamp": ""}]

    def network_activity(self):
        return {"events": [{"pid": 1, "remote_ip": "10.0.0.5", "remote_port": 443, "status": "ESTABLISHED", "protocol": "tcp"}], "recent": [], "count": 1}

    def signature_intelligence(self):
        return {"latest": {"signature_id": "sig-123"}, "correlation": {"matched": True, "matches": []}, "history": [{"signature_id": "sig-123"}]}

    def forensic_report_summary(self):
        return {
            "latest": {"incident_id": "incident-1"},
            "reports": [{"incident_id": "incident-1"}],
            "wallets": [{"wallet_type": "btc", "wallet_address": "bc1qexample"}],
            "persistence": [],
            "process_tree": [],
            "entry_point": {},
        }

    def get_attack_report_path(self) -> Path:
        return self._report_path


def test_api_smoke_endpoints(tmp_path, monkeypatch):
    report_path = tmp_path / "attack_report.txt"
    report_path.write_text("CyberShield report", encoding="utf-8")

    stub_controller = _FakeController(report_path)
    monkeypatch.setattr(backend_api, "_controller_from_app", lambda flask_app: stub_controller)

    app = backend_api.create_app()
    client = app.test_client()

    response = client.get("/api/network")
    assert response.status_code == 200
    assert response.get_json()["count"] == 1

    response = client.get("/api/signature")
    assert response.status_code == 200
    assert response.get_json()["latest"]["signature_id"] == "sig-123"

    response = client.get("/api/report?format=json")
    assert response.status_code == 200
    assert response.get_json()["latest"]["incident_id"] == "incident-1"

    response = client.get("/api/report/download")
    assert response.status_code == 200
    assert response.headers["Content-Disposition"].startswith("attachment;")

    response = client.post("/api/start")
    assert response.status_code == 200
    assert response.get_json()["message"] == "monitoring_started"

    response = client.post("/api/stop")
    assert response.status_code == 200
    assert response.get_json()["message"] == "monitoring_stopped"

    response = client.get("/api/logs")
    assert response.status_code == 200
    assert response.get_json()["logs"][0]["event"] == "attack_detected"

    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert response.get_json()["alerts"][0]["title"] == "Test Alert"

    response = client.get("/api/fingerprints")
    assert response.status_code == 200
    assert response.get_json()["fingerprints"][0]["signature_hash"] == "sig-123"

    response = client.get("/api/timeline")
    assert response.status_code == 200
    assert response.get_json()["timeline"][0]["state"] == "SAFE"
