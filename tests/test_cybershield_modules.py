from __future__ import annotations

from pathlib import Path

from backend.modules import (
    AttackSignatureEngine,
    CorrelationEngine,
    EvidenceReportGenerator,
    HoneypotManager,
    NetworkTracker,
    PersistenceDetector,
    ProcessTreeTracker,
    TimelineEngine,
    WalletTracker,
)


class _FakeProcess:
    def __init__(self, pid: int, ppid: int, name: str, path: str, cmdline: str, created_at: float = 1_700_000_000.0) -> None:
        self.pid = pid
        self._ppid = ppid
        self._name = name
        self._path = path
        self._cmdline = cmdline
        self._created_at = created_at

    def create_time(self) -> float:
        return self._created_at

    def ppid(self) -> int:
        return self._ppid

    def net_connections(self, kind: str = "inet"):
        return [
            type(
                "Conn",
                (),
                {
                    "raddr": type("Addr", (), {"ip": "10.0.0.5", "port": 443})(),
                    "laddr": type("Addr", (), {"ip": "192.168.1.2", "port": 51000})(),
                    "status": "ESTABLISHED",
                    "type": 1,
                },
            )()
        ]


class _FakeProcessService:
    def __init__(self) -> None:
        self.processes = {
            2: _FakeProcess(2, 1, "child.exe", "C:/Users/User/AppData/Local/child.exe", "child.exe --run"),
            1: _FakeProcess(1, 0, "parent.exe", "C:/Windows/System32/parent.exe", "parent.exe"),
        }

    def get_process(self, pid: int):
        return self.processes.get(pid)

    def safe_name(self, process) -> str:
        return getattr(process, "_name", "") or (process.name() if hasattr(process, "name") else "")

    def safe_exe(self, process) -> str:
        return getattr(process, "_path", "")

    def safe_cmdline(self, process) -> str:
        return getattr(process, "_cmdline", "") or (" ".join(process.cmdline()) if hasattr(process, "cmdline") else "")

    def safe_parent_pid(self, process) -> int:
        return int(getattr(process, "_ppid", 0) or (process.ppid() if hasattr(process, "ppid") else 0))

    def detect_suspicious_processes(self, **kwargs):
        return [
            {
                "pid": 2,
                "name": "child.exe",
                "path": "C:/Users/User/AppData/Local/child.exe",
                "cpu": 89.5,
                "score": 82.0,
            }
        ]


def test_attack_signature_and_correlation_round_trip():
    signature = AttackSignatureEngine().generate(
        entropy=7.61,
        file_rate=44.2,
        process_name="ransom.exe",
        timing_ms=181.4,
        cpu_usage=93.2,
        confidence=88.0,
    )

    correlation = CorrelationEngine().correlate(
        incoming_signature=signature,
        known_signatures=[{**signature, "occurrences": 3}],
    )

    assert signature["signature_id"]
    assert correlation["matched"] is True
    assert correlation["matches"][0]["signature_id"] == signature["signature_id"]


def test_wallet_tracker_extracts_btc_and_eth():
    wallets = WalletTracker().extract_wallets_from_text(
        "pay to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh or 0x0123456789abcdef0123456789abcdef01234567"
    )

    assert {wallet["type"] for wallet in wallets} == {"btc", "eth"}


def test_process_tree_network_and_timeline_modules(tmp_path):
    service = _FakeProcessService()

    tree = ProcessTreeTracker(service).track_chain(2)
    entry = ProcessTreeTracker(service).entry_point(2)
    network_events = NetworkTracker(service).capture_process_connections(2)
    timeline = TimelineEngine()
    timeline.record(state="SUSPICIOUS", title="Suspicious", details="Detected", severity="warning")

    report = EvidenceReportGenerator(tmp_path / "incidents").generate(
        {
            "incident_id": "incident-001",
            "status": "UNDER_ATTACK",
            "severity": "critical",
            "signature": {"signature_id": "sig-001"},
            "wallets": [{"type": "btc", "address": "bc1qexample"}],
            "correlation": {"matched": False, "matches": []},
            "entry_point": entry,
            "process_tree": tree,
            "network_logs": network_events,
            "timeline": timeline.snapshot(),
            "logs": [{"event": "attack_detected"}],
        }
    )

    assert tree[0]["pid"] == 2
    assert entry["entry_pid"] == 1
    assert network_events[0]["remote_ip"] == "10.0.0.5"
    assert Path(report["report_path"]).exists()


def test_honeypot_and_persistence_modules(tmp_path, monkeypatch):
    root = tmp_path / "protected"
    startup = tmp_path / "AppData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    root.mkdir(parents=True)
    startup.mkdir(parents=True)
    (startup / "launch.vbs").write_text("WScript.Echo \"hi\"", encoding="utf-8")

    honeypot = HoneypotManager([root])
    created = honeypot.seed_default_decoys()
    assert any("admin.db" in item for item in created)

    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
    detector = PersistenceDetector(_FakeProcessService())
    findings = detector.detect()

    assert any(finding["finding_type"] == "startup_entry" for finding in findings)
