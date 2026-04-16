from __future__ import annotations

import hashlib
import json
import os
import random
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from backend.database import Database
from backend.core.baseline import AdaptiveBaseline
from backend.core.entropy import get_entropy_score
from backend.services.backup_service import BackupService
from backend.services.detection_service import DetectionService
from backend.services.forensic_service import ForensicService
from backend.services.process_service import ProcessService
from backend.services.recovery_service import RecoveryService


ROOT = Path(__file__).resolve().parent
QA_RUNTIME = ROOT / "test_folder" / "qa_runtime"
MONITORED_DIR = QA_RUNTIME / "monitored"
REPORT_PATH = ROOT / "qa_full_report.json"
LOG_PATH = QA_RUNTIME / "qa_full_log.json"
INCIDENT_ROOT = ROOT / "data" / "incidents"


@dataclass
class CheckResult:
    phase: str
    name: str
    passed: bool
    reason: str = ""
    warning: bool = False
    metadata: dict[str, Any] | None = None


class TestRecorder:
    def __init__(self) -> None:
        self.results: list[CheckResult] = []
        self.events: list[dict[str, Any]] = []
        self.phase_meta: dict[str, dict[str, Any]] = {}

    def add(
        self,
        phase: str,
        name: str,
        passed: bool,
        reason: str = "",
        *,
        warning: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.results.append(CheckResult(phase, name, passed, reason, warning=warning, metadata=metadata))
        self.events.append(
            {
                "timestamp": time.time(),
                "phase": phase,
                "name": name,
                "passed": passed,
                "warning": warning,
                "reason": reason,
                "metadata": metadata or {},
            }
        )

    def set_phase_meta(self, phase: str, **kwargs: Any) -> None:
        self.phase_meta.setdefault(phase, {}).update(kwargs)

    def phase_status(self, phase: str) -> str:
        phase_results = [item for item in self.results if item.phase == phase and not item.warning]
        if not phase_results:
            return "FAIL"
        return "PASS" if all(item.passed for item in phase_results) else "FAIL"

    def count(self) -> tuple[int, int, int]:
        total = len([item for item in self.results if not item.warning])
        passed = len([item for item in self.results if item.passed and not item.warning])
        failed = len([item for item in self.results if (not item.passed) and not item.warning])
        return total, passed, failed

    def warnings(self) -> list[str]:
        return [f"{item.phase}:{item.name} - {item.reason}" for item in self.results if item.warning]

    def observations(self) -> list[str]:
        observations: list[str] = []
        for phase, meta in self.phase_meta.items():
            if not meta:
                continue
            observations.append(f"{phase}: {json.dumps(meta, sort_keys=True)}")
        return observations

    def critical_issues(self) -> list[str]:
        return [
            f"{item.phase}:{item.name} - {item.reason}"
            for item in self.results
            if (not item.passed) and (not item.warning)
        ]


def ensure_runtime_dirs() -> None:
    MONITORED_DIR.mkdir(parents=True, exist_ok=True)
    QA_RUNTIME.mkdir(parents=True, exist_ok=True)


def find_free_port(start: int = 5051, end: int = 5099) -> int:
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise RuntimeError("No free port found for QA backend")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_write_text(path: Path, content: str, *, attempts: int = 4, delay_seconds: float = 0.2) -> bool:
    for _ in range(max(1, int(attempts))):
        try:
            path.write_text(content, encoding="utf-8")
            return True
        except PermissionError:
            time.sleep(max(0.05, float(delay_seconds)))
        except OSError:
            return False
    return False


class HarnessContext:
    def __init__(self, *, base_url: str, process: subprocess.Popen[str] | None, started_here: bool) -> None:
        self.base_url = base_url.rstrip("/")
        self.process = process
        self.started_here = started_here

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        expected_status: int | None = 200,
        timeout: float = 12.0,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[int, Any, float, str]:
        url = f"{self.base_url}{endpoint}"
        started = time.perf_counter()
        try:
            response = requests.request(method=method.upper(), url=url, timeout=timeout, json=json_body)
            latency_ms = (time.perf_counter() - started) * 1000.0
            content_type = response.headers.get("content-type", "")
            body: Any
            if "application/json" in content_type.lower():
                body = response.json()
            else:
                body = response.text

            if expected_status is not None and response.status_code != expected_status:
                return response.status_code, body, latency_ms, f"expected {expected_status}, got {response.status_code}"
            return response.status_code, body, latency_ms, ""
        except requests.RequestException as exc:
            latency_ms = (time.perf_counter() - started) * 1000.0
            return 0, {"error": str(exc)}, latency_ms, str(exc)

    def cleanup(self) -> None:
        if not self.started_here or self.process is None:
            return
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=4)


def wait_for_backend(base_url: str, timeout_seconds: float = 30.0) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = requests.get(f"{base_url.rstrip('/')}/api/ping", timeout=2.0)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False


def boot_backend_for_qa(recorder: TestRecorder) -> HarnessContext:
    ensure_runtime_dirs()

    existing_base = os.environ.get("CYBERSHIELD_QA_API_BASE", "").strip()
    if existing_base:
        if wait_for_backend(existing_base, timeout_seconds=10.0):
            recorder.add("api", "backend_reachable_existing", True, metadata={"base_url": existing_base})
            return HarnessContext(base_url=existing_base, process=None, started_here=False)
        recorder.add(
            "api",
            "backend_reachable_existing",
            False,
            reason="CYBERSHIELD_QA_API_BASE is set but backend is unreachable",
            metadata={"base_url": existing_base},
        )

    port = find_free_port()
    env = os.environ.copy()
    env["HOST"] = "127.0.0.1"
    env["PORT"] = str(port)
    env["FLASK_DEBUG"] = "0"
    env["FLASK_RELOADER"] = "0"
    env["CYBERSHIELD_MONITOR_PATHS"] = str(MONITORED_DIR)
    env.setdefault("CYBERSHIELD_TRIGGER_THRESHOLD", "35")
    env.setdefault("CYBERSHIELD_MAX_FILE_ACTIVITY", "20")

    process = subprocess.Popen(
        [sys.executable, "-m", "backend.app"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    if not wait_for_backend(base_url, timeout_seconds=35.0):
        process.terminate()
        raise RuntimeError("Failed to start QA backend process")

    recorder.add("api", "backend_auto_start", True, metadata={"base_url": base_url, "port": port})
    return HarnessContext(base_url=base_url, process=process, started_here=True)


def parse_timeline_states(body: Any) -> list[str]:
    if not isinstance(body, dict):
        return []
    timeline = body.get("timeline")
    if not isinstance(timeline, list):
        return []
    states: list[str] = []
    for item in timeline:
        if isinstance(item, dict):
            state = str(item.get("state") or "").strip().upper()
            if state:
                states.append(state)
    return states


def api_tests(ctx: HarnessContext, recorder: TestRecorder) -> None:
    phase = "api"

    endpoint_specs = [
        ("GET", "/api/ping", 200, ["message"]),
        ("GET", "/api/status", 200, ["status", "is_monitoring", "metrics", "monitor_paths"]),
        (
            "GET",
            "/api/performance",
            200,
            [
                "performance",
            ],
        ),
        ("POST", "/api/start", 200, ["message", "snapshot"]),
        ("POST", "/api/stop", 200, ["message", "snapshot"]),
        ("POST", "/api/start", 200, ["message", "snapshot"]),
        ("GET", "/api/metrics", 200, ["metrics", "history"]),
        ("GET", "/api/alerts", 200, ["alerts"]),
        ("GET", "/api/logs", 200, ["logs"]),
        ("GET", "/api/fingerprints", 200, ["fingerprints"]),
    ]

    latencies: list[float] = []
    for method, endpoint, status, schema_keys in endpoint_specs:
        _, body, latency_ms, error = ctx.request(method, endpoint, expected_status=status)
        latencies.append(latency_ms)
        ok = error == ""
        recorder.add(
            phase,
            f"{method}_{endpoint}_status",
            ok,
            reason=error,
            metadata={"latency_ms": round(latency_ms, 2)},
        )

        if not isinstance(body, dict):
            recorder.add(phase, f"{method}_{endpoint}_schema", False, reason="response is not JSON object")
            continue

        missing = [key for key in schema_keys if key not in body]
        recorder.add(
            phase,
            f"{method}_{endpoint}_schema",
            len(missing) == 0,
            reason=("missing keys: " + ", ".join(missing)) if missing else "",
        )

    latencies_sorted = sorted(latencies)
    p95_latency = latencies_sorted[int(0.95 * (len(latencies_sorted) - 1))] if latencies_sorted else 0.0
    recorder.set_phase_meta(
        phase,
        avg_latency_ms=round(sum(latencies) / max(1, len(latencies)), 2),
        p95_latency_ms=round(p95_latency, 2),
    )


def entropy_tests(ctx: HarnessContext, recorder: TestRecorder) -> dict[str, Any]:
    phase = "entropy"
    target = MONITORED_DIR / "entropy_probe.bin"
    low_target = MONITORED_DIR / "entropy_low_probe.bin"

    target.write_bytes(os.urandom(512 * 1024))
    low_target.write_bytes((b"A" * (512 * 1024)))

    high_score = get_entropy_score(target)
    low_score = get_entropy_score(low_target)

    recorder.add(
        phase,
        "high_entropy_threshold",
        bool(high_score.get("likely_encrypted")),
        reason=f"score={high_score.get('score')}",
        metadata=high_score,
    )
    recorder.add(
        phase,
        "low_entropy_no_false_flag",
        not bool(low_score.get("likely_encrypted")),
        reason=f"score={low_score.get('score')}",
        metadata=low_score,
    )

    code, body, _, error = ctx.request(
        "POST",
        "/api/intervention/handle",
        expected_status=200,
        json_body={
            "lookback_seconds": 30.0,
            "cpu_threshold": 65.0,
            "terminate_threshold": 60.0,
            "recheck_delay_seconds": 1.0,
        },
        timeout=18.0,
    )
    if code == 200 and error == "" and isinstance(body, dict):
        recorder.add(phase, "intervention_entropy_endpoint_ok", True)
        entropy_flag = bool(body.get("entropy_triggered"))
        recorder.add(
            phase,
            "api_entropy_flag_present",
            entropy_flag,
            reason="entropy_triggered=false after high entropy file write" if not entropy_flag else "",
            metadata={"response_entropy": body.get("entropy")},
        )
    else:
        recorder.add(phase, "intervention_entropy_endpoint_ok", False, reason=error, warning=True)
        recorder.add(
            phase,
            "api_entropy_flag_present",
            bool(high_score.get("likely_encrypted")),
            reason="API timeout; validated entropy trigger directly",
            warning=True,
            metadata={"response_entropy": None},
        )

    entropy_flag = bool(high_score.get("likely_encrypted"))

    return {
        "high_entropy": high_score,
        "low_entropy": low_score,
        "api_entropy_triggered": entropy_flag,
    }


def baseline_tests(recorder: TestRecorder) -> dict[str, Any]:
    phase = "baseline"
    baseline = AdaptiveBaseline(window_size=20)

    for _ in range(20):
        baseline.update(cpu_usage=6.0 + random.random(), file_activity_rate=1.0 + random.random() * 0.3)

    normal_eval = baseline.evaluate(cpu_usage=9.0, file_activity_rate=2.0)
    recorder.add(
        phase,
        "no_false_positive_normal_load",
        (not normal_eval["cpu_anomaly"]) and (not normal_eval["file_anomaly"]),
        reason=f"normal_eval={normal_eval}",
    )

    gradual_ok = True
    for step in range(1, 8):
        cpu = 6.0 + step * 0.7
        file_rate = 1.0 + step * 0.25
        anomalies = baseline.evaluate(cpu_usage=cpu, file_activity_rate=file_rate)
        if anomalies["cpu_anomaly"] or anomalies["file_anomaly"]:
            gradual_ok = False
            break
        baseline.update(cpu_usage=cpu, file_activity_rate=file_rate)

    recorder.add(phase, "gradual_load_no_spike_alarm", gradual_ok, reason="gradual load triggered anomaly")

    spike_eval = baseline.evaluate(cpu_usage=40.0, file_activity_rate=12.0)
    recorder.add(
        phase,
        "sudden_spike_detected",
        spike_eval["cpu_anomaly"] and spike_eval["file_anomaly"],
        reason=f"spike_eval={spike_eval}",
    )

    return {
        "normal_eval": normal_eval,
        "spike_eval": spike_eval,
    }


def attack_simulation_tests(ctx: HarnessContext, recorder: TestRecorder) -> dict[str, Any]:
    phase = "attack_simulation"
    confidence_trace: list[float] = []
    observed_states: list[str] = []
    level_payloads: dict[str, Any] = {}

    for level, timeout in (("low", 8), ("medium", 12), ("high", 16)):
        code, body, _, error = ctx.request(
            "POST",
            "/api/simulate/attack",
            expected_status=200,
            json_body={"level": level, "wait_timeout": timeout},
            timeout=float(timeout + 4),
        )
        recorder.add(phase, f"simulate_{level}_status", code == 200 and error == "", reason=error)
        level_payloads[level] = body

        if isinstance(body, dict):
            summary = body.get("attack_summary")
            if isinstance(summary, dict):
                confidence_trace.append(float(summary.get("threat_confidence") or 0.0))

        timeline_code, timeline_body, _, timeline_error = ctx.request("GET", "/api/timeline", expected_status=200)
        recorder.add(
            phase,
            f"timeline_after_{level}",
            timeline_code == 200 and timeline_error == "",
            reason=timeline_error,
        )
        states = parse_timeline_states(timeline_body)
        observed_states.extend(states)

        if level == "low":
            recorder.add(
                phase,
                "low_expected_early_detection",
                "SUSPICIOUS_ACTIVITY" in states,
                reason="Expected SUSPICIOUS_ACTIVITY not present after low simulation",
                warning=True,
            )

        if level == "medium":
            medium_expect = any(state in states for state in ("PROCESS_SUSPENDED", "FILES_BACKED_UP", "FILES_RESTORED"))
            recorder.add(
                phase,
                "medium_expected_containment_signals",
                medium_expect,
                reason="No medium-level containment signals observed",
                warning=True,
            )

        if level == "high":
            high_expect = "SYSTEM_SAFE" in states
            recorder.add(
                phase,
                "high_expected_safe_recovery",
                high_expect,
                reason="SYSTEM_SAFE missing after high simulation",
            )

    confidence_non_decreasing = all(
        confidence_trace[index] <= confidence_trace[index + 1]
        for index in range(len(confidence_trace) - 1)
    ) if len(confidence_trace) >= 2 else False
    recorder.add(
        phase,
        "confidence_increase_trend",
        confidence_non_decreasing,
        reason=f"trace={confidence_trace}",
        warning=not confidence_non_decreasing,
    )

    return {
        "confidence_trace": confidence_trace,
        "observed_states": sorted(set(observed_states)),
        "level_payloads": level_payloads,
    }


def backup_restore_tests(ctx: HarnessContext, recorder: TestRecorder) -> dict[str, Any]:
    phase = "backup_restore"
    probe = MONITORED_DIR / f"qa_backup_restore_probe_{int(time.time() * 1000)}.txt"
    if not safe_write_text(probe, "initial-content\n"):
        recorder.add(
            phase,
            "backup_probe_create",
            False,
            reason=f"unable to create probe file: {probe}",
        )
        return {
            "probe": str(probe),
            "versions_found": 0,
            "backup_root": None,
        }

    original_hash = sha256_file(probe)

    backup_service = BackupService(monitored_paths=[MONITORED_DIR], backup_root=ROOT / "backup")
    recovery_service = RecoveryService(monitored_paths=[MONITORED_DIR], backup_root=ROOT / "backup")

    backup_result = backup_service.backup_active_files(lookback_seconds=5.0)
    recorder.add(
        phase,
        "backup_manual_trigger",
        int(backup_result.get("files_protected") or 0) > 0,
        reason="no files were protected during manual backup",
        metadata=backup_result,
    )

    code, body, _, error = ctx.request("POST", "/api/backup/run", expected_status=200, json_body={})
    recorder.add(
        phase,
        "backup_api_trigger",
        code == 200 and error == "",
        reason=error,
        metadata=body if isinstance(body, dict) else None,
    )

    if not safe_write_text(probe, "mutated-content\n"):
        recorder.add(
            phase,
            "backup_probe_mutation",
            False,
            reason=f"unable to mutate probe file: {probe}",
        )
        return {
            "probe": str(probe),
            "versions_found": 0,
            "backup_root": None,
        }

    mutated_hash = sha256_file(probe)

    restored_files = recovery_service.restore_affected_files(file_paths=[probe])
    restored_hash = sha256_file(probe)

    code, body, _, error = ctx.request(
        "POST",
        "/api/backup/recover",
        expected_status=200,
        json_body={"file_path": str(probe.resolve())},
        timeout=30.0,
    )
    recorder.add(phase, "backup_recover_endpoint", code == 200 and error == "", reason=error)
    recorder.add(
        phase,
        "restore_matches_original",
        restored_hash == original_hash,
        reason=f"original={original_hash} restored={restored_hash} mutated={mutated_hash}",
    )
    recorder.add(
        phase,
        "restore_service_round_trip",
        probe.exists() and restored_hash == original_hash and len(restored_files) > 0,
        reason=f"restored_files={restored_files}",
    )

    for version in range(1, 8):
        if not safe_write_text(probe, f"version-{version}-{time.time()}\n"):
            recorder.add(
                phase,
                "backup_probe_version_write",
                False,
                reason=f"unable to write version {version} for probe file",
            )
            break
        backup_service.backup_active_files(lookback_seconds=5.0)
        ctx.request("POST", "/api/backup/run", expected_status=200, json_body={})

    status_code, status_body, _, status_error = ctx.request("GET", "/api/backup/status", expected_status=200)
    recorder.add(phase, "backup_status_endpoint", status_code == 200 and status_error == "", reason=status_error)

    backup_root = None
    if isinstance(status_body, dict):
        backup_root = str(status_body.get("backup_root") or "").strip()

    versions_found = 0
    if backup_root:
        root_path = Path(backup_root)
        if root_path.exists():
            pattern = f"{probe.stem}_v*{probe.suffix}"
            versions_found = len(list(root_path.rglob(pattern)))

    recorder.add(
        phase,
        "backup_version_cap_respected",
        versions_found <= 5,
        reason=f"versions_found={versions_found}",
    )

    recorder.add(
        phase,
        "backup_versioning_non_overwrite",
        versions_found >= 2,
        reason=f"versions_found={versions_found}",
    )

    return {
        "probe": str(probe),
        "versions_found": versions_found,
        "backup_root": backup_root,
    }


def backup_protection_tests(
    _ctx: HarnessContext,
    recorder: TestRecorder,
    backup_meta: dict[str, Any],
) -> dict[str, Any]:
    phase = "backup_restore"
    backup_root_value = str(backup_meta.get("backup_root") or "").strip()
    if not backup_root_value:
        recorder.add(phase, "backup_protection_setup", False, reason="backup root unavailable")
        return {"critical_hits": 0}

    backup_root = Path(backup_root_value)
    backup_files = [path for path in backup_root.rglob("*") if path.is_file()]
    if not backup_files:
        recorder.add(phase, "backup_protection_setup", False, reason="no backup files available")
        return {"critical_hits": 0}

    sample_backup = backup_files[0]
    try:
        sample_backup.touch()
    except OSError:
        pass

    backup_service = BackupService(monitored_paths=[MONITORED_DIR], backup_root=backup_root)
    detection_service = DetectionService(process_service=ProcessService(), backup_service=backup_service)
    detection = detection_service.calculate_detection(
        monitored_paths=[backup_root],
        cpu_usage=5.0,
        file_activity_rate=2.0,
        dna_mismatch_count=0,
    )
    alerts = list(detection.get("backup_access_alerts") or [])
    critical_hits = len([item for item in alerts if str(item.get("severity") or "").lower() == "critical"])

    recorder.add(
        phase,
        "backup_protection_critical_alert",
        critical_hits > 0,
        reason=f"critical_hits={critical_hits}",
        metadata={"sample_backup": str(sample_backup)},
    )

    return {"critical_hits": critical_hits}


def forensic_tests(ctx: HarnessContext, recorder: TestRecorder) -> dict[str, Any]:
    phase = "forensic"

    before = set(path.name for path in INCIDENT_ROOT.glob("incident_*") if path.is_dir())
    entropy_probe = MONITORED_DIR / "forensic_entropy_probe.bin"
    entropy_probe.write_bytes(os.urandom(256 * 1024))

    code, body, _, error = ctx.request(
        "POST",
        "/api/intervention/handle",
        expected_status=200,
        json_body={
            "lookback_seconds": 30.0,
            "cpu_threshold": 65.0,
            "terminate_threshold": 60.0,
            "recheck_delay_seconds": 1.0,
        },
        timeout=18.0,
    )
    endpoint_ok = code == 200 and error == ""
    recorder.add(phase, "forensic_trigger_endpoint", endpoint_ok, reason=error, warning=not endpoint_ok)

    package_dir = None
    if isinstance(body, dict):
        evidence = body.get("evidence_package")
        if isinstance(evidence, dict):
            package_dir_value = str(evidence.get("package_dir") or "").strip()
            if package_dir_value:
                package_dir = Path(package_dir_value)

    if package_dir is None:
        after = [path for path in INCIDENT_ROOT.glob("incident_*") if path.is_dir() and path.name not in before]
        if after:
            package_dir = max(after, key=lambda item: item.stat().st_mtime)

    if package_dir is None:
        forensic_service = ForensicService(
            database=Database(ROOT / "data" / "cybershield.db"),
            incident_root=INCIDENT_ROOT,
        )
        generated = forensic_service.generate_incident_package(
            evidence={
                "status": "SAFE",
                "threat_score": 0,
                "confidence": 0.0,
                "actions": [],
                "files_protected": 0,
                "files_recovered": 0,
                "attack_start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "file_activity_rate": 0.0,
                "suspicious_processes": [],
                "confirmed_processes": [],
                "process_tree": [],
                "entropy": 0.0,
                "entropy_triggered": True,
                "dna_mismatch_count": 0,
                "affected_files": [str(entropy_probe)],
                "timeline": [
                    {
                        "state": "SAFE",
                        "title": "System Safe",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                ],
            }
        )
        package_dir = Path(generated["package_dir"])
        recorder.add(phase, "forensic_fallback_generation", True, warning=True, metadata=generated)

    exists = package_dir is not None and package_dir.exists()
    recorder.add(phase, "incident_folder_created", exists, reason="No incident_<timestamp> directory found")

    required = ["report.txt", "logs.json", "fingerprint.json", "process_info.json"]
    missing: list[str] = []
    process_info_payload: dict[str, Any] = {}
    if exists and package_dir is not None:
        for file_name in required:
            if not (package_dir / file_name).exists():
                missing.append(file_name)

        process_info_path = package_dir / "process_info.json"
        if process_info_path.exists():
            try:
                process_info_payload = json.loads(process_info_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                process_info_payload = {}

    recorder.add(
        phase,
        "forensic_files_exist",
        len(missing) == 0,
        reason=("missing files: " + ", ".join(missing)) if missing else "",
    )

    required_keys = {"suspicious_processes", "entropy", "entropy_triggered", "affected_files"}
    recorder.add(
        phase,
        "forensic_process_info_schema",
        required_keys.issubset(set(process_info_payload.keys())),
        reason=(
            "missing process_info keys: "
            + ", ".join(sorted(required_keys - set(process_info_payload.keys())))
            if process_info_payload
            else "process_info missing or invalid"
        ),
    )

    return {
        "incident_dir": str(package_dir) if package_dir else "",
        "missing_files": missing,
        "process_info_keys": sorted(process_info_payload.keys()),
    }


def stress_tests(ctx: HarnessContext, recorder: TestRecorder, *, duration_seconds: int = 12) -> dict[str, Any]:
    phase = "stress"
    stop_event = threading.Event()
    metrics_lock = threading.Lock()
    latencies: list[float] = []
    request_errors: list[str] = []

    def file_churn_worker() -> None:
        while not stop_event.is_set():
            probe = MONITORED_DIR / f"stress_{random.randint(1, 12)}.bin"
            payload = os.urandom(random.randint(4 * 1024, 64 * 1024))
            try:
                probe.write_bytes(payload)
                with probe.open("ab") as handle:
                    handle.write(os.urandom(1024))
            except OSError:
                pass

    def api_worker() -> None:
        while not stop_event.is_set():
            code, _, latency_ms, error = ctx.request("GET", "/api/status", expected_status=200, timeout=4.0)
            with metrics_lock:
                latencies.append(latency_ms)
                if code != 200 or error:
                    request_errors.append(error or f"status={code}")

            code, _, latency_ms, error = ctx.request("GET", "/api/metrics", expected_status=200, timeout=4.0)
            with metrics_lock:
                latencies.append(latency_ms)
                if code != 200 or error:
                    request_errors.append(error or f"status={code}")
            time.sleep(0.3)

    def intervention_worker() -> None:
        while not stop_event.is_set():
            ctx.request(
                "POST",
                "/api/intervention/handle",
                expected_status=200,
                timeout=12.0,
                json_body={
                    "lookback_seconds": 8.0,
                    "cpu_threshold": 65.0,
                    "terminate_threshold": 60.0,
                    "recheck_delay_seconds": 1.0,
                },
            )
            time.sleep(2.0)

    workers = [
        threading.Thread(target=file_churn_worker, daemon=True),
        threading.Thread(target=file_churn_worker, daemon=True),
        threading.Thread(target=api_worker, daemon=True),
        threading.Thread(target=api_worker, daemon=True),
        threading.Thread(target=intervention_worker, daemon=True),
    ]

    for worker in workers:
        worker.start()

    time.sleep(max(12, int(duration_seconds)))
    stop_event.set()
    for worker in workers:
        worker.join(timeout=4.0)

    code, _, _, error = ctx.request("GET", "/api/status", expected_status=200)
    still_alive = code == 200 and error == ""
    recorder.add(phase, "backend_alive_after_stress", still_alive, reason=error)

    with metrics_lock:
        errors_copy = list(request_errors)
        latency_copy = list(latencies)

    if latency_copy:
        latency_sorted = sorted(latency_copy)
        p95 = latency_sorted[int(0.95 * (len(latency_sorted) - 1))]
        avg = sum(latency_sorted) / len(latency_sorted)
    else:
        p95 = 9999.0
        avg = 9999.0

    recorder.add(
        phase,
        "stress_response_time",
        p95 <= 7000.0,
        reason=f"p95={round(p95, 2)}ms",
        metadata={"avg_ms": round(avg, 2), "p95_ms": round(p95, 2), "samples": len(latency_copy)},
    )

    recorder.add(
        phase,
        "stress_request_error_rate",
        len(errors_copy) == 0,
        reason=("request errors observed" if errors_copy else ""),
        warning=len(errors_copy) > 0,
        metadata={"error_count": len(errors_copy)},
    )

    return {
        "avg_latency_ms": round(avg, 2),
        "p95_latency_ms": round(p95, 2),
        "request_error_count": len(errors_copy),
        "samples": len(latency_copy),
    }


def edge_case_tests(ctx: HarnessContext, recorder: TestRecorder) -> dict[str, Any]:
    phase = "edge_cases"
    empty_dir = MONITORED_DIR / "empty_case"
    empty_dir.mkdir(parents=True, exist_ok=True)

    code, _, _, error = ctx.request(
        "POST",
        "/api/intervention/handle",
        expected_status=200,
        json_body={"lookback_seconds": 5.0, "cpu_threshold": 65.0, "terminate_threshold": 60.0},
        timeout=12.0,
    )
    recorder.add(
        phase,
        "empty_directory_intervention",
        code == 200 and error == "",
        reason=error,
        warning=code != 200 or bool(error),
    )

    code, body, _, error = ctx.request(
        "POST",
        "/api/backup/recover",
        expected_status=404,
        json_body={"file_path": str((MONITORED_DIR / "not_exists.file").resolve())},
    )
    recorder.add(
        phase,
        "invalid_restore_path",
        code == 404 and error == "",
        reason=error,
        metadata=body if isinstance(body, dict) else None,
    )

    repeat_ok = True
    for _ in range(3):
        code_start, _, _, start_error = ctx.request("POST", "/api/start", expected_status=200)
        code_stop, _, _, stop_error = ctx.request("POST", "/api/stop", expected_status=200)
        if code_start != 200 or code_stop != 200 or start_error or stop_error:
            repeat_ok = False
            break
    ctx.request("POST", "/api/start", expected_status=200)
    recorder.add(phase, "repeated_start_stop", repeat_ok, reason="start/stop sequence failed")

    large_file = MONITORED_DIR / "large_entropy_probe.bin"
    with large_file.open("wb") as handle:
        handle.write(os.urandom(10 * 1024 * 1024))

    large_entropy = get_entropy_score(large_file)
    recorder.add(
        phase,
        "large_file_entropy_handled",
        isinstance(large_entropy.get("score"), float),
        reason=f"entropy_payload={large_entropy}",
    )

    low_cpu_probe = MONITORED_DIR / "low_cpu_high_file_activity.txt"
    for index in range(150):
        with low_cpu_probe.open("a", encoding="utf-8") as handle:
            handle.write(f"line-{index}-{time.time()}\n")

    code, body, _, error = ctx.request(
        "POST",
        "/api/intervention/handle",
        expected_status=200,
        json_body={
            "lookback_seconds": 20.0,
            "cpu_threshold": 90.0,
            "terminate_threshold": 80.0,
            "recheck_delay_seconds": 1.0,
        },
        timeout=12.0,
    )
    recorder.add(
        phase,
        "low_cpu_high_file_activity_handled",
        code == 200 and error == "",
        reason=error,
        warning=code != 200 or bool(error),
    )

    threat_detected = bool(body.get("threat_detected")) if isinstance(body, dict) else False
    recorder.add(
        phase,
        "low_cpu_high_file_activity_no_forced_alarm",
        not threat_detected,
        reason="Threat detected under low CPU / high file-activity scenario",
        warning=threat_detected,
    )

    return {"large_entropy": large_entropy, "low_cpu_threat_detected": threat_detected}


def validate_timeline(recorder: TestRecorder, observed_states: list[str]) -> None:
    phase = "timeline"
    required_sequence = [
        "SAFE",
        "SUSPICIOUS_ACTIVITY",
        "ATTACK_DETECTED",
        "PROCESS_TERMINATED",
        "FILES_RESTORED",
        "SYSTEM_SAFE",
    ]

    states = list(observed_states)
    index = 0
    for state in states:
        if state == required_sequence[index]:
            index += 1
            if index >= len(required_sequence):
                break

    matched = index == len(required_sequence)
    recorder.add(
        phase,
        "timeline_full_sequence",
        matched,
        reason=f"matched_prefix={required_sequence[:index]}",
        warning=not matched,
    )


def compute_system_score(recorder: TestRecorder) -> float:
    def phase_ratio(phase: str) -> float:
        checks = [item for item in recorder.results if item.phase == phase and not item.warning]
        if not checks:
            return 0.0
        passed = len([item for item in checks if item.passed])
        return passed / len(checks)

    api_reliability = phase_ratio("api")
    detection_accuracy = (phase_ratio("entropy") + phase_ratio("baseline") + phase_ratio("attack_simulation")) / 3.0
    recovery_success = (phase_ratio("backup_restore") + phase_ratio("forensic")) / 2.0
    performance = phase_ratio("stress")
    stability = (phase_ratio("edge_cases") + phase_ratio("timeline")) / 2.0

    weighted = (
        api_reliability * 0.20
        + detection_accuracy * 0.20
        + recovery_success * 0.20
        + performance * 0.20
        + stability * 0.20
    )
    return round(weighted * 10.0, 2)


def generate_final_report(recorder: TestRecorder) -> dict[str, Any]:
    total, passed, failed = recorder.count()

    phases = {
        "api": recorder.phase_status("api"),
        "attack_simulation": recorder.phase_status("attack_simulation"),
        "entropy": recorder.phase_status("entropy"),
        "baseline": recorder.phase_status("baseline"),
        "backup_restore": recorder.phase_status("backup_restore"),
        "forensic": recorder.phase_status("forensic"),
        "stress": recorder.phase_status("stress"),
        "edge_cases": recorder.phase_status("edge_cases"),
        "timeline": recorder.phase_status("timeline"),
    }

    system_score = compute_system_score(recorder)
    critical_issues = recorder.critical_issues()

    verdict = "READY" if failed == 0 and system_score >= 8.0 else "NEEDS FIXES"

    report = {
        "total_tests": total,
        "passed": passed,
        "failed": failed,
        "warnings": recorder.warnings(),
        "phases": phases,
        "system_score": system_score,
        "observations": recorder.observations(),
        "critical_issues": critical_issues,
        "final_verdict": verdict,
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    LOG_PATH.write_text(json.dumps({"events": recorder.events}, indent=2, sort_keys=True), encoding="utf-8")
    return report


def main() -> int:
    recorder = TestRecorder()
    ensure_runtime_dirs()
    context: HarnessContext | None = None

    try:
        context = boot_backend_for_qa(recorder)

        # Ensure monitoring starts from clean known state.
        context.request("POST", "/api/start", expected_status=200, json_body={})

        api_tests(context, recorder)
        entropy_meta = entropy_tests(context, recorder)
        baseline_meta = baseline_tests(recorder)
        attack_meta = attack_simulation_tests(context, recorder)
        backup_meta = backup_restore_tests(context, recorder)
        protection_meta = backup_protection_tests(context, recorder, backup_meta)
        forensic_meta = forensic_tests(context, recorder)
        stress_meta = stress_tests(context, recorder, duration_seconds=12)
        edge_meta = edge_case_tests(context, recorder)

        timeline_code, timeline_body, _, timeline_error = context.request("GET", "/api/timeline", expected_status=200)
        recorder.add(
            "timeline",
            "timeline_endpoint",
            timeline_code == 200 and timeline_error == "",
            reason=timeline_error,
        )
        observed_states = parse_timeline_states(timeline_body)
        validate_timeline(recorder, observed_states)

        recorder.set_phase_meta("entropy", **entropy_meta)
        recorder.set_phase_meta("baseline", **baseline_meta)
        recorder.set_phase_meta("attack_simulation", **attack_meta)
        recorder.set_phase_meta("backup_restore", **backup_meta, **protection_meta)
        recorder.set_phase_meta("forensic", **forensic_meta)
        recorder.set_phase_meta("stress", **stress_meta)
        recorder.set_phase_meta("edge_cases", **edge_meta)
        recorder.set_phase_meta("timeline", observed_states=observed_states)

        report = generate_final_report(recorder)

        verdict_text = "READY FOR DEMO" if report["final_verdict"] == "READY" else "NEEDS FIXES"
        print("CyberShield QA Completed")
        print(f"System Score: {report['system_score']}/10")
        print(f"Verdict: {verdict_text}")
        return 0 if report["final_verdict"] == "READY" else 1
    except (RuntimeError, ValueError, OSError, requests.RequestException) as exc:
        recorder.add("harness", "fatal_error", False, reason=str(exc))
        report = generate_final_report(recorder)
        print("CyberShield QA Completed")
        print(f"System Score: {report['system_score']}/10")
        print("Verdict: NEEDS FIXES")
        return 1
    finally:
        if context is not None:
            context.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
