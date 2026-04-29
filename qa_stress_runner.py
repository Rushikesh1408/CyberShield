from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Any

import requests

try:
    import socketio
except ImportError as exc:  # pragma: no cover - dependency/runtime guard
    raise SystemExit(
        "python-socketio is required for qa_stress_runner.py. "
        "Install dependencies with: pip install -r requirements.txt"
    ) from exc


ROOT = Path(__file__).resolve().parent
SIMULATOR_SCRIPT = ROOT / "test_folder" / "demo_attack_simulator.py"
RUNTIME_ROOT = ROOT / "test_folder" / "qa_runtime"
STRESS_TARGET = RUNTIME_ROOT / "e2e_stress_target"
FINAL_REPORT_PATH = ROOT / "final_qa_stress_report.json"
TIMELINE_PATH = ROOT / "qa_stress_timeline.json"
LOG_PATH = ROOT / "qa_stress_log.json"
SOCKET_EVENT_NAME = "cybershield_event"
SOCKET_EVENT_ACK_NAME = "cybershield_event_ack"


@dataclass
class ProcessHandle:
    name: str
    process: subprocess.Popen[str] | None
    started_here: bool


@dataclass
class RunnerState:
    events: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    logs: list[dict[str, Any]] = field(default_factory=list)
    crashes: int = 0
    disconnects: int = 0
    reconnections: int = 0
    missed_events: int = 0
    propagation_delays_ms: list[float] = field(default_factory=list)
    baseline_latency_ms: float = 0.0
    detection_latency_ms: float | None = None
    backend_running: bool = False
    frontend_running: bool = False
    health_snapshot: dict[str, Any] = field(default_factory=dict)
    expected_events_seen: set[str] = field(default_factory=set)


class StressRunner:
    def __init__(
        self,
        *,
        host_ip: str,
        backend_port: int,
        frontend_port: int,
        socket_api_key: str,
        run_mobile_socket: bool,
        keep_processes: bool,
    ) -> None:
        self.host_ip = host_ip
        self.backend_port = backend_port
        self.frontend_port = frontend_port
        self.socket_api_key = socket_api_key
        self.run_mobile_socket = run_mobile_socket
        self.keep_processes = keep_processes

        self.backend_url = f"http://127.0.0.1:{backend_port}"
        self.backend_lan_url = f"http://{host_ip}:{backend_port}"
        self.frontend_local_url = f"http://localhost:{frontend_port}"
        self.frontend_lan_url = f"http://{host_ip}:{frontend_port}"

        self.backend_handle = ProcessHandle("backend", None, False)
        self.frontend_handle = ProcessHandle("frontend", None, False)
        self.socket_client: socketio.Client | None = None
        self.state = RunnerState()
        self._planned_disconnect = False

    def log(self, level: str, message: str, **data: Any) -> None:
        entry = {
            "timestamp": time.time(),
            "level": level.upper(),
            "message": message,
            "data": data,
        }
        self.state.logs.append(entry)
        print(f"[{entry['level']}] {message}")

    def add_timeline(self, phase: str, name: str, **data: Any) -> None:
        self.state.timeline.append(
            {
                "timestamp": time.time(),
                "phase": phase,
                "name": name,
                "data": data,
            }
        )

    def request_json(self, endpoint: str, timeout: float = 6.0) -> tuple[bool, dict[str, Any], float]:
        url = f"{self.backend_url}{endpoint}"
        started = time.perf_counter()
        try:
            response = requests.get(url, timeout=timeout)
            latency_ms = (time.perf_counter() - started) * 1000.0
            if response.status_code != 200:
                return False, {"status_code": response.status_code, "text": response.text}, latency_ms
            payload = response.json()
            if not isinstance(payload, dict):
                return False, {"error": "non-dict JSON response"}, latency_ms
            return True, payload, latency_ms
        except requests.RequestException as exc:
            latency_ms = (time.perf_counter() - started) * 1000.0
            return False, {"error": str(exc)}, latency_ms

    def url_is_up(self, url: str, timeout: float = 2.5) -> bool:
        try:
            response = requests.get(url, timeout=timeout)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def find_python_exe(self) -> str:
        venv_python = ROOT / ".venv" / "Scripts" / "python.exe"
        if venv_python.exists():
            return str(venv_python)
        return sys.executable

    def resolve_frontend_root(self) -> Path:
        local_frontend = ROOT / "frontend"
        sibling_frontend = ROOT.parent.parent / "Cybersheildapp" / "cybershield-command-center" / "frontend"
        if local_frontend.exists():
            return local_frontend
        if sibling_frontend.exists():
            return sibling_frontend
        raise RuntimeError(
            "Frontend folder not found. Expected one of: "
            f"{local_frontend} or {sibling_frontend}"
        )

    def is_port_in_use(self, host: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            return sock.connect_ex((host, port)) == 0

    def wait_for_backend(self, timeout_seconds: float = 40.0) -> bool:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            ok, payload, _lat = self.request_json("/api/realtime/health", timeout=2.0)
            if ok and payload.get("socket_active") is True:
                return True
            time.sleep(0.5)
        return False

    def wait_for_frontend(self, timeout_seconds: float = 35.0) -> bool:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if self.url_is_up(self.frontend_local_url, timeout=2.0) or self.url_is_up(self.frontend_lan_url, timeout=2.0):
                return True
            time.sleep(0.5)
        return False

    def start_backend_if_needed(self) -> None:
        ok, _payload, _lat = self.request_json("/api/realtime/health", timeout=2.0)
        if ok:
            self.log("info", "Backend already running")
            self.state.backend_running = True
            return

        python_exe = self.find_python_exe()
        env = os.environ.copy()
        env["HOST"] = "0.0.0.0"
        env["PORT"] = str(self.backend_port)
        env["FLASK_DEBUG"] = "0"
        env["FLASK_RELOADER"] = "0"
        env["CYBERSHIELD_SOCKET_API_KEY"] = self.socket_api_key
        env["CYBERSHIELD_MONITOR_PATHS"] = str(STRESS_TARGET)

        if self.is_port_in_use("127.0.0.1", self.backend_port):
            raise RuntimeError(
                f"Backend port {self.backend_port} is already in use but /api/realtime/health is not reachable"
            )

        self.log("info", "Starting backend process")
        proc = subprocess.Popen(
            [python_exe, "-m", "backend.app"],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.backend_handle = ProcessHandle("backend", proc, True)

        if not self.wait_for_backend():
            self.state.crashes += 1
            raise RuntimeError("Backend failed to start within timeout")

        self.state.backend_running = True
        self.add_timeline("startup", "backend_started", pid=proc.pid)

    def start_frontend_if_needed(self) -> None:
        if self.url_is_up(self.frontend_local_url) or self.url_is_up(self.frontend_lan_url):
            self.log("info", "Frontend already running")
            self.state.frontend_running = True
            return

        frontend_root = self.resolve_frontend_root()
        env = os.environ.copy()
        env["VITE_CYBERSHIELD_SOCKET_URL"] = self.backend_lan_url
        env["VITE_CYBERSHIELD_SOCKET_API_KEY"] = self.socket_api_key
        env.setdefault("VITE_REALTIME_HEALTH_POLL_MS", "3000")

        if self.is_port_in_use("127.0.0.1", self.frontend_port):
            raise RuntimeError(
                f"Frontend port {self.frontend_port} is already in use but app URL is not reachable"
            )

        npm_exe = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm_exe:
            raise RuntimeError("npm executable not found in PATH")

        self.log("info", "Starting frontend process")
        proc = subprocess.Popen(
            [npm_exe, "run", "dev", "--", "--host", "0.0.0.0", "--port", str(self.frontend_port)],
            cwd=str(frontend_root),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            shell=False,
        )
        self.frontend_handle = ProcessHandle("frontend", proc, True)

        if not self.wait_for_frontend():
            self.state.crashes += 1
            raise RuntimeError("Frontend failed to start within timeout")

        self.state.frontend_running = True
        self.add_timeline("startup", "frontend_started", pid=proc.pid)

    def connect_socket_probe(self) -> None:
        if not self.run_mobile_socket:
            self.log("info", "Mobile socket probe disabled")
            return

        self.log("info", "Connecting Socket.IO probe client")
        client = socketio.Client(
            reconnection=True,
            reconnection_attempts=10,
            reconnection_delay=1.0,
            request_timeout=20.0,
        )

        @client.event
        def connect() -> None:
            self.add_timeline("socket", "connected", sid=client.sid)

        @client.event
        def disconnect() -> None:
            if not self._planned_disconnect:
                self.state.disconnects += 1
            self.add_timeline("socket", "disconnected")

        @client.event
        def connect_error(data: Any) -> None:
            self.add_timeline("socket", "connect_error", error=str(data))

        @client.event
        def reconnect() -> None:
            self.state.reconnections += 1
            self.add_timeline("socket", "reconnected")

        @client.on(SOCKET_EVENT_NAME)
        def on_cybershield_event(data: Any) -> None:
            if not isinstance(data, dict):
                return
            event_type = str(data.get("type") or "UNKNOWN")
            payload_ts = float(data.get("timestamp") or 0.0)
            received_wall = time.time()
            delay_ms = None
            if payload_ts > 0:
                delay_ms = max(0.0, (received_wall - payload_ts) * 1000.0)
                self.state.propagation_delays_ms.append(delay_ms)

            event_id = str(data.get("event_id") or "").strip()
            if event_id:
                client.emit(
                    SOCKET_EVENT_ACK_NAME,
                    {
                        "event_id": event_id,
                        "client": "qa-mobile-probe",
                        "received_at": received_wall,
                    },
                )

            if event_type in {"ATTACK_DETECTED", "FILES_RESTORED", "SYSTEM_SAFE"}:
                self.state.expected_events_seen.add(event_type)

            self.state.events.append(
                {
                    "received_at": received_wall,
                    "event_type": event_type,
                    "payload_timestamp": payload_ts,
                    "event_delay_ms": delay_ms,
                    "data": data.get("data", {}),
                }
            )
            self.add_timeline("socket", "event_received", event_type=event_type, delay_ms=delay_ms)

        client.connect(
            self.backend_url,
            transports=["websocket"],
            auth={"apiKey": self.socket_api_key},
            wait_timeout=10,
        )
        self.socket_client = client

    def phase_system_health(self) -> None:
        phase = "PHASE_1_SYSTEM_HEALTH"
        self.log("info", "Running Phase 1: system health check")

        ok, payload, latency_ms = self.request_json("/api/realtime/health")
        self.state.health_snapshot = payload if ok else {}
        self.add_timeline(phase, "health_polled", ok=ok, latency_ms=latency_ms, payload=payload)

        if not ok:
            raise RuntimeError(f"Health endpoint failed: {payload}")
        if payload.get("socket_active") is not True:
            raise RuntimeError("socket_active is not true")
        if str(payload.get("status") or "").lower() != "healthy":
            raise RuntimeError("health status is not healthy")

        # Wait briefly for client count to reflect probe connection.
        deadline = time.time() + 6.0
        clients = int(payload.get("connected_clients") or 0)
        while clients < 1 and time.time() < deadline:
            time.sleep(0.5)
            ok, payload, _lat = self.request_json("/api/realtime/health")
            if not ok:
                break
            clients = int(payload.get("connected_clients") or 0)

        if clients < 1:
            raise RuntimeError("connected_clients < 1; websocket probe was not observed")

        self.add_timeline(phase, "health_validated", connected_clients=clients)

    def phase_baseline_performance(self) -> None:
        phase = "PHASE_2_BASELINE_PERFORMANCE"
        self.log("info", "Running Phase 2: baseline latency measurement")
        latencies: list[float] = []

        for _ in range(8):
            ok, _payload, latency_ms = self.request_json("/api/realtime/health")
            if ok:
                latencies.append(latency_ms)
            time.sleep(0.15)

        if not latencies:
            raise RuntimeError("Could not collect baseline latency samples")

        self.state.baseline_latency_ms = mean(latencies)
        self.add_timeline(phase, "baseline_measured", samples=len(latencies), latency_ms=self.state.baseline_latency_ms)

    def run_simulator(self, level: str, target: Path) -> subprocess.CompletedProcess[str]:
        python_exe = self.find_python_exe()
        cmd = [python_exe, str(SIMULATOR_SCRIPT), level, "--target", str(target), "--api-base", self.backend_url]
        self.log("info", f"Running simulator level={level}")
        result = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=420)
        if result.returncode == 0:
            return result

        # One retry for transient backend resets under load.
        self.log("warn", f"Simulator {level} failed once; retrying")
        time.sleep(1.0)
        return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=420)

    def run_high_simulator_with_status_probe(self, target: Path) -> tuple[subprocess.CompletedProcess[str], float | None]:
        python_exe = self.find_python_exe()
        cmd = [python_exe, str(SIMULATOR_SCRIPT), "high", "--target", str(target), "--api-base", self.backend_url]
        self.log("info", "Running simulator level=high")

        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        first_under_attack_ts: float | None = None
        try:
            while proc.poll() is None:
                if first_under_attack_ts is None:
                    ok, payload, _lat = self.request_json("/api/status", timeout=2.0)
                    if ok:
                        status = str(payload.get("status") or "").upper()
                        if status in {"ATTACK", "UNDER_ATTACK", "CRITICAL"}:
                            first_under_attack_ts = time.time()
                time.sleep(0.2)

            stdout, stderr = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=10)

        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=int(proc.returncode or 0),
            stdout=stdout,
            stderr=stderr,
        )
        return result, first_under_attack_ts

    def phase_attack_simulation(self) -> float:
        phase = "PHASE_3_ATTACK_SIMULATION"
        self.log("info", "Running Phase 3: attack simulation")
        STRESS_TARGET.mkdir(parents=True, exist_ok=True)

        setup_res = self.run_simulator("setup", STRESS_TARGET)
        if setup_res.returncode != 0:
            raise RuntimeError(f"Simulator setup failed: {setup_res.stderr or setup_res.stdout}")
        self.add_timeline(phase, "simulator_setup_done")

        attack_start_monotonic = time.perf_counter()
        attack_start_wall = time.time()
        attack_res, first_under_attack_ts = self.run_high_simulator_with_status_probe(STRESS_TARGET)
        if attack_res.returncode != 0:
            self.log("warn", "Simulator high failed once; retrying")
            attack_res, first_under_attack_ts = self.run_high_simulator_with_status_probe(STRESS_TARGET)
        if attack_res.returncode != 0:
            self.state.crashes += 1
            raise RuntimeError(f"Simulator high failed: {attack_res.stderr or attack_res.stdout}")

        # Wait briefly for ATTACK_DETECTED to arrive to avoid undercounting delayed events.
        deadline = time.time() + 20.0
        detected_event = next(
            (
                e
                for e in self.state.events
                if e.get("event_type") == "ATTACK_DETECTED" and not bool((e.get("data") or {}).get("selftest"))
            ),
            None,
        )
        while detected_event is None and time.time() < deadline:
            time.sleep(0.2)
            detected_event = next(
                (
                    e
                    for e in self.state.events
                    if e.get("event_type") == "ATTACK_DETECTED" and not bool((e.get("data") or {}).get("selftest"))
                ),
                None,
            )

        # Estimate detection latency using first ATTACK_DETECTED receive time.
        if detected_event is not None:
            detected_at = float(detected_event["received_at"])
            self.state.detection_latency_ms = max(0.0, (detected_at - attack_start_wall) * 1000.0)
        elif first_under_attack_ts is not None:
            self.state.detection_latency_ms = max(0.0, (first_under_attack_ts - attack_start_wall) * 1000.0)
        else:
            self.state.missed_events += 1
            self.state.detection_latency_ms = None

        elapsed_ms = (time.perf_counter() - attack_start_monotonic) * 1000.0
        self.add_timeline(
            phase,
            "attack_complete",
            runtime_ms=elapsed_ms,
            detection_latency_ms=self.state.detection_latency_ms,
            simulator_stdout=attack_res.stdout[-1000:],
        )
        return attack_start_wall

    def phase_realtime_sync(self) -> None:
        phase = "PHASE_4_REALTIME_SYNC"
        self.log("info", "Running Phase 4: realtime sync assertions")

        try:
            response = requests.post(
                f"{self.backend_url}/api/realtime/selftest",
                json={"source": "qa_stress_runner"},
                timeout=8.0,
            )
            if response.status_code != 200:
                self.log("warn", f"Realtime selftest endpoint returned {response.status_code}")
        except requests.RequestException as exc:
            self.log("warn", f"Realtime selftest call failed: {exc}")

        expected = {"ATTACK_DETECTED", "FILES_RESTORED", "SYSTEM_SAFE"}
        wait_deadline = time.time() + 12.0
        while time.time() < wait_deadline and not expected.issubset(self.state.expected_events_seen):
            time.sleep(0.2)

        seen = set(self.state.expected_events_seen)
        missing = sorted(expected - seen)
        self.state.missed_events += len(missing)

        self.add_timeline(
            phase,
            "sync_checked",
            expected=sorted(expected),
            seen=sorted(seen),
            missing=missing,
            propagation_samples=len(self.state.propagation_delays_ms),
        )

    def phase_stress_load(self) -> None:
        phase = "PHASE_5_STRESS_LOAD"
        self.log("info", "Running Phase 5: stress load")
        STRESS_TARGET.mkdir(parents=True, exist_ok=True)

        started = time.time()
        writes = 0
        health_failures = 0

        while time.time() - started < 8.0:
            idx = int((time.time() - started) * 100)
            probe = STRESS_TARGET / f"stress_probe_{idx}.tmp"
            try:
                probe.write_text(f"stress {time.time()}\n", encoding="utf-8")
                with probe.open("a", encoding="utf-8") as handle:
                    handle.write("burst\n")
                probe.unlink(missing_ok=True)
                writes += 3
            except OSError:
                health_failures += 1

            ok, payload, _lat = self.request_json("/api/realtime/health", timeout=2.0)
            if (not ok) or (payload.get("socket_active") is not True):
                health_failures += 1
            time.sleep(0.05)

        if health_failures > 0:
            self.state.crashes += 1

        self.add_timeline(phase, "stress_complete", writes=writes, health_failures=health_failures)

    def phase_recovery_validation(self) -> None:
        phase = "PHASE_6_RECOVERY_VALIDATION"
        self.log("info", "Running Phase 6: recovery validation")
        deadline = time.time() + 150.0
        status = "UNKNOWN"
        status_payload: dict[str, Any] = {}

        while time.time() < deadline:
            ok, payload, _lat = self.request_json("/api/status", timeout=8.0)
            if ok:
                status_payload = payload
                status = str(payload.get("status") or "UNKNOWN").upper()
                if status == "SAFE":
                    break
            time.sleep(2.0)

        enc_files = list(STRESS_TARGET.glob("*.enc"))
        data_loss = len(enc_files)
        safe_recovered = status == "SAFE"

        if not safe_recovered:
            self.state.crashes += 1

        self.add_timeline(
            phase,
            "recovery_checked",
            status=status,
            data_loss=data_loss,
            safe_recovered=safe_recovered,
            snapshot=status_payload,
        )
        self.state.health_snapshot = self.state.health_snapshot or {}
        self.state.health_snapshot["data_loss"] = data_loss

    def phase_failure_tests(self) -> None:
        phase = "PHASE_7_FAILURE_TESTS"
        self.log("info", "Running Phase 7: disconnect/reconnect test")

        if self.socket_client is None:
            self.add_timeline(phase, "skipped", reason="socket probe disabled")
            return

        self._planned_disconnect = True
        self.socket_client.disconnect()
        time.sleep(1.2)
        try:
            self.socket_client.connect(
                self.backend_url,
                transports=["websocket"],
                auth={"apiKey": self.socket_api_key},
                wait_timeout=10,
            )
        finally:
            self._planned_disconnect = False
        time.sleep(1.0)

        connected = bool(self.socket_client.connected)
        if not connected:
            self.state.crashes += 1
            raise RuntimeError("Socket client failed to reconnect")

        self.state.reconnections += 1
        self.add_timeline(phase, "reconnected", connected=connected)

    def compute_report(self) -> dict[str, Any]:
        detection_latency = self.state.detection_latency_ms
        event_delay = mean(self.state.propagation_delays_ms) if self.state.propagation_delays_ms else None
        api_latency = self.state.baseline_latency_ms

        data_loss = int(self.state.health_snapshot.get("data_loss") or 0)
        recovery_success = data_loss == 0

        score = 10.0

        if detection_latency is None:
            score -= 2.0
        elif detection_latency > 1500:
            score -= 1.5
        elif detection_latency > 800:
            score -= 0.5

        if event_delay is None:
            score -= 1.5
        elif event_delay > 800:
            score -= 1.0
        elif event_delay > 300:
            score -= 0.5

        if api_latency > 300:
            score -= 1.0
        elif api_latency > 150:
            score -= 0.5

        score -= min(3.0, self.state.missed_events * 0.7)
        score -= min(4.0, self.state.crashes * 2.0)
        score -= min(2.0, self.state.disconnects * 0.3)
        score -= min(2.0, self.state.reconnections * 0.2)

        if not recovery_success:
            score -= 2.0
            score -= min(2.0, data_loss * 0.5)

        score = round(max(0.0, min(10.0, score)), 2)
        verdict = "READY" if score >= 8.0 and recovery_success and self.state.crashes == 0 else "NEEDS FIXES"

        web_sync_status = "OK" if self.url_is_up(self.frontend_local_url) or self.url_is_up(self.frontend_lan_url) else "FAIL"
        mobile_sync_status = (
            "OK"
            if self.run_mobile_socket and {"ATTACK_DETECTED", "FILES_RESTORED", "SYSTEM_SAFE"}.issubset(self.state.expected_events_seen)
            else "FAIL"
        )

        health_ok, health_payload, _ = self.request_json("/api/realtime/health", timeout=4.0)
        health_payload = health_payload if health_ok else {}

        report = {
            "system_score": score,
            "verdict": verdict,
            "performance": {
                "detection_latency_ms": round(detection_latency or 0.0, 2),
                "event_delay_ms": round(event_delay or 0.0, 2),
                "api_latency_ms": round(api_latency, 2),
            },
            "stability": {
                "crashes": self.state.crashes,
                "disconnects": self.state.disconnects,
                "reconnections": self.state.reconnections,
                "missed_events": self.state.missed_events,
            },
            "recovery": {
                "success": recovery_success,
                "data_loss": data_loss,
            },
            "realtime_sync": {
                "web": web_sync_status,
                "mobile": mobile_sync_status,
            },
            "health": {
                "socket_active": bool(health_payload.get("socket_active")),
                "clients": int(health_payload.get("connected_clients") or 0),
                "status": str(health_payload.get("status") or "unknown"),
            },
            "metrics": {
                "detection_latency": detection_latency,
                "event_propagation_time": event_delay,
                "api_latency": api_latency,
                "missed_events": self.state.missed_events,
                "crashes": self.state.crashes,
                "reconnections": self.state.reconnections,
            },
            "timestamps": {
                "generated_at": time.time(),
            },
        }
        return report

    def write_artifacts(self, report: dict[str, Any]) -> None:
        FINAL_REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
        TIMELINE_PATH.write_text(json.dumps(self.state.timeline, indent=2), encoding="utf-8")

        log_payload = {
            "logs": self.state.logs,
            "events": self.state.events,
        }
        LOG_PATH.write_text(json.dumps(log_payload, indent=2), encoding="utf-8")

    def cleanup(self) -> None:
        if self.socket_client is not None:
            try:
                if self.socket_client.connected:
                    self.socket_client.disconnect()
            except Exception:
                pass

        if self.keep_processes:
            return

        for handle in (self.frontend_handle, self.backend_handle):
            if not handle.started_here or handle.process is None:
                continue
            if handle.process.poll() is not None:
                continue
            handle.process.terminate()
            try:
                handle.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                handle.process.kill()
                handle.process.wait(timeout=4)

    def run(self) -> dict[str, Any]:
        RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)

        self.start_backend_if_needed()
        self.start_frontend_if_needed()
        self.connect_socket_probe()

        phase_calls = [
            ("PHASE_1_SYSTEM_HEALTH", self.phase_system_health),
            ("PHASE_2_BASELINE_PERFORMANCE", self.phase_baseline_performance),
            ("PHASE_3_ATTACK_SIMULATION", self.phase_attack_simulation),
            ("PHASE_4_REALTIME_SYNC", self.phase_realtime_sync),
            ("PHASE_5_STRESS_LOAD", self.phase_stress_load),
            ("PHASE_6_RECOVERY_VALIDATION", self.phase_recovery_validation),
            ("PHASE_7_FAILURE_TESTS", self.phase_failure_tests),
        ]

        for phase_name, phase_fn in phase_calls:
            try:
                phase_fn()
            except Exception as exc:
                self.state.crashes += 1
                self.log("error", f"{phase_name} failed: {exc}")
                self.add_timeline(phase_name, "phase_failed", error=str(exc))

        return self.compute_report()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="One-click QA and stress runner for CyberShield")
    parser.add_argument("--host-ip", default="10.253.172.187", help="LAN host IP used by frontend/mobile")
    parser.add_argument("--backend-port", type=int, default=5000, help="Backend port")
    parser.add_argument("--frontend-port", type=int, default=5173, help="Frontend port")
    parser.add_argument("--socket-api-key", default="CYBERSHIELD_SECURE_KEY", help="Socket API key")
    parser.add_argument(
        "--disable-mobile-probe",
        action="store_true",
        help="Disable Socket.IO probe client (mobile simulation)",
    )
    parser.add_argument(
        "--keep-processes",
        action="store_true",
        help="Do not stop backend/frontend processes started by this runner",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runner = StressRunner(
        host_ip=args.host_ip,
        backend_port=args.backend_port,
        frontend_port=args.frontend_port,
        socket_api_key=args.socket_api_key,
        run_mobile_socket=not args.disable_mobile_probe,
        keep_processes=args.keep_processes,
    )

    try:
        report = runner.run()
        runner.write_artifacts(report)

        print("")
        print("[OK] Test Completed")
        print(f"[TROPHY] System Score: {report['system_score']}/10")
        print(f"[METRIC] Verdict: {report['verdict']}")
        print(f"[FILE] Report: {FINAL_REPORT_PATH}")
        print(f"[FILE] Timeline: {TIMELINE_PATH}")
        print(f"[FILE] Logs: {LOG_PATH}")
        return 0
    except Exception as exc:
        runner.state.crashes += 1
        runner.log("error", f"QA stress runner failed: {exc}")
        fallback_report = runner.compute_report()
        fallback_report["verdict"] = "NEEDS FIXES"
        fallback_report["error"] = str(exc)
        runner.write_artifacts(fallback_report)

        print("")
        print("[FAIL] Test Completed With Errors")
        print(f"[TROPHY] System Score: {fallback_report['system_score']}/10")
        print(f"[METRIC] Verdict: {fallback_report['verdict']}")
        print(f"[FILE] Report: {FINAL_REPORT_PATH}")
        return 1
    finally:
        runner.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
