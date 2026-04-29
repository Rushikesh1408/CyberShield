from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from backend.core.baseline import AdaptiveBaseline
from backend.core.entropy import get_entropy_score
from backend.core.scoring import calculate_threat_score

from .backup_service import BackupService
from .process_service import ProcessService


@dataclass(frozen=True)
class DetectionResult:
    score: int
    level: str
    confidence: float
    entropy: float
    entropy_threshold_hit: bool
    entropy_triggered: bool
    dna_mismatch_count: int
    threat_detected: bool
    anomalies: dict[str, bool]
    baseline: dict[str, float]
    suspicious_processes: list[dict[str, object]]
    process_tree: list[dict[str, object]]
    high_risk_processes: list[dict[str, object]]
    affected_files: list[str]
    backup_access_alerts: list[dict[str, object]]


class DetectionService:
    def __init__(
        self,
        *,
        process_service: ProcessService,
        backup_service: BackupService | None = None,
        baseline: AdaptiveBaseline | None = None,
    ) -> None:
        self.process_service = process_service
        self.backup_service = backup_service
        self.baseline = baseline or AdaptiveBaseline(window_size=40)

    @staticmethod
    def _safe_paths(paths: Iterable[str | Path] | None) -> list[Path]:
        normalized: list[Path] = []
        seen: set[str] = set()
        for value in paths or []:
            try:
                path = Path(value).resolve()
            except OSError:
                continue
            key = str(path).lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(path)
        return normalized

    def _sample_recent_files(
        self,
        monitored_paths: Iterable[str | Path] | None,
        *,
        lookback_seconds: float = 8.0,
    ) -> list[Path]:
        recent_files: list[Path] = []
        lower_bound = time.time() - max(1.0, float(lookback_seconds))
        for root in self._safe_paths(monitored_paths):
            if not root.exists() or not root.is_dir():
                continue
            for file_path in root.rglob("*"):
                if not file_path.is_file():
                    continue
                try:
                    if file_path.stat().st_mtime < lower_bound:
                        continue
                except OSError:
                    continue
                recent_files.append(file_path)
                if len(recent_files) >= 12:
                    return recent_files
        return recent_files

    @staticmethod
    def _process_risk_score(process_tree: list[dict[str, object]]) -> tuple[float, list[dict[str, object]]]:
        risk = 0.0
        high_risk_nodes: list[dict[str, object]] = []
        for node in process_tree:
            node_name = str(node.get("name") or "").lower()
            node_path = str(node.get("path") or "").lower()
            node_cmdline = str(node.get("cmdline") or "").lower()
            node_risk = 0.0

            if any(marker in node_name for marker in ("cmd", "powershell", "pwsh")) or any(
                marker in node_cmdline for marker in ("powershell", "cmd.exe", "pwsh")
            ):
                node_risk += 0.4
            if any(marker in node_path for marker in ("temp", "appdata", "downloads")):
                node_risk += 0.35
            if not node_name or node_name in {"system", "unknown", "unknown.exe"}:
                node_risk += 0.25
            if "->" in node_cmdline:
                node_risk += 0.1

            if node_risk >= 0.5:
                high_risk_nodes.append(node)
            risk = max(risk, min(1.0, node_risk))

        return risk, high_risk_nodes

    def get_process_tree(self, pid: int, *, max_depth: int = 5) -> list[dict[str, object]]:
        tree: list[dict[str, object]] = []
        current_pid = int(pid)
        depth = 0
        while current_pid > 0 and depth < max_depth:
            process = self.process_service.get_process(current_pid)
            if process is None:
                break

            tree.append(
                {
                    "pid": int(process.pid),
                    "name": self.process_service.safe_name(process),
                    "path": self.process_service.safe_exe(process),
                    "cmdline": self.process_service.safe_cmdline(process),
                    "parent_pid": int(process.ppid()),
                }
            )
            parent_pid = int(process.ppid())
            if parent_pid <= 0 or parent_pid == current_pid:
                break
            current_pid = parent_pid
            depth += 1

        return tree

    def calculate_detection(
        self,
        *,
        monitored_paths: Iterable[str | Path] | None,
        cpu_usage: float,
        file_activity_rate: float,
        dna_mismatch_count: int,
        recent_processes: Iterable[dict[str, object]] | None = None,
        process_pid: int | None = None,
    ) -> dict[str, Any]:
        baseline_snapshot = self.baseline.update(
            cpu_usage=float(cpu_usage),
            file_activity_rate=float(file_activity_rate),
        )
        anomalies = self.baseline.evaluate(
            cpu_usage=float(cpu_usage),
            file_activity_rate=float(file_activity_rate),
        )
        adaptive_cpu_threshold = max(20.0, float(baseline_snapshot["avg_cpu_usage"]) * 2.0)

        recent_files = self._sample_recent_files(monitored_paths)
        entropies: list[float] = []
        affected_files: list[str] = []
        entropy_triggered = False
        for file_path in recent_files:
            try:
                entropy_data = get_entropy_score(file_path)
            except (FileNotFoundError, OSError, ValueError):
                continue
            file_entropy = float(entropy_data.get("score") or 0.0)
            entropies.append(file_entropy)
            entropy_triggered = entropy_triggered or bool(entropy_data.get("likely_encrypted"))
            affected_files.append(str(file_path))

        average_entropy = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
        process_intelligence = 0.0
        high_risk_processes: list[dict[str, object]] = []
        process_tree: list[dict[str, object]] = []
        suspicious_processes = list(recent_processes or [])
        if not suspicious_processes:
            suspicious_processes = self.process_service.detect_suspicious_processes(
                monitored_paths=monitored_paths,
                cpu_threshold=adaptive_cpu_threshold,
            )

        if process_pid is None and suspicious_processes:
            top_process = max(suspicious_processes, key=lambda item: float(item.get("score") or 0.0))
            process_pid = int(top_process.get("pid") or 0)

        if process_pid is not None:
            process_tree = self.get_process_tree(int(process_pid))
            process_intelligence, high_risk_processes = self._process_risk_score(process_tree)

        backup_access_alerts = []
        if self.backup_service is not None:
            backup_candidates = list(affected_files)
            for process in suspicious_processes:
                backup_candidates.extend(self.process_service.open_file_paths(int(process.get("pid") or 0)))

            backup_access_alerts = self.backup_service.build_backup_protection_alerts(backup_candidates)

        weighted = calculate_threat_score(
            file_activity_count=max(0, int(round(file_activity_rate))),
            cpu_usage=float(cpu_usage),
            dna_mismatch_count=int(dna_mismatch_count),
            entropy=average_entropy,
            entropy_threshold_hit=entropy_triggered,
            process_risk=process_intelligence,
            max_file_activity=200,
            max_dna_mismatch=20,
        )

        score = int(weighted["score"])
        threat_detected = bool(
            score >= 50
            or entropy_triggered
            or backup_access_alerts
            or (suspicious_processes and (anomalies["cpu_anomaly"] or anomalies["file_anomaly"]))
        )

        return {
            "score": score,
            "level": str(weighted["level"]),
            "confidence": round(score / 100.0, 2),
            "entropy": average_entropy,
            "entropy_threshold_hit": entropy_triggered,
            "entropy_triggered": entropy_triggered,
            "file_activity_rate": float(file_activity_rate),
            "dna_mismatch_count": int(dna_mismatch_count),
            "threat_detected": threat_detected,
            "baseline": baseline_snapshot,
            "anomalies": anomalies,
            "adaptive_cpu_threshold": round(adaptive_cpu_threshold, 2),
            "suspicious_processes": suspicious_processes,
            "process_tree": process_tree,
            "high_risk_processes": high_risk_processes,
            "affected_files": affected_files,
            "backup_access_alerts": backup_access_alerts,
        }
