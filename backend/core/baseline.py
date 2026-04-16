from __future__ import annotations

from collections import deque
from typing import Deque


class AdaptiveBaseline:
    def __init__(self, *, window_size: int = 30) -> None:
        self.window_size = max(5, int(window_size))
        self._cpu_window: Deque[float] = deque(maxlen=self.window_size)
        self._file_rate_window: Deque[float] = deque(maxlen=self.window_size)

    @staticmethod
    def _average(values: Deque[float]) -> float:
        if not values:
            return 0.0
        return float(sum(values) / len(values))

    def update(self, *, cpu_usage: float, file_activity_rate: float) -> dict[str, float]:
        self._cpu_window.append(max(0.0, float(cpu_usage)))
        self._file_rate_window.append(max(0.0, float(file_activity_rate)))
        return {
            "avg_cpu_usage": round(self._average(self._cpu_window), 4),
            "avg_file_activity_rate": round(self._average(self._file_rate_window), 4),
        }

    def evaluate(self, *, cpu_usage: float, file_activity_rate: float) -> dict[str, bool]:
        avg_cpu = self._average(self._cpu_window)
        avg_file_rate = self._average(self._file_rate_window)

        # Keep a practical lower floor so early startup samples do not produce zero thresholds.
        cpu_baseline = max(5.0, avg_cpu)
        file_baseline = max(1.0, avg_file_rate)

        return {
            "cpu_anomaly": float(cpu_usage) > (cpu_baseline * 2.0),
            "file_anomaly": float(file_activity_rate) > (file_baseline * 3.0),
        }
