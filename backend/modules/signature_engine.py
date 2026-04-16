from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


class AttackSignatureEngine:
    def generate(
        self,
        *,
        entropy: float,
        file_rate: float,
        process_name: str,
        timing_ms: float,
        cpu_usage: float,
        confidence: float,
    ) -> dict[str, Any]:
        normalized = {
            "entropy": round(max(0.0, float(entropy)), 4),
            "file_rate": round(max(0.0, float(file_rate)), 4),
            "process_name": str(process_name or "unknown").strip().lower(),
            "timing_ms": round(max(0.0, float(timing_ms)), 2),
            "cpu_usage": round(max(0.0, float(cpu_usage)), 2),
            "confidence": round(max(0.0, min(100.0, float(confidence))), 2),
        }
        seed = "|".join(
            [
                f"{normalized['entropy']:.4f}",
                f"{normalized['file_rate']:.4f}",
                normalized["process_name"],
                f"{normalized['timing_ms']:.2f}",
            ]
        )
        signature_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        return {
            "signature_id": signature_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **normalized,
            "metadata": {"seed": seed},
        }
