from __future__ import annotations

from typing import Any


class CorrelationEngine:
    @staticmethod
    def _safe_float(value: object) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _safe_int(value: object, default: int = 0) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default

    def correlate(
        self,
        *,
        incoming_signature: dict[str, Any],
        known_signatures: list[dict[str, Any]],
        incoming_wallets: list[str] | None = None,
        known_wallets: list[dict[str, Any]] | None = None,
        similarity_threshold: float = 0.75,
    ) -> dict[str, Any]:
        if not known_signatures:
            return {"matched": False, "matches": []}

        incoming_wallet_set = {wallet.lower() for wallet in (incoming_wallets or []) if wallet}

        known_wallet_set = {
            str(item.get("wallet_address") or "").lower()
            for item in (known_wallets or [])
            if isinstance(item, dict)
        }

        matches: list[dict[str, Any]] = []
        for known in known_signatures:
            # Compute per-known wallet set — supports both list-of-dicts and list-of-strings
            per_known_wallets = set(known_wallet_set)
            wallets_field = known.get("wallets", [])
            if isinstance(wallets_field, list):
                for w in wallets_field:
                    if isinstance(w, dict):
                        addr = w.get("address") or w.get("wallet_address")
                        if addr:
                            per_known_wallets.add(str(addr).lower())
                    elif isinstance(w, str):
                        per_known_wallets.add(w.lower())
            if "wallet_address" in known:
                per_known_wallets.add(str(known["wallet_address"]).lower())

            wallet_overlap = bool(incoming_wallet_set.intersection(per_known_wallets))
            score = self._score_signature(incoming_signature, known)
            occurrences = self._safe_int(known.get("occurrences"))

            if score >= similarity_threshold or wallet_overlap:
                matches.append(
                    {
                        "signature_id": str(known.get("signature_id") or ""),
                        "similarity": round(score * 100.0, 2),
                        "wallet_overlap": wallet_overlap,
                        "occurrences": occurrences,
                    }
                )

        matches.sort(key=lambda item: float(item.get("similarity") or 0.0), reverse=True)
        return {"matched": bool(matches), "matches": matches[:10]}

    def _score_signature(self, incoming: dict[str, Any], known: dict[str, Any]) -> float:
        weight = 0.0
        score = 0.0

        weight += 0.4
        if str(incoming.get("process_name") or "") == str(known.get("process_name") or ""):
            score += 0.4

        entropy_delta = abs(self._safe_float(incoming.get("entropy")) - self._safe_float(known.get("entropy")))
        weight += 0.2
        score += max(0.0, 0.2 - min(0.2, entropy_delta / 10.0))

        file_rate_delta = abs(self._safe_float(incoming.get("file_rate")) - self._safe_float(known.get("file_rate")))
        weight += 0.25
        score += max(0.0, 0.25 - min(0.25, file_rate_delta / 250.0))

        timing_delta = abs(self._safe_float(incoming.get("timing_ms")) - self._safe_float(known.get("timing_ms")))
        weight += 0.15
        score += max(0.0, 0.15 - min(0.15, timing_delta / 10000.0))

        if weight <= 0:
            return 0.0
        return max(0.0, min(1.0, score / weight))
