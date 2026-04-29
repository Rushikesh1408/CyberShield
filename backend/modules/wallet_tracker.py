from __future__ import annotations

import re
from pathlib import Path


BTC_PATTERN = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RANSOM_NOTE_NAME_HINTS = ("readme", "decrypt", "recover", "ransom", "how_to")

MAX_FILE_BYTES = 1024 * 1024  # 1MB


class WalletTracker:
    def extract_wallets_from_text(self, text: str) -> list[dict[str, str]]:
        wallets: list[dict[str, str]] = []
        for match in BTC_PATTERN.findall(text or ""):
            wallets.append({"type": "btc", "address": match})
        for match in ETH_PATTERN.findall(text or ""):
            wallets.append({"type": "eth", "address": match})

        unique: dict[str, dict[str, str]] = {}
        for wallet in wallets:
            key = f"{wallet['type']}:{wallet['address']}".lower()
            if key not in unique:
                unique[key] = wallet
        return list(unique.values())

    def scan_notes(self, roots: list[str | Path], *, max_files: int = 120) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        scanned = 0

        for root_value in roots:
            root = Path(root_value).resolve()
            if not root.exists() or not root.is_dir():
                continue

            for file_path in root.rglob("*"):
                if scanned >= max_files:
                    return findings

                # HEAD: skip symlinks for security; branch only skips non-files
                if not file_path.is_file() or file_path.is_symlink():
                    continue

                lower_name = file_path.name.lower()
                if not any(hint in lower_name for hint in RANSOM_NOTE_NAME_HINTS):
                    continue

                scanned += 1
                try:
                    # HEAD: file size guard to prevent reading huge files
                    try:
                        if file_path.stat().st_size > MAX_FILE_BYTES:
                            continue
                    except OSError:
                        continue

                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                for wallet in self.extract_wallets_from_text(content):
                    findings.append({"type": wallet["type"], "address": wallet["address"], "source_file": str(file_path)})

        return findings
