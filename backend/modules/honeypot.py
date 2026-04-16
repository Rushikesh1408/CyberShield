from __future__ import annotations

from pathlib import Path


class HoneypotManager:
    def __init__(self, roots: list[str | Path]) -> None:
        self.roots = [Path(value).resolve() for value in roots]

    def seed_default_decoys(self) -> set[str]:
        templates = {
            "admin.db": "admins,hash\nroot,not-real\n",
            "bank.txt": "account=00000000\nrouting=000000000\n",
            "credential_dump.csv": "service,user,password\nmail,ops@example.com,NotReal\n",
        }
        created: set[str] = set()

        for root in self.roots:
            if not root.exists() or not root.is_dir():
                continue
            trap_dir = root / "sensitive_archive"
            try:
                trap_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                continue

            for file_name, content in templates.items():
                file_path = trap_dir / file_name
                try:
                    if not file_path.exists():
                        file_path.write_text(content, encoding="utf-8")
                        created.add(str(file_path.resolve()).lower())
                except OSError:
                    continue

        return created
