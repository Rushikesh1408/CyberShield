from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    use_reloader: bool = False

    @classmethod
    def from_env(cls) -> "AppConfig":
        host = os.environ.get("HOST", cls.host)
        port = int(os.environ.get("PORT", str(cls.port)))
        debug = os.environ.get("FLASK_DEBUG", "0") in {"1", "true", "True"}
        use_reloader = os.environ.get("FLASK_RELOADER", "0") in {"1", "true", "True"}
        return cls(
            host=host,
            port=port,
            debug=debug,
            use_reloader=use_reloader,
        )

    def flask_mapping(self) -> dict[str, object]:
        return {
            "HOST": self.host,
            "PORT": self.port,
            "DEBUG": self.debug,
            "USE_RELOADER": self.use_reloader,
        }
