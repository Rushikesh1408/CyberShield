from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from backend.api import init_socketio
    from backend.api import register_routes
    from backend.api import socketio
    from backend.config import AppConfig
else:
    from .api import init_socketio
    from .api import register_routes
    from .api import socketio
    from .config import AppConfig


def _load_dotenv_file(dotenv_path: Path) -> None:
    if not dotenv_path.exists() or not dotenv_path.is_file():
        return

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv_file(Path(__file__).resolve().parent.parent / ".env")


def create_app() -> Flask:
    flask_app = Flask(__name__)
    config = AppConfig.from_env()
    flask_app.config.from_mapping(config.flask_mapping())

    @flask_app.after_request
    def add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, x-api-key"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    register_routes(flask_app)
    init_socketio(flask_app)
    return flask_app


app = create_app()


if __name__ == "__main__":
    runtime_config = AppConfig.from_env()
    socketio.run(
        app,
        host=runtime_config.host,
        port=runtime_config.port,
        debug=runtime_config.debug,
        use_reloader=runtime_config.use_reloader,
    )
