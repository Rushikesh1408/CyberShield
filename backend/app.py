from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from backend.api import register_routes
    from backend.config import AppConfig
else:
    from .api import register_routes
    from .config import AppConfig


def create_app() -> Flask:
    flask_app = Flask(__name__)
    config = AppConfig.from_env()
    flask_app.config.from_mapping(config.flask_mapping())
    register_routes(flask_app)
    return flask_app


app = create_app()


if __name__ == "__main__":
    runtime_config = AppConfig.from_env()
    app.run(
        host=runtime_config.host,
        port=runtime_config.port,
        debug=runtime_config.debug,
        use_reloader=runtime_config.use_reloader,
    )
