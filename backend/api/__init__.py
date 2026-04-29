"""
backend/api package — unified re-export shim.

The Flask/SocketIO production implementation lives in backend/_flask_api.py.
The FastAPI router lives in backend/api/routes.py.

Imports from `backend.api` (used by backend/app.py) will resolve here and
transparently pick up the Flask symbols.
"""
from backend._flask_api import (  # noqa: F401
    init_socketio,
    register_routes,
    socketio,
    emit_event,
    create_app,
)

__all__ = [
    "init_socketio",
    "register_routes",
    "socketio",
    "emit_event",
    "create_app",
]
