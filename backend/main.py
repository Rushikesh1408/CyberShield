"""
Main entrypoint for CyberShield backend (FastAPI).
Handles startup: loads env, creates DB tables, mounts router.
"""
import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load .env files before anything else imports env vars
_backend_env = Path(__file__).resolve().parent / ".env"
_root_env = Path(__file__).resolve().parent.parent / ".env"
for _env_path in (_backend_env, _root_env):
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path, override=False)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.db.database import engine, SessionLocal
from backend.db.models import Base

logger = logging.getLogger("cybershield.startup")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: create tables on startup."""
    logger.info("CyberShield starting up — creating database tables if needed...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables ready.")
    except Exception as exc:
        logger.error(f"DB table creation failed: {exc}")

    yield

    logger.info("CyberShield shutting down.")


app = FastAPI(
    title="CyberShield API",
    version="1.0.0",
    description="Real-time ransomware defense system",
    lifespan=lifespan,
)

# CORS — allow only trusted origins
_allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

from backend.api.routes import router  # noqa: E402 — imported after env is loaded

app.include_router(router, prefix="/api")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
