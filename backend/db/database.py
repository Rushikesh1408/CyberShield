# Production-grade database connection for CyberShield
import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from both backend/ and project root so all configs are available
_backend_env = Path(__file__).resolve().parent.parent / ".env"
_root_env = Path(__file__).resolve().parent.parent.parent / ".env"
for _env_path in (_backend_env, _root_env):
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path, override=False)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Individual Postgres vars (only used when DATABASE_URL is not set)
POSTGRES_DB = os.environ.get("POSTGRES_DB", "cybershield")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "cyber")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "shield")
# Default to localhost for local dev; use "db" inside Docker via DATABASE_URL
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")

SQLITE_PATH = os.environ.get("SQLITE_PATH", "./cybershield.db")


def get_database_url() -> str:
    # Explicit DATABASE_URL always wins (set in .env or Docker env)
    url = os.environ.get("DATABASE_URL", "")
    if url:
        return url
    # Offline / local-only mode
    if os.environ.get("OFFLINE_MODE") == "1":
        return f"sqlite:///{SQLITE_PATH}"
    # Default: SQLite so the app always starts without Postgres
    return f"sqlite:///{SQLITE_PATH}"


DATABASE_URL = get_database_url()

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
