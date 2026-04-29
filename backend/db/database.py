# Production-grade database connection for CyberShield
import os
import logging
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger("cybershield.database")

# Load .env from both backend/ and project root so all configs are available
_backend_env = Path(__file__).resolve().parent.parent / ".env"
_root_env = Path(__file__).resolve().parent.parent.parent / ".env"
for _env_path in (_backend_env, _root_env):
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path, override=False)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Individual Postgres vars (only used when DATABASE_URL is not set)
# No defaults for credentials — they must be supplied explicitly.
POSTGRES_DB = os.environ.get("POSTGRES_DB", "cybershield")
POSTGRES_USER = os.environ.get("POSTGRES_USER")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD")
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

    # When Postgres credentials are available, build the Postgres URL
    if POSTGRES_USER and POSTGRES_PASSWORD:
        return (
            f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
            f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
        )

    # If credentials are absent, raise in Postgres mode to fail fast
    if os.environ.get("REQUIRE_POSTGRES", "0") == "1":
        raise ValueError(
            "POSTGRES_USER and POSTGRES_PASSWORD must be set when REQUIRE_POSTGRES=1. "
            "Set DATABASE_URL or OFFLINE_MODE=1 to use SQLite."
        )

    # Default: SQLite so the app always starts in local dev without Postgres
    logger.warning(
        "POSTGRES_USER/POSTGRES_PASSWORD not set — falling back to SQLite. "
        "Set REQUIRE_POSTGRES=1 to fail fast in production."
    )
    return f"sqlite:///{SQLITE_PATH}"


DATABASE_URL = get_database_url()

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
