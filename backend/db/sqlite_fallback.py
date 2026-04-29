"""
SQLite fallback for CyberShield (offline mode).
Provides a SQLAlchemy session for offline operation with WAL journal mode
and a busy timeout for concurrent access resilience.
"""
import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

SQLITE_PATH = os.environ.get("SQLITE_PATH", "./cybershield.db")
DATABASE_URL = f"sqlite:///{SQLITE_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 30,  # 30-second busy timeout for concurrent writes
    },
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _connection_record):
    """Enable WAL mode and NORMAL synchronous for concurrent web use."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
