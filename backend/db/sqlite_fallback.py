"""
Production-grade SQLite fallback for CyberShield (offline mode).
Provides a SQLAlchemy session for offline operation.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SQLITE_PATH = os.environ.get("SQLITE_PATH", "./cybershield.db")
DATABASE_URL = f"sqlite:///{SQLITE_PATH}"

engine = create_engine(
	DATABASE_URL,
	connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
