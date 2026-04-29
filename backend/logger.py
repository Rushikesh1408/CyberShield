"""
Production-grade logging for CyberShield backend.
- Rotating file handler
- Console output
- JSON log support
- Integrates with all modules
"""
import logging
from logging.handlers import RotatingFileHandler
import os
import json

LOG_DIR = os.environ.get("LOG_DIR", "./logs")
LOG_FILE = os.path.join(LOG_DIR, "cybershield.log")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

os.makedirs(LOG_DIR, exist_ok=True)

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "level": record.levelname,
            "time": self.formatTime(record, self.datefmt),
            "module": record.module,
            "funcName": record.funcName,
            "lineNo": record.lineno,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)

class DBLogHandler(logging.Handler):
    def emit(self, record):
        try:
            from backend.db.database import SessionLocal
            from backend.db import models
            db = SessionLocal()
            db_log = models.Log(
                message=record.getMessage(),
                level=record.levelname
            )
            db.add(db_log)
            db.commit()
            db.close()
        except Exception:
            pass  # Avoid recursion if DB is down

def get_logger(name="cybershield", json_logs=False, db_logs=True):
    logger = logging.getLogger(name)
    if logger.hasHandlers():
        return logger
    logger.setLevel(LOG_LEVEL)
    formatter = JsonFormatter() if json_logs else logging.Formatter('[%(asctime)s] %(levelname)s %(module)s:%(lineno)d %(message)s')
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    if db_logs:
        logger.addHandler(DBLogHandler())
    return logger
