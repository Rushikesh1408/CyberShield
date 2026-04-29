"""
Production-grade email alerting for CyberShield.
- Sends alerts on ransomware detection, recovery, or critical failures
- Configurable SMTP settings via environment variables
- Integrates with logging

IMPORTANT: Set SMTP_PASSWORD via environment — no plaintext defaults.
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from backend.logger import get_logger

SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.example.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
ALERT_EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", SMTP_USER)
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO", "")
SMTP_TIMEOUT = int(os.environ.get("SMTP_TIMEOUT", "15"))  # seconds

logger = get_logger("cybershield.email_alert")


def send_email_alert(subject: str, message: str, to: str | None = None) -> bool:
    """
    Send an email alert.  Returns True on success, False on failure.
    SMTP_PASSWORD must be supplied via environment; empty password causes a
    configuring error logged at WARNING level rather than a crash.
    """
    recipient = (to or ALERT_EMAIL_TO).strip()
    if not recipient:
        logger.warning("[email_alert] ALERT_EMAIL_TO is not configured — skipping alert.")
        return False
    if not SMTP_USER:
        logger.warning("[email_alert] SMTP_USER is not configured — skipping alert.")
        return False
    if not SMTP_PASSWORD:
        logger.warning("[email_alert] SMTP_PASSWORD is not set — alert will likely fail authentication.")

    msg = MIMEMultipart()
    msg["From"] = ALERT_EMAIL_FROM or SMTP_USER
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(message, "plain"))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
            server.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_EMAIL_FROM or SMTP_USER, recipient, msg.as_string())
        logger.info(f"Email alert sent to {recipient}: {subject}")
        # Persist alert to DB
        db = None
        try:
            from backend.db.database import SessionLocal
            from backend.db import models
            db = SessionLocal()
            db_alert = models.Alert(
                severity="email",
                reason=subject + ": " + message,
                file_path=None,
                process_id=None,
            )
            db.add(db_alert)
            db.commit()
        except Exception as db_err:
            logger.error(f"[email_alert] Failed to persist alert to DB: {db_err}")
        finally:
            if db is not None:
                db.close()
        return True
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        return False
