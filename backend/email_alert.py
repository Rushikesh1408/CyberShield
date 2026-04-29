"""
Production-grade email alerting for CyberShield.
- Sends alerts on ransomware detection, recovery, or critical failures
- Configurable SMTP settings
- Integrates with logging
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from backend.logger import get_logger

SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.example.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "user@example.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "password")
ALERT_EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", SMTP_USER)
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO", "admin@example.com")

logger = get_logger("cybershield.email_alert")

def send_email_alert(subject, message, to=None):
    to = to or ALERT_EMAIL_TO
    msg = MIMEMultipart()
    msg["From"] = ALERT_EMAIL_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(message, "plain"))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_EMAIL_FROM, to, msg.as_string())
        logger.info(f"Email alert sent to {to}: {subject}")
        # Persist alert to DB
        try:
            from backend.db.database import SessionLocal
            from backend.db import models
            db = SessionLocal()
            db_alert = models.Alert(
                severity="email",
                reason=subject + ": " + message,
                file_path=None,
                process_id=None
            )
            db.add(db_alert)
            db.commit()
            db.close()
        except Exception:
            pass
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
