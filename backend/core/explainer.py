"""
CyberShield backend explainability engine.
Sanitizes event/reason inputs before returning human-readable explanations.
"""
import html
import unicodedata


_MAX_LEN = 1000
_CONTROL_CATS = {"Cc", "Cf"}


def _sanitize(value: object) -> str:
    """Coerce to str, truncate, strip control characters."""
    text = str(value)[:_MAX_LEN]
    return "".join(
        ch for ch in text if unicodedata.category(ch) not in _CONTROL_CATS
    )


def explain_detection(event, reason) -> str:
    """Return a sanitized, HTML-safe explanation string."""
    safe_event = html.escape(_sanitize(event))
    safe_reason = html.escape(_sanitize(reason))
    return f"Event: {safe_event} | Reason: {safe_reason}"
