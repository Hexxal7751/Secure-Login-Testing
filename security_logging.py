"""
Security event logging.

Every event is one searchable line on stdout (Render shows it under Logs), for example:

    SEC event=login_failure level=WARNING request_id=1a2b3c4d user_id=5 ip=203.0.113.7 device="Chrome on Android"

Search Render's log box for `event=login_failure`, `user_id=5` or a `request_id=` copied from an
error page to follow one request. Set LOG_TO_FILE=1 to also keep the same lines in logs/security.log.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from flask import has_request_context, request, session, g

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

_stdout = logging.StreamHandler(sys.stdout)
_stdout.setFormatter(logging.Formatter("%(message)s"))
security_logger.addHandler(_stdout)

if os.getenv("LOG_TO_FILE", "").strip().lower() in ("1", "true", "yes", "on"):
    try:
        os.makedirs("logs", exist_ok=True)
        _file = RotatingFileHandler("logs/security.log", maxBytes=10485760, backupCount=10)
        _file.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        security_logger.addHandler(_file)
    except OSError:
        pass  # read-only disk: stdout logging is enough


def _fmt(value):
    text = str(value).replace("\n", " ").replace("\r", " ")[:200]
    return f'"{text}"' if (" " in text or "=" in text or not text) else text


def log_security_event(event_type, details, level="INFO"):
    """Log one security event as a searchable key=value line.

    event_type: e.g. login_success, login_failure, account_deleted
    details:    dict of extra facts (never put passwords or codes in here)
    level:      INFO, WARNING, ERROR or CRITICAL
    """
    in_request = has_request_context()
    fields = {
        "event": event_type,
        "level": level,
        "request_id": g.get("request_id", "-") if in_request else "-",
        "user_id": (details or {}).get("user_id") or (session.get("user_id") if in_request else None) or "anonymous",
        "ip": (request.remote_addr if in_request else "unknown"),
    }
    try:
        from core import client_ip  # trusted visitor IP (imported late: core imports this module)
        if in_request:
            fields["ip"] = client_ip()
    except Exception:
        pass
    if in_request:
        fields["ua"] = (request.headers.get("User-Agent") or "unknown")[:120]
    for key, value in (details or {}).items():
        if key != "user_id":
            fields[key] = value

    line = "SEC " + " ".join(f"{k}={_fmt(v)}" for k, v in fields.items())
    level_name = str(level).upper()
    if level_name == "WARNING":
        security_logger.warning(line)
    elif level_name == "ERROR":
        security_logger.error(line)
    elif level_name == "CRITICAL":
        security_logger.critical(line)
    else:
        security_logger.info(line)


# Security event types
LOGIN_SUCCESS = "login_success"
LOGIN_FAILURE = "login_failure"
REGISTRATION = "user_registration"
PASSWORD_CHANGE = "password_change"
ACCOUNT_LOCKOUT = "account_lockout"
ACCOUNT_DELETED = "account_deleted"
SUSPICIOUS_ACTIVITY = "suspicious_activity"
PERMISSION_DENIED = "permission_denied"
ADMIN_ACTION = "admin_action"
