"""
Structured security event logging — SIEM-ready.

Emits one JSON object per line to security.log.
Schema is stable and documented in log_event().
"""
import logging
import json
import os
import uuid
from datetime import datetime
from logging.handlers import RotatingFileHandler

from app.config import Config

logger = logging.getLogger("security")
logger.setLevel(logging.INFO)
logger.propagate = False

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOG_PATH = os.path.join(_PROJECT_ROOT, "security.log")

try:
    handler = RotatingFileHandler(
        _LOG_PATH,
        maxBytes=50 * 1024 * 1024,   # 50 MB per file
        backupCount=10,               # keep 10 rotated files (~500 MB max)
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
except Exception:
    logger.addHandler(logging.StreamHandler())


SERVICE_NAME = Config.APP_NAME
SERVICE_ENV = Config.ENVIRONMENT


def log_event(
    event_type: str,
    *,
    email: str = None,
    user_name: str = None,
    ip: str = None,
    user_agent: str = None,
    request_id: str = None,
    session_id: str = None,
    http_method: str = None,
    http_path: str = None,
    http_status: int = None,
    action: str = None,
    target: str = None,
    success: bool = True,
    severity: str = None,
    error: str = None,
    duration_ms: int = None,
    details: dict = None,
):
    """
    Write a structured security event.

    event_type: dotted name — e.g. 'auth.login.failed'
    severity:   'info' | 'warn' | 'error' | 'critical'
                Default: 'info' if success else 'warn'
    """
    if severity is None:
        severity = "info" if success else "warn"

    payload = {
        "@timestamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "severity": severity,
        "outcome": "success" if success else "failure",

        "service": {
            "name": SERVICE_NAME,
            "env": SERVICE_ENV,
        },

        "actor": {
            "email": email,
            "user_name": user_name,
            "ip": ip,
            "user_agent": user_agent,
            "session_id": session_id,
        },

        "http": {
            "method": http_method,
            "path": http_path,
            "status_code": http_status,
            "request_id": request_id,
        },

        "action": action,
        "target": target,

        "duration_ms": duration_ms,
        "error": error,
        "details": details or {},
    }
    logger.info(json.dumps(payload, default=str))


# ============================================================
# REQUEST CONTEXT HELPERS
# ============================================================
def get_client_ip(request) -> str:
    """
    Extract client IP, respecting X-Forwarded-For / X-Real-IP
    so we log the real client even behind nginx.
    """
    if request is None:
        return None

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return None


def get_user_agent(request) -> str:
    if request is None:
        return None
    return request.headers.get("user-agent")


def get_request_id(request) -> str:
    """Use incoming X-Request-ID if present, else generate one."""
    if request is None:
        return str(uuid.uuid4())
    incoming = request.headers.get("x-request-id")
    return incoming or str(uuid.uuid4())


def new_request_id() -> str:
    return str(uuid.uuid4())