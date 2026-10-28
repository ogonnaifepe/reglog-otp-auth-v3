from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from ipaddress import ip_address, ip_network

from app.routes import (
    auth_router,
    otp_router,
    admin_router,
    admin_customer_router,
)
from app.config import Config
from app.database import db
from app import auth_logger
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# IP SAFELIST  restrict admin paths to trusted networks
# ============================================================
_allowed_raw = os.getenv("IP_SAFELIST_NETWORKS", "127.0.0.1/32")
ALLOWED_ADMIN_NETWORKS = []
for cidr in _allowed_raw.split(","):
    cidr = cidr.strip()
    if cidr:
        try:
            ALLOWED_ADMIN_NETWORKS.append(ip_network(cidr))
        except ValueError:
            logger.error(f"Invalid CIDR in IP_SAFELIST_NETWORKS: {cidr}")

# Paths that require IP restriction
ADMIN_PROTECTED_PREFIXES = (
    "/api/v1/admin",
    "/docs",
    "/redoc",
    "/openapi.json",
)


app = FastAPI(
    title="FastAPI OTP Authentication System",
    description="Authentication API with OTP verification + Admin Backend",
    version="2.0.0",
    debug=Config.DEBUG,
    docs_url="/docs" if Config.ENABLE_DOCS else None,
    redoc_url="/redoc" if Config.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if Config.ENABLE_DOCS else None,
)


# ============================================================
# CORS  open for internal testing
# ============================================================
# Note: allow_credentials MUST be False when using wildcard origins.
# The frontend uses bearer tokens (Authorization header), not cookies,
# so this is fine. Change to an explicit origin list before going public.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# ============================================================
# IP SAFELIST MIDDLEWARE
# ============================================================
@app.middleware("http")
async def ip_safelist_middleware(request: Request, call_next):
    """
    Restrict admin paths to trusted networks.
    Non-admin paths pass through freely.
    """
    path = request.url.path

    if path.startswith(ADMIN_PROTECTED_PREFIXES):
        client_ip = _extract_client_ip(request)

        if not client_ip:
            return JSONResponse(status_code=403, content={"detail": "Client IP unavailable"})

        try:
            ip = ip_address(client_ip)
        except ValueError:
            return JSONResponse(status_code=403, content={"detail": "Invalid client IP"})

        allowed = any(ip in net for net in ALLOWED_ADMIN_NETWORKS)

        if not allowed:
            logger.warning(f"IP safelist blocked access to {path} from {client_ip}")
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied from your network"},
            )

    return await call_next(request)


def _extract_client_ip(request: Request) -> str | None:
    """Extract client IP, respecting X-Forwarded-For if present."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


# ============================================================
# SECURITY HEADERS MIDDLEWARE (path-aware CSP)
# ============================================================
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)

    if Config.ENABLE_SECURITY_HEADERS:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        path = request.url.path
        is_docs_page = (
            path.startswith("/docs")
            or path.startswith("/redoc")
            or path.startswith("/openapi.json")
        )

        if is_docs_page:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
                "font-src 'self' https://cdn.jsdelivr.net data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'"
            )

    return response


# ============================================================
# GLOBAL EXCEPTION HANDLER
# ============================================================
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    ip = _extract_client_ip(request)
    auth_logger.log_event(
        "unhandled_exception",
        ip=ip,
        success=False,
        details={"path": str(request.url.path), "error": str(exc)},
    )
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ============================================================
# ROUTERS
# ============================================================
app.include_router(auth_router)
app.include_router(otp_router)
app.include_router(admin_router)
app.include_router(admin_customer_router)


# ============================================================
# ROOT + HEALTH
# ============================================================
@app.get("/")
async def root():
    return {
        "message": "FastAPI OTP Authentication System",
        "version": "2.0.0",
        "status": "running",
    }


@app.get("/health")
async def health_check():
    if not Config.DEBUG:
        try:
            db.connection.cursor().execute("SELECT 1 FROM DUAL")
            return {"status": "ok"}
        except Exception:
            return {"status": "degraded"}

    try:
        cursor = db.connection.cursor()
        cursor.execute("SELECT 1 FROM DUAL")
        cursor.fetchone()
        cursor.close()
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        db_status = "unhealthy"
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "database": db_status,
    }


@app.on_event("shutdown")
def shutdown_event():
    db.close()
    logger.info("Application shutdown complete")