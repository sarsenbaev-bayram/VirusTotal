# ============================================================
# OWASP Security — web/app.py
# FastAPI application factory with security middleware.
# OWASP A05: Security Misconfiguration → security headers set
# OWASP A07: Auth failures → no sensitive data in errors
# ============================================================

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger
import os

from web.routers import scan, history


# ── Security Headers Middleware ───────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add OWASP-recommended HTTP security headers to every response.

    Headers added:
    - X-Content-Type-Options: Prevents MIME-type sniffing (XSS vector)
    - X-Frame-Options: Prevents clickjacking
    - X-XSS-Protection: Legacy XSS filter for older browsers
    - Content-Security-Policy: Controls which resources can be loaded
    - Referrer-Policy: Limits referrer information leakage
    - Permissions-Policy: Disables unnecessary browser features
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self';"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        return response


def create_app() -> FastAPI:
    """Application factory — builds and configures the FastAPI app."""

    app = FastAPI(
        title="OWASP Security Scanner",
        description="Scan URLs and file hashes with VirusTotal + AI analysis.",
        version="1.0.0",
        # Hide OpenAPI docs in production (comment out to enable)
        # docs_url=None,
        # redoc_url=None,
    )

    # ── Security headers on every response ───────────────────
    app.add_middleware(SecurityHeadersMiddleware)

    # ── Mount static files ────────────────────────────────────
    static_dir = os.path.join("web", "static")
    os.makedirs(static_dir, exist_ok=True)
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # ── Register routers ──────────────────────────────────────
    app.include_router(scan.router)
    app.include_router(history.router)

    # ── Global exception handler (OWASP A09) ─────────────────
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        # Don't expose internal paths or stack traces
        return JSONResponse(
            status_code=404,
            content={"error": "Page not found."},
        )

    @app.exception_handler(500)
    async def server_error_handler(request: Request, exc):
        logger.exception(f"[WEB] Unhandled 500 error on {request.url.path}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error. Please try again later."},
        )

    # ── Startup event ─────────────────────────────────────────
    @app.on_event("startup")
    async def on_startup():
        from database.database import init_db
        await init_db()
        logger.info("[WEB] FastAPI application started.")

    # ── Health Check (for Docker/ALB) ─────────────────────────
    @app.get("/health", tags=["monitoring"])
    async def health_check():
        return {"status": "healthy"}

    logger.info("[WEB] FastAPI app created with security middleware.")
    return app


# ── Module-level app instance (used by uvicorn) ───────────────
app = create_app()
