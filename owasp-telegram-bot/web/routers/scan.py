# ============================================================
# OWASP Security — web/routers/scan.py
# FastAPI routes: POST /scan/url and POST /scan/hash
# OWASP A03: Pydantic validates all input before processing
# OWASP A05: Security headers added via middleware in app.py
# ============================================================

from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from database.database import get_db
from database.crud import save_scan
from services.validator import validate_url, validate_hash, ValidationError
from services.virustotal import scan_url as vt_scan_url
from services.virustotal import scan_hash as vt_scan_hash
from services.gemini_service import explain_scan_result
from services.rate_limiter import rate_limiter

import os

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join("web", "templates"))

# ── Risk emoji helper ─────────────────────────────────────────
_RISK_EMOJI = {"Low": "🟢", "Medium": "🟡", "High": "🔴", "Unknown": "⚪"}


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, accounting for reverse proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ── Home page ─────────────────────────────────────────────────
@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})


# ── Scan URL — form POST ──────────────────────────────────────
@router.post("/scan/url", response_class=HTMLResponse)
async def scan_url_route(
    request: Request,
    url: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    rate_key = f"web_ip_{ip}"

    # ── Rate limiting ─────────────────────────────────────────
    if not rate_limiter.is_allowed(rate_key):
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={
                "request": request,
                "error": "⏳ Rate limit exceeded. Please wait a moment and try again.",
                "scan_type": "URL",
            },
            status_code=429,
        )

    # ── Input validation (OWASP A03) ──────────────────────────
    try:
        clean_url = validate_url(url)
    except ValidationError as ve:
        logger.warning(f"[WEB] URL validation failed from IP {ip}: {ve}")
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={
                "request": request,
                "error": str(ve),
                "scan_type": "URL",
                "input": url[:80],
            },
        )

    logger.info(f"[WEB] URL scan started — ip={ip} url={clean_url[:80]}")

    try:
        vt_result = await vt_scan_url(clean_url)
        explanation = await explain_scan_result(
            scan_type="url",
            target=clean_url,
            malicious_count=vt_result["malicious_count"],
            total_engines=vt_result["total_engines"],
            risk_level=vt_result["risk_level"],
            raw_stats=vt_result["raw"],
        )

        await save_scan(
            db,
            scan_type="url",
            target=clean_url,
            source="web",
            malicious_count=vt_result["malicious_count"],
            total_engines=vt_result["total_engines"],
            risk_level=vt_result["risk_level"],
            ai_explanation=explanation,
        )

        risk = vt_result["risk_level"]
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={
                "request": request,
                "scan_type": "URL",
                "target": clean_url,
                "risk": risk,
                "risk_emoji": _RISK_EMOJI.get(risk, "⚪"),
                "malicious": vt_result["malicious_count"],
                "total": vt_result["total_engines"],
                "permalink": vt_result["permalink"],
                "explanation": explanation,
                "raw": vt_result["raw"],
            },
        )

    except RuntimeError as e:
        logger.error(f"[WEB] Scan error from IP {ip}: {e}")
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={"request": request, "error": str(e), "scan_type": "URL"},
            status_code=502,
        )
    except Exception:
        logger.exception(f"[WEB] Unexpected error scanning URL from IP {ip}")
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={
                "request": request,
                "error": "An unexpected error occurred. Please try again.",
                "scan_type": "URL",
            },
            status_code=500,
        )


# ── Scan Hash — form POST ─────────────────────────────────────
@router.post("/scan/hash", response_class=HTMLResponse)
async def scan_hash_route(
    request: Request,
    file_hash: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    rate_key = f"web_ip_{ip}"

    if not rate_limiter.is_allowed(rate_key):
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={
                "request": request,
                "error": "⏳ Rate limit exceeded. Please wait a moment and try again.",
                "scan_type": "Hash",
            },
            status_code=429,
        )

    try:
        clean_hash = validate_hash(file_hash)
    except ValidationError as ve:
        logger.warning(f"[WEB] Hash validation failed from IP {ip}: {ve}")
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={
                "request": request,
                "error": str(ve),
                "scan_type": "Hash",
                "input": file_hash[:80],
            },
        )

    logger.info(f"[WEB] Hash scan started — ip={ip} hash={clean_hash}")

    try:
        vt_result = await vt_scan_hash(clean_hash)
        explanation = await explain_scan_result(
            scan_type="hash",
            target=clean_hash,
            malicious_count=vt_result["malicious_count"],
            total_engines=vt_result["total_engines"],
            risk_level=vt_result["risk_level"],
            raw_stats=vt_result["raw"],
        )

        await save_scan(
            db,
            scan_type="hash",
            target=clean_hash,
            source="web",
            malicious_count=vt_result["malicious_count"],
            total_engines=vt_result["total_engines"],
            risk_level=vt_result["risk_level"],
            ai_explanation=explanation,
        )

        risk = vt_result["risk_level"]
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={
                "request": request,
                "scan_type": "Hash",
                "target": clean_hash,
                "risk": risk,
                "risk_emoji": _RISK_EMOJI.get(risk, "⚪"),
                "malicious": vt_result["malicious_count"],
                "total": vt_result["total_engines"],
                "permalink": vt_result["permalink"],
                "explanation": explanation,
                "raw": vt_result["raw"],
                "note": vt_result.get("note", ""),
            },
        )

    except RuntimeError as e:
        logger.error(f"[WEB] Hash scan error from IP {ip}: {e}")
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={"request": request, "error": str(e), "scan_type": "Hash"},
            status_code=502,
        )
    except Exception:
        logger.exception(f"[WEB] Unexpected error scanning hash from IP {ip}")
        return templates.TemplateResponse(
            request=request, name="results.html",
            context={
                "request": request,
                "error": "An unexpected error occurred. Please try again.",
                "scan_type": "Hash",
            },
            status_code=500,
        )
