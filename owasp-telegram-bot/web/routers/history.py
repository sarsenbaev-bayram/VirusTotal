# ============================================================
# OWASP Security — web/routers/history.py
# GET /history — display recent scan history from database
# ============================================================

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from database.database import get_db
from database.crud import get_history
import os

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join("web", "templates"))


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Show the 50 most recent scans from both bot and web."""
    try:
        scans = await get_history(db, limit=50)
        logger.info(f"[WEB] History page loaded — {len(scans)} records")
        return templates.TemplateResponse(
            request=request, name="history.html",
            context={
                "request": request,
                "scans": scans,
                "total": len(scans),
            },
        )
    except Exception:
        logger.exception("[WEB] Error loading history page")
        return templates.TemplateResponse(
            request=request, name="history.html",
            context={
                "request": request,
                "scans": [],
                "total": 0,
                "error": "Could not load history. Please try again.",
            },
        )
