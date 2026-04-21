# ============================================================
# OWASP Security — bot/handlers/scan_url.py
# Handles /scan_url command — validates, scans, explains.
# OWASP A03: Injection — input validated before any API call
# OWASP A09: Logging — every scan is logged with user info
# ============================================================

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from loguru import logger

from services.validator import validate_url, ValidationError
from services.virustotal import scan_url as vt_scan_url
from services.gemini_service import explain_scan_result
from database.database import AsyncSessionLocal
from database.crud import save_scan

router = Router(name="scan_url")

# ── Risk level to emoji mapping ───────────────────────────────
_RISK_EMOJI = {
    "Low": "🟢",
    "Medium": "🟡",
    "High": "🔴",
    "Unknown": "⚪",
}


@router.message(Command("scan_url"))
async def scan_url_handler(message: Message, _: dict, lang: str, db) -> None:
    """
    Usage: /scan_url <url>
    """
    user = message.from_user
    # ── Extract argument from command text ────────────────────
    parts = message.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.answer(_["scan_url_prompt"], parse_mode="HTML")
        return

    raw_url = parts[1].strip()

    # ── OWASP A03: Validate input before any processing ───────
    try:
        clean_url = validate_url(raw_url)
    except ValidationError:
        await message.answer(_["invalid_url"], parse_mode="HTML")
        return

    # ── Acknowledge the request immediately ───────────────────
    status_msg = await message.answer(_["scanning"], parse_mode="HTML")

    logger.info(f"[BOT] URL scan started — user={user.id} url={clean_url[:80]}")

    try:
        # ── Step 1: VirusTotal scan ───────────────────────────
        vt_result = await vt_scan_url(clean_url)

        # ── Step 2: AI explanation ────────────────────────────
        explanation = await explain_scan_result(
            scan_type="url",
            target=clean_url,
            malicious_count=vt_result["malicious_count"],
            total_engines=vt_result["total_engines"],
            risk_level=vt_result["risk_level"],
            raw_stats=vt_result["raw"],
            language="uzbek" if lang == "uz" else "english"
        )

        # ── Step 3: Save to database ──────────────────────────
        await save_scan(
            db,
            scan_type="url",
            target=clean_url,
            source="bot",
            telegram_user_id=user.id,
            malicious_count=vt_result["malicious_count"],
            total_engines=vt_result["total_engines"],
            risk_level=vt_result["risk_level"],
            ai_explanation=explanation,
        )

        risk = vt_result["risk_level"]
        localized_risk = _["risk_" + risk.lower()]

        # ── Step 4: Send result ───────────────────────────────
        result_text = _["scan_result"].format(
            target=clean_url[:50],
            malicious=vt_result['malicious_count'],
            total=vt_result['total_engines'],
            risk_level=localized_risk,
            ai_explanation=explanation
        )

        await status_msg.edit_text(result_text, parse_mode="HTML")

    except Exception as e:
        logger.exception(f"[BOT] Error in scan_url for user {user.id}")
        await status_msg.edit_text(_["error"], parse_mode="HTML")
