# ============================================================
# OWASP Security — bot/handlers/scan_hash.py
# Handles /scan_hash command — validates hash, scans, explains.
# OWASP A03: Injection — strict hex-only regex validation
# ============================================================

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from loguru import logger

from services.validator import validate_hash, ValidationError
from services.virustotal import scan_hash as vt_scan_hash
from services.gemini_service import explain_scan_result
from database.database import AsyncSessionLocal
from database.crud import save_scan

router = Router(name="scan_hash")

_RISK_EMOJI = {
    "Low": "🟢",
    "Medium": "🟡",
    "High": "🔴",
    "Unknown": "⚪",
}


@router.message(Command("scan_hash"))
async def scan_hash_handler(message: Message, _: dict, lang: str, db) -> None:
    """
    Usage: /scan_hash <md5|sha1|sha256>
    """
    user = message.from_user
    parts = message.text.strip().split(maxsplit=1)

    if len(parts) < 2 or not parts[1].strip():
        await message.answer(_["scan_hash_prompt"], parse_mode="HTML")
        return

    raw_hash = parts[1].strip()

    # ── OWASP A03: Validate — only hex chars, correct length ──
    try:
        clean_hash = validate_hash(raw_hash)
    except ValidationError:
        await message.answer(_["invalid_hash"], parse_mode="HTML")
        return

    status_msg = await message.answer(_["scanning"], parse_mode="HTML")

    logger.info(f"[BOT] Hash scan started — user={user.id} hash={clean_hash}")

    try:
        # ── VirusTotal hash lookup ────────────────────────────
        vt_result = await vt_scan_hash(clean_hash)

        # ── AI explanation ────────────────────────────────────
        explanation = await explain_scan_result(
            scan_type="hash",
            target=clean_hash,
            malicious_count=vt_result["malicious_count"],
            total_engines=vt_result["total_engines"],
            risk_level=vt_result["risk_level"],
            raw_stats=vt_result["raw"],
            language="uzbek" if lang == "uz" else "english"
        )

        # ── Persist to database ───────────────────────────────
        await save_scan(
            db,
            scan_type="hash",
            target=clean_hash,
            source="bot",
            telegram_user_id=user.id,
            malicious_count=vt_result["malicious_count"],
            total_engines=vt_result["total_engines"],
            risk_level=vt_result["risk_level"],
            ai_explanation=explanation,
        )

        risk = vt_result["risk_level"]
        localized_risk = _["risk_" + risk.lower()]

        result_text = _["scan_result"].format(
            target=clean_hash,
            malicious=vt_result['malicious_count'],
            total=vt_result['total_engines'],
            risk_level=localized_risk,
            ai_explanation=explanation
        )

        await status_msg.edit_text(result_text, parse_mode="HTML")

    except Exception as e:
        logger.exception(f"[BOT] Error in scan_hash for user {user.id}")
        await status_msg.edit_text(_["error"], parse_mode="HTML")
