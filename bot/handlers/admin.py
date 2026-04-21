# ============================================================
# OWASP Security — bot/handlers/admin.py
# Admin-only commands for statistics and management.
# ============================================================

from aiogram import Router, F
from aiogram.types import Message
from aiogram.filters import Command
from config import settings
from database.database import get_db
from database.crud import get_stats
from loguru import logger

router = Router()

@router.message(Command("admin"), F.from_user.id == settings.ADMIN_ID)
async def admin_panel(message: Message):
    """Show quick statistics to the admin."""
    logger.info(f"[ADMIN] Statistics requested by {message.from_user.id}")
    
    async for db in get_db():
        stats = await get_stats(db)
        
        text = (
            "<b>📊 Admin Statistics Panel</b>\n\n"
            f"👥 <b>Total Users:</b> {stats['users']}\n"
            f"🔍 <b>Total Scans:</b> {stats['scans']}\n"
            f"⚠️ <b>Threats Found:</b> {stats['malicious']}\n\n"
            "<i>Note: Only you can see this message.</i>"
        )
        
        await message.answer(text)
        break # Only need one DB session

@router.message(Command("admin"))
async def admin_denied(message: Message):
    """Handle unauthorized access to admin command."""
    # We silently ignore or give a generic error to prevent 
    # revealing that there's an admin command (Security through obscurity/A01).
    logger.warning(f"[SECURITY] Unauthorized /admin access attempt from {message.from_user.id}")
    await message.answer("Sizda ushbu buyruqni bajarish uchun ruxsat yo'q.")
