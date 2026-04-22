# ============================================================
# OWASP Security — bot/handlers/menu.py
# Handles text menu button clicks (emoji buttons).
# ============================================================

from aiogram import Router, F
from aiogram.types import Message
from bot.handlers.language import get_language_kb
from bot.handlers.scan_url import scan_url_handler
from bot.handlers.scan_hash import scan_hash_handler
from loguru import logger

router = Router(name="menu")

@router.message(F.text)
async def menu_text_handler(message: Message, _: dict, lang: str, db) -> None:
    """Handles text input from the persistent menu keyboard."""
    text = message.text
    
    # Map button text to actions based on localization
    if text == _["btn_url"]:
        await message.answer(_["scan_url_prompt"], parse_mode="HTML")
    
    elif text == _["btn_hash"]:
        await message.answer(_["scan_hash_prompt"], parse_mode="HTML")
    
    elif text == _["btn_lang"]:
        await message.answer(_["select_language"], reply_markup=get_language_kb())
        
    elif text == _["btn_history"]:
        # Direct them to the web dashboard for history
        from config import settings
        # Assuming there is a settings.BASE_URL or similar. 
        # For now, just a message or a button.
        await message.answer(
            f"📊 <b>Skanerlash tarixi</b>\n\n"
            f"Barcha skanerlash natijalaringizni veb-panelimiz orqali ko'rishingiz mumkin.\n"
            f"🌐 <a href='{settings.BASE_URL}/history'>Tarix sahifasiga o'tish</a>",
            parse_mode="HTML"
        )
    else:
        # If it's not a menu button, it might be a raw URL or Hash to scan
        # We can try to auto-detect if they just sent a URL or Hash without a command
        pass
