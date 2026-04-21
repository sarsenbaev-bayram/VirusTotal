# ============================================================
# OWASP Security — bot/handlers/language.py
# Handles language selection and switching.
# ============================================================

from aiogram import Router, F
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from database.crud import set_user_language
from loguru import logger

router = Router(name="language")

def get_language_kb() -> InlineKeyboardMarkup:
    """Returns an inline keyboard with language options."""
    buttons = [
        [
            InlineKeyboardButton(text="🇺🇿 O'zbekcha", callback_data="set_lang_uz"),
            InlineKeyboardButton(text="🇺🇸 English", callback_data="set_lang_en")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


@router.message(Command("language"))
async def language_command(message: Message, _: dict) -> None:
    """Displays language selection keyboard."""
    await message.answer(_["select_language"], reply_markup=get_language_kb())


@router.callback_query(F.data.startswith("set_lang_"))
async def set_language_callback(callback: CallbackQuery, db, _: dict) -> None:
    """Handles language selection callback."""
    lang = callback.data.replace("set_lang_", "")
    await set_user_language(db, callback.from_user.id, lang)
    
    # We need to refresh the localized messages since the language changed
    from bot.locales import MESSAGES
    new_messages = MESSAGES.get(lang, MESSAGES["uz"])
    
    await callback.message.edit_text(new_messages["language_changed"])
    await callback.answer()
    logger.info(f"[BOT] User {callback.from_user.id} changed language to {lang}")
