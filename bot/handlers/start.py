# ============================================================
# OWASP Security — bot/handlers/start.py
# Handles the /start command — welcome screen with instructions.
# ============================================================

from aiogram import Router, F
from aiogram.filters import CommandStart
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton
from loguru import logger

# Each handler module gets its own Router, registered in bot.py
router = Router(name="start")


@router.message(CommandStart())
async def start_handler(message: Message, _: dict) -> None:
    """Send a friendly welcome message with a persistent menu keyboard."""
    user = message.from_user
    logger.info(f"[BOT] /start from user_id={user.id} username={user.username}")

    # Create the main menu keyboard
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [
                KeyboardButton(text=_["btn_url"]),
                KeyboardButton(text=_["btn_hash"]),
            ],
            [
                KeyboardButton(text=_["btn_history"]),
                KeyboardButton(text=_["btn_lang"]),
            ],
        ],
        resize_keyboard=True,
        placeholder="Menu...",
    )

    await message.answer(
        _["welcome"].format(name=user.first_name),
        parse_mode="HTML",
        reply_markup=keyboard,
    )
