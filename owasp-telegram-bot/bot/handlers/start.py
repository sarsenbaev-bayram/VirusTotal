# ============================================================
# OWASP Security — bot/handlers/start.py
# Handles the /start command — welcome screen with instructions.
# ============================================================

from aiogram import Router
from aiogram.filters import CommandStart
from aiogram.types import Message
from loguru import logger

# Each handler module gets its own Router, registered in bot.py
router = Router(name="start")


@router.message(CommandStart())
async def start_handler(message: Message, _: dict) -> None:
    """Send a friendly welcome message explaining all bot commands."""
    user = message.from_user
    logger.info(f"[BOT] /start from user_id={user.id} username={user.username}")

    await message.answer(
        _["welcome"].format(name=user.first_name),
        parse_mode="HTML",
    )
