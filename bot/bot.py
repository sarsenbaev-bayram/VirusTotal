# ============================================================
# OWASP Security — bot/bot.py
# Aiogram bot initialization, dispatcher, middleware registration.
# ============================================================

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

from config import settings
from bot.middlewares.rate_limiter import RateLimitMiddleware
from bot.middlewares.i18n import I18nMiddleware
from bot.handlers import start, scan_url, scan_hash, language, admin
from loguru import logger


def create_bot() -> Bot:
    """Instantiate the Aiogram Bot with secure defaults."""
    return Bot(
        token=settings.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )


def create_dispatcher() -> Dispatcher:
    """Build the Dispatcher and register all routers + middlewares."""
    dp = Dispatcher()

    # ── Middlewares ───────────────────────────────────────────
    dp.message.middleware(I18nMiddleware())
    dp.message.middleware(RateLimitMiddleware())
    dp.callback_query.middleware(I18nMiddleware())

    # ── Register command routers ──────────────────────────────
    dp.include_router(admin.router)
    dp.include_router(start.router)
    dp.include_router(scan_url.router)
    dp.include_router(scan_hash.router)
    dp.include_router(language.router)

    logger.info("[BOT] Dispatcher configured with rate limiter and all handlers.")
    return dp


async def start_bot() -> None:
    """Entry point for the Telegram bot polling loop.
    Called from main.py as an async task."""
    bot = create_bot()
    dp = create_dispatcher()

    # Delete any pending webhook (important if switching from webhook mode)
    await bot.delete_webhook(drop_pending_updates=True)

    logger.info("[BOT] Starting polling...")
    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()
        logger.info("[BOT] Bot stopped and session closed.")
