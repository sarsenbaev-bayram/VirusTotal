# ============================================================
# OWASP Security — bot/middlewares/rate_limiter.py
# Aiogram middleware that enforces per-user rate limiting.
# OWASP A04: Insecure Design — all bot commands are protected
# ============================================================

from typing import Callable, Dict, Any, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Message
from services.rate_limiter import rate_limiter
from loguru import logger


class RateLimitMiddleware(BaseMiddleware):
    """Aiogram v3 middleware that checks the shared rate limiter
    before every update reaches a handler.

    If the user exceeds the limit, we reply with a friendly
    message and drop the update — no handler is called.
    """

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        # Extract user id from the event (works for Message, CallbackQuery, etc.)
        user = data.get("event_from_user")
        if user is None:
            # No user context — let it through (e.g. channel posts)
            return await handler(event, data)

        key = f"bot_user_{user.id}"

        if not rate_limiter.is_allowed(key):
            remaining_info = rate_limiter.remaining(key)
            logger.warning(
                f"[RATE LIMIT] Bot user {user.id} (@{user.username}) blocked."
            )
            # Reply only to Message events (not to callbacks etc.)
            if isinstance(event, Message):
                # Try to get localized message, fallback to default English if I18nMiddleware hasn't run yet
                msg = data.get("_", {}).get("rate_limit", "⚠️ Too many requests. Please wait a bit.")
                await event.answer(msg, parse_mode="HTML")
            return  # Drop the update — don't call the handler

        # Within limit — pass control to the next middleware / handler
        return await handler(event, data)
