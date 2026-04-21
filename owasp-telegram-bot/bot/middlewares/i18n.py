from typing import Callable, Dict, Any, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, User as TGUser
from database.database import AsyncSessionLocal
from database.crud import get_user, create_user
from bot.locales import MESSAGES
from loguru import logger

class I18nMiddleware(BaseMiddleware):
    """Middleware to handle user localization."""
    
    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        tg_user: TGUser = data.get("event_from_user")
        
        if not tg_user:
            return await handler(event, data)

        async with AsyncSessionLocal() as db:
            user = await get_user(db, tg_user.id)
            if not user:
                # Create user in DB if they don't exist
                user = await create_user(
                    db, 
                    telegram_id=tg_user.id, 
                    username=tg_user.username,
                    language=tg_user.language_code if tg_user.language_code in ["uz", "en"] else "uz"
                )
                logger.info(f"[DB] New user registered: {tg_user.id} ({user.language})")
            
            # Inject language and localized messages into data
            data["lang"] = user.language
            data["_"] = MESSAGES.get(user.language, MESSAGES["uz"])
            data["db"] = db # Also pass the db session for convenience

            return await handler(event, data)
