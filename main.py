# ============================================================
# OWASP Security — main.py
# Application entry point — runs bot + web server concurrently.
# ============================================================

import asyncio
import sys
import os
import uvicorn
from loguru import logger
from config import settings

# ── Configure loguru ──────────────────────────────────────────
def setup_logging():
    os.makedirs("logs", exist_ok=True)
    logger.remove()
    logger.add(
        sys.stdout,
        level=settings.LOG_LEVEL,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan> — <level>{message}</level>",
        colorize=True,
    )
    logger.add("logs/app.log", level="DEBUG", rotation="10 MB", retention="7 days", compression="zip")
    logger.info("Logging configured.")

async def main():
    setup_logging()
    logger.info("=" * 60)
    logger.info("  OWASP Secure Scanner — Starting up")
    logger.info("=" * 60)

    # 1. Initialize DB first
    from database.database import init_db
    await init_db()

    # 2. Get Bot instance
    from bot.bot import dp, bot
    
    # 3. Setup web server config
    # Use global settings.WEB_PORT which now respects Heroku's $PORT
    config = uvicorn.Config(
        app="web.app:app",
        host="0.0.0.0",
        port=settings.WEB_PORT,
        log_level="info",
        loop="asyncio"
    )
    server = uvicorn.Server(config)

    logger.info(f"[WEB] Starting on port {settings.WEB_PORT}")
    logger.info(f"[BOT] Starting polling...")

    # 4. Run both concurrently
    # We use create_task to ensure web starts binding ASAP
    web_task = asyncio.create_task(server.serve())
    bot_task = asyncio.create_task(dp.start_polling(bot))

    # Keep running until one of them fails
    await asyncio.gather(web_task, bot_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutdown requested.")
