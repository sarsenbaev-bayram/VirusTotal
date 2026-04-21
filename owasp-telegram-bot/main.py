# ============================================================
# OWASP Security — main.py
# Application entry point — runs bot + web server concurrently.
# ============================================================

import asyncio
import sys
import uvicorn
from loguru import logger
from config import settings


# ── Configure loguru ──────────────────────────────────────────
def setup_logging():
    """Configure loguru with rotating file + console output.
    OWASP A09: Logging & Monitoring — structured, persistent logs."""
    import os
    os.makedirs("logs", exist_ok=True)

    logger.remove()  # Remove default handler

    # Console handler
    logger.add(
        sys.stdout,
        level=settings.LOG_LEVEL,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{line}</cyan> — <level>{message}</level>",
        colorize=True,
    )

    # Rotating file handler (10 MB max, keep 7 days)
    logger.add(
        "logs/app.log",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{line} — {message}",
        rotation="10 MB",
        retention="7 days",
        compression="zip",
    )
    logger.info("Logging configured.")


async def run_web():
    """Start the uvicorn ASGI server for the FastAPI web app."""
    config = uvicorn.Config(
        app="web.app:app",
        host=settings.WEB_HOST,
        port=settings.WEB_PORT,
        log_level=settings.LOG_LEVEL.lower(),
        reload=False,
    )
    server = uvicorn.Server(config)
    logger.info(f"[WEB] Starting on http://{settings.WEB_HOST}:{settings.WEB_PORT}")
    await server.serve()


async def run_bot():
    """Start the Telegram bot polling loop."""
    from bot.bot import start_bot
    await start_bot()


async def main():
    """Run both the web server and the Telegram bot concurrently."""
    setup_logging()
    logger.info("=" * 60)
    logger.info("  OWASP Secure Scanner — Starting up")
    logger.info("=" * 60)

    # Run web + bot as concurrent async tasks
    await asyncio.gather(
        run_web(),
        run_bot(),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user (Ctrl+C). Exiting cleanly.")
