# ============================================================
# OWASP Security — config.py
# Central configuration loaded from environment variables.
# OWASP A05: Security Misconfiguration → never hardcode secrets
# ============================================================

import os
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv()


def _require(key: str) -> str:
    """Raise immediately if a required env var is missing.
    Prevents the app from silently starting with empty keys."""
    value = os.getenv(key)
    if not value:
        raise EnvironmentError(
            f"[CONFIG ERROR] Required environment variable '{key}' is missing. "
            f"Copy .env.example to .env and fill in all values."
        )
    return value


class Settings:
    # ── Telegram ──────────────────────────────────────────────
    BOT_TOKEN: str = _require("BOT_TOKEN")

    # ── External APIs ─────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = _require("VIRUSTOTAL_API_KEY")
    GEMINI_API_KEY: str = _require("GEMINI_API_KEY")

    # ── Admin Config ──────────────────────────────────────────
    # Your Telegram ID to restrict admin command access
    ADMIN_ID: int = int(os.getenv("ADMIN_ID", "7805185795"))

    # ── Web Server ────────────────────────────────────────────
    WEB_HOST: str = os.getenv("WEB_HOST", "0.0.0.0")
    # PORT is set by Heroku. We MUST prioritize it over .env settings.
    WEB_PORT: int = int(os.getenv("PORT") or os.getenv("WEB_PORT") or "8000")
    BASE_URL: str = os.getenv("BASE_URL", f"http://localhost:{WEB_PORT}")

    # ── Rate Limiting ─────────────────────────────────────────
    # Maximum scan requests per minute per user / IP
    RATE_LIMIT: int = int(os.getenv("RATE_LIMIT", "5"))

    # ── Database ──────────────────────────────────────────────
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "sqlite+aiosqlite:///./data/scans.db"
    )

    # ── Logging ───────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

    # ── VirusTotal base URL ───────────────────────────────────
    VT_BASE_URL: str = "https://www.virustotal.com/api/v3"

    # ── Input constraints (OWASP A03: Injection prevention) ───
    MAX_URL_LENGTH: int = 2048          # RFC 2616 practical max
    MAX_HASH_LENGTH: int = 64           # SHA-256 hex length
    ALLOWED_HASH_LENGTHS: tuple = (32, 40, 64)  # MD5, SHA1, SHA256


# Singleton settings object used by the whole project
settings = Settings()
