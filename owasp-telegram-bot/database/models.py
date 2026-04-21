# ============================================================
# OWASP Security — database/models.py
# SQLAlchemy ORM models. Using ORM prevents raw SQL injection.
# OWASP A03: Injection → parameterised queries via ORM
# ============================================================

from datetime import datetime
from sqlalchemy import String, Integer, Text, DateTime, Enum
from sqlalchemy.orm import Mapped, mapped_column
from database.database import Base
import enum


class ScanType(str, enum.Enum):
    """Allowed scan types — enforced at DB level (OWASP A03)."""
    URL = "url"
    HASH = "hash"


class RiskLevel(str, enum.Enum):
    """Standardised risk labels returned to users."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    UNKNOWN = "Unknown"


class User(Base):
    """Stores Telegram user preferences."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    telegram_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    language: Mapped[str] = mapped_column(String(2), default="uz")  # 'uz' or 'en'
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<User id={self.id} telegram_id={self.telegram_id} lang={self.language}>"


class ScanResult(Base):
    """Stores every scan performed via bot or web app.

    Security notes:
    - `target` is stored as-is (already validated before insert).
    - `ai_explanation` may be long — Text column, no length limit.
    - No user passwords or PII are stored here.
    """

    __tablename__ = "scan_results"

    # ── Primary key ───────────────────────────────────────────
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # ── What was scanned ──────────────────────────────────────
    scan_type: Mapped[str] = mapped_column(
        Enum(ScanType), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(String(2048), nullable=False)

    # ── Source: 'bot' or 'web' ────────────────────────────────
    source: Mapped[str] = mapped_column(String(16), default="web")

    # ── Telegram user ID (optional — only set from bot) ───────
    telegram_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── VirusTotal results ────────────────────────────────────
    malicious_count: Mapped[int] = mapped_column(Integer, default=0)
    total_engines: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(
        Enum(RiskLevel), default=RiskLevel.UNKNOWN
    )

    # ── AI-generated explanation ──────────────────────────────
    ai_explanation: Mapped[str] = mapped_column(Text, default="")

    # ── Timestamps ────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )

    def __repr__(self) -> str:
        return (
            f"<ScanResult id={self.id} type={self.scan_type} "
            f"risk={self.risk_level} target={self.target[:40]}>"
        )
