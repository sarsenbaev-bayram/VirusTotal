# ============================================================
# OWASP Security — database/crud.py
# All database Create / Read operations via ORM (no raw SQL).
# OWASP A03: Injection → parameterized queries only
# ============================================================

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from database.models import ScanResult, ScanType, RiskLevel, User
from loguru import logger
from datetime import datetime


async def get_user(db: AsyncSession, telegram_id: int) -> User | None:
    """Fetch user by telegram_id."""
    stmt = select(User).where(User.telegram_id == telegram_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def create_user(
    db: AsyncSession, telegram_id: int, username: str | None = None, language: str = "uz"
) -> User:
    """Create a new user record."""
    user = User(telegram_id=telegram_id, username=username, language=language)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def set_user_language(db: AsyncSession, telegram_id: int, language: str) -> None:
    """Update user's preferred language."""
    user = await get_user(db, telegram_id)
    if user:
        user.language = language
        await db.commit()


async def save_scan(
    db: AsyncSession,
    *,
    scan_type: str,
    target: str,
    source: str = "web",
    telegram_user_id: int | None = None,
    malicious_count: int,
    total_engines: int,
    risk_level: str,
    ai_explanation: str,
) -> ScanResult:
    """Insert a new scan record and return the created object.

    All fields are passed as keyword arguments to avoid accidental
    positional mix-ups (readability + correctness).
    """
    record = ScanResult(
        scan_type=scan_type,
        target=target,
        source=source,
        telegram_user_id=telegram_user_id,
        malicious_count=malicious_count,
        total_engines=total_engines,
        risk_level=risk_level,
        ai_explanation=ai_explanation,
        created_at=datetime.utcnow(),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    logger.info(
        f"[DB] Saved scan — id={record.id} type={scan_type} "
        f"target={target[:40]} risk={risk_level}"
    )
    return record


async def get_history(
    db: AsyncSession, limit: int = 50
) -> list[ScanResult]:
    """Return the most recent `limit` scan records, newest first."""
    stmt = select(ScanResult).order_by(desc(ScanResult.created_at)).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_scan_by_id(
    db: AsyncSession, scan_id: int
) -> ScanResult | None:
    """Fetch a single scan result by primary key."""
    stmt = select(ScanResult).where(ScanResult.id == scan_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
