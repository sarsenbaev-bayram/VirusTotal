# ============================================================
# OWASP Security — database/database.py
# Async SQLAlchemy engine + session factory + init helper.
# OWASP A03: Injection → always use parameterized queries (ORM).
# ============================================================

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from config import settings
from loguru import logger
import os

# ── Ensure the data directory exists ─────────────────────────
os.makedirs("data", exist_ok=True)

# ── Create async engine ───────────────────────────────────────
# connect_args check_same_thread=False is required for SQLite
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,          # Set True for SQL debug logging
    connect_args={"check_same_thread": False},
)

# ── Session factory ───────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ── Base class for all ORM models ─────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Dependency for FastAPI routes ─────────────────────────────
async def get_db() -> AsyncSession:
    """FastAPI dependency that yields a database session
    and guarantees it is closed even on exceptions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Initialize all tables ─────────────────────────────────────
async def init_db():
    """Create all tables defined in the models if they don't exist."""
    from database import models  # noqa: F401 — import triggers table registration

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database initialized — all tables created.")
