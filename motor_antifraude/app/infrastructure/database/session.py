"""
session.py
----------
Configuración de la conexión asíncrona a PostgreSQL.

Provee:
  - engine: motor SQLAlchemy async con pool configurado
  - AsyncSessionLocal: fábrica de sesiones
  - get_db: dependency de FastAPI para inyectar sesión en routers
  - init_db: crea tablas en desarrollo (en producción usa Alembic)
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

# Fix asyncpg issue with sslmode
db_url = settings.DATABASE_URL
if "?sslmode=" in db_url:
    db_url = db_url.split("?sslmode=")[0]

# ── Motor de base de datos ────────────────────────────────────────────
engine = create_async_engine(
    db_url,
    echo           = settings.DEBUG,   # Loggea SQL solo en desarrollo
    pool_pre_ping  = True,             # Verifica conexión antes de usarla
    pool_size      = 10,               # Conexiones permanentes en el pool
    max_overflow   = 20,               # Conexiones extra bajo carga alta
)

# ── Fábrica de sesiones ───────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind           = engine,
    class_         = AsyncSession,
    expire_on_commit = False,
    autocommit     = False,
    autoflush      = False,
)


# ── Dependency para FastAPI ───────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Inyecta una sesión de base de datos en cada request.
    Se cierra automáticamente al terminar el request.

    Uso en un router:
        @router.post("/algo")
        async def mi_endpoint(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Init para desarrollo ─────────────────────────────────────────────
async def init_db() -> None:
    """
    Crea todas las tablas definidas en models.py.
    Solo usar en desarrollo — en producción usar Alembic.
    Llamar desde el lifespan de main.py si settings.DEBUG es True.
    """
    from app.domain.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)