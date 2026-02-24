"""
redis_client.py
---------------
Cliente Redis optimizado para el Motor Antifraude — Wallet Plux.

Mejoras sobre el cliente original:
  - Pool de conexiones con parámetros explícitos para alto volumen
  - Health check al conectar: falla rápido si Redis no está disponible
  - Retry automático con backoff exponencial (3 intentos antes de fallar)
  - socket_connect_timeout separado de socket_timeout
  - decode_responses=False porque algunos módulos guardan JSON como bytes
    y otros como string — se maneja en cada módulo con .decode() explícito
  - Logging estructurado para cada evento del ciclo de vida
  - Propiedad .is_connected para verificar estado desde el orquestador

Uso en FastAPI (app/main.py):
    @app.on_event("startup")
    async def startup():
        await redis_manager.connect()

    @app.on_event("shutdown")
    async def shutdown():
        await redis_manager.disconnect()
"""

import asyncio
import logging

import redis.asyncio as redis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import BusyLoadingError, ConnectionError, TimeoutError

from app.core.config import settings

logger = logging.getLogger(__name__)


class RedisManager:
    """
    Gestor del cliente Redis con reconexión automática y health check.

    Parámetros del pool explicados:
      max_connections=200   → soporta hasta 200 coroutines simultáneas
                              esperando una conexión del pool
      socket_timeout=0.5    → tiempo máximo para operaciones de lectura/escritura
                              si Redis tarda más de 500ms algo está muy mal
      socket_connect_timeout=2.0 → tiempo máximo para establecer la conexión
                              más generoso que el timeout de operación
      socket_keepalive=True → mantiene las conexiones TCP vivas para evitar
                              que el firewall/NAT las cierre por inactividad
      health_check_interval=30 → Redis verifica internamente que las
                              conexiones del pool siguen vivas cada 30s
    """

    def __init__(self):
        self.client: redis.Redis | None = None
        self._connected: bool = False

    @property
    def is_connected(self) -> bool:
        return self._connected and self.client is not None

    async def connect(self) -> None:
        """
        Inicializa el pool de conexiones y verifica que Redis responda.
        Llama desde el evento startup de FastAPI.
        Lanza excepción si Redis no está disponible al arrancar.
        """
        logger.info(f"[Redis] Conectando a {settings.REDIS_URL} ...")

        # Retry automático con backoff exponencial para operaciones fallidas.
        # Solo aplica a errores de red, no a errores de lógica.
        retry = Retry(
            backoff    = ExponentialBackoff(cap=0.5, base=0.1),
            retries    = 3,
            supported_errors = (ConnectionError, TimeoutError, BusyLoadingError),
        )

        self.client = redis.Redis.from_url(
            settings.REDIS_URL,
            # ── Pool de conexiones ─────────────────────────────────
            max_connections         = 200,
            # ── Timeouts ──────────────────────────────────────────
            socket_timeout          = 0.5,    # máx 500ms por operación
            socket_connect_timeout  = 2.0,    # máx 2s para conectar
            # ── Keepalive ─────────────────────────────────────────
            socket_keepalive        = True,
            socket_keepalive_options = {},
            # ── Health check interno del pool ──────────────────────
            health_check_interval   = 30,
            # ── Retry automático ───────────────────────────────────
            retry                   = retry,
            retry_on_timeout        = True,
            # ── Encoding ──────────────────────────────────────────
            # False porque los módulos manejan bytes/str explícitamente
            decode_responses        = False,
        )

        # Verificar que Redis responde antes de declarar éxito
        await self._health_check(raise_on_fail=True)
        self._connected = True
        logger.info("[Redis] Conexión establecida y verificada ✓")

    async def disconnect(self) -> None:
        """
        Cierra todas las conexiones del pool limpiamente.
        Llama desde el evento shutdown de FastAPI.
        """
        if self.client:
            try:
                await self.client.aclose()
                self._connected = False
                logger.info("[Redis] Conexiones cerradas correctamente ✓")
            except Exception as e:
                logger.error(f"[Redis] Error al cerrar conexiones: {e}")

    async def _health_check(self, raise_on_fail: bool = False) -> bool:
        """
        Envía un PING a Redis y verifica la respuesta.

        raise_on_fail=True  → lanza excepción (usar en startup)
        raise_on_fail=False → retorna bool (usar en checks periódicos)
        """
        try:
            response = await asyncio.wait_for(
                self.client.ping(),
                timeout=2.0,
            )
            if response:
                return True
            raise ConnectionError("Redis PING retornó False")

        except asyncio.TimeoutError:
            msg = "[Redis] Health check timeout — Redis no responde en 2s"
            logger.error(msg)
            if raise_on_fail:
                raise ConnectionError(msg)
            return False

        except Exception as e:
            msg = f"[Redis] Health check falló: {e}"
            logger.error(msg)
            if raise_on_fail:
                raise
            return False

    async def ping(self) -> bool:
        """
        Health check público para usar desde el endpoint /health de FastAPI.

        Ejemplo en main.py:
            @app.get("/health")
            async def health():
                redis_ok = await redis_manager.ping()
                return {"redis": "ok" if redis_ok else "degraded"}
        """
        if not self.client:
            return False
        return await self._health_check(raise_on_fail=False)


# Singleton — misma interfaz que el cliente original
redis_manager = RedisManager()