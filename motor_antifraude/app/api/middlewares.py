"""
middlewares.py
--------------
Middlewares del Motor Antifraude — Wallet Plux.

Middlewares incluidos:
  1. GeoEnrichmentMiddleware  → enriquece cada request con GeoIP y BIN
  2. SecurityHeadersMiddleware → agrega headers de seguridad HTTP
  3. setup_cors()             → configura CORS para web y móvil

Orden de registro en main.py (importa el orden):
  1. CORS            → primero, para que preflight requests pasen
  2. SecurityHeaders → segundo, aplica a todas las respuestas
  3. GeoEnrichment   → tercero, enriquece antes de llegar al router

El GeoEnrichmentMiddleware inyecta en request.state:
  - request.state.ip_country  → código ISO del país de la IP
  - request.state.ip_city     → ciudad
  - request.state.is_vpn      → True si es VPN/proxy/Tor
  - request.state.is_hosting  → True si es datacenter
  - request.state.bin_country → país del BIN (solo si viene card_bin en body)
  - request.state.card_type   → tipo de tarjeta
  - request.state.card_brand  → marca de la tarjeta

El router lee estos valores y los agrega al payload antes de pasarlo
al orquestador.
"""

import json
import logging
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.services.external_apis import geoip_client, bin_lookup_client

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# 1. GeoEnrichment Middleware
# ─────────────────────────────────────────────────────────────────────

class GeoEnrichmentMiddleware(BaseHTTPMiddleware):
    """
    Enriquece cada request al endpoint /evaluate con:
      - Datos geográficos de la IP (país, ciudad, VPN)
      - Datos del BIN de la tarjeta (país emisor, tipo, marca)

    Solo actúa en el endpoint de evaluación para no añadir latencia
    a otros endpoints como /health o /docs.

    Los datos se guardan en request.state para que el router
    los lea y los inyecte en el payload del motor.

    Flujo:
      Request llega → extraer IP real → consultar GeoIP (con caché)
      → si hay card_bin en body → consultar BIN (con caché)
      → guardar todo en request.state → continuar al router
    """

    # Solo enriquecer estos paths para no añadir latencia innecesaria
    ENRICH_PATHS = {"/v1/transactions/evaluate"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Solo enriquecer el endpoint de evaluación
        if request.url.path in self.ENRICH_PATHS:
            await self._enrich(request)

        response = await call_next(request)
        return response

    async def _enrich(self, request: Request) -> None:
        """
        Extrae la IP real y consulta GeoIP y BIN en paralelo.
        Si algo falla, pone defaults seguros en request.state
        para no bloquear la evaluación.
        """
        import asyncio

        # ── Extraer IP real ───────────────────────────────────────────
        # X-Forwarded-For viene cuando hay un proxy/load balancer delante.
        # Tomamos la primera IP de la lista (la del cliente original).
        # Si no hay proxy, usamos request.client.host directamente.
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        else:
            ip_address = request.client.host if request.client else "127.0.0.1"

        # ── Leer card_bin del body para BIN lookup ────────────────────
        # Necesitamos leer el body aquí para obtener el card_bin,
        # pero el body solo puede leerse una vez. Lo guardamos en
        # request.state para que el router no tenga que leerlo de nuevo.
        card_bin = None
        try:
            body_bytes = await request.body()
            if body_bytes:
                body_data = json.loads(body_bytes)
                card_bin  = body_data.get("card_bin")
                # Guardar el body parseado para que el router lo use
                request.state.body = body_data
        except Exception as e:
            logger.warning(f"[GeoEnrichment] No se pudo parsear el body: {e}")
            request.state.body = None

        # ── Consultar GeoIP y BIN en paralelo ─────────────────────────
        tasks = [geoip_client.lookup(ip_address)]
        if card_bin:
            tasks.append(bin_lookup_client.lookup(card_bin))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # ── GeoIP result ──────────────────────────────────────────────
        geo_result = results[0] if not isinstance(results[0], Exception) else None
        if geo_result and geo_result.success:
            request.state.ip_address  = ip_address
            request.state.ip_country  = geo_result.ip_country
            request.state.ip_city     = geo_result.ip_city
            request.state.is_vpn      = geo_result.is_vpn
            request.state.is_hosting  = geo_result.is_hosting
        else:
            # Default seguro: no bloquear por fallo de GeoIP
            request.state.ip_address  = ip_address
            request.state.ip_country  = "XX"
            request.state.ip_city     = "Unknown"
            request.state.is_vpn      = False
            request.state.is_hosting  = False
            if isinstance(results[0], Exception):
                logger.error(f"[GeoEnrichment] GeoIP falló: {results[0]}")

        # ── BIN result ────────────────────────────────────────────────
        if card_bin and len(results) > 1:
            bin_result = (
                results[1]
                if not isinstance(results[1], Exception)
                else None
            )
            if bin_result and bin_result.success:
                request.state.bin_country = bin_result.bin_country
                request.state.card_type   = bin_result.card_type
                request.state.card_brand  = bin_result.card_brand
                request.state.bank_name   = bin_result.bank_name
            else:
                request.state.bin_country = "XX"
                request.state.card_type   = "unknown"
                request.state.card_brand  = "unknown"
                request.state.bank_name   = "Unknown"
        else:
            request.state.bin_country = "XX"
            request.state.card_type   = "unknown"
            request.state.card_brand  = "unknown"
            request.state.bank_name   = "Unknown"

        logger.debug(
            f"[GeoEnrichment] ip={ip_address}  "
            f"country={request.state.ip_country}  "
            f"vpn={request.state.is_vpn}  "
            f"bin_country={request.state.bin_country}"
        )


# ─────────────────────────────────────────────────────────────────────
# 2. Security Headers Middleware
# ─────────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Agrega headers de seguridad HTTP a todas las respuestas.

    Headers incluidos:
      - X-Content-Type-Options    → evita MIME sniffing
      - X-Frame-Options           → evita clickjacking
      - X-XSS-Protection          → protección XSS en browsers legacy
      - Strict-Transport-Security → fuerza HTTPS (solo en producción)
      - Content-Security-Policy   → restricción de fuentes de contenido
      - Referrer-Policy           → controla información del referrer
      - Permissions-Policy        → deshabilita APIs del browser no necesarias
      - Cache-Control             → evita cacheo de respuestas sensibles
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Evita que el browser adivine el Content-Type
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Evita que la app sea embebida en un iframe (clickjacking)
        response.headers["X-Frame-Options"] = "DENY"

        # Protección XSS para browsers que no soportan CSP
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Fuerza HTTPS por 1 año (incluye subdominios)
        # Solo agregar en producción para no romper desarrollo local
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # Política de contenido: solo recursos del mismo origen
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        # No enviar el referrer a otros dominios
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Deshabilitar APIs del browser que no necesitamos
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        # No cachear respuestas de la API (contienen datos sensibles)
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private"
        )

        # Ocultar que usamos Python/FastAPI (no dar info al atacante)
        response.headers["Server"] = "Plux-API"

        return response


# ─────────────────────────────────────────────────────────────────────
# 3. CORS
# ─────────────────────────────────────────────────────────────────────

def setup_cors(app: FastAPI, allowed_origins: list[str]) -> None:
    """
    Configura CORS para permitir requests desde el frontend web y móvil.

    En desarrollo: permite localhost en puertos comunes.
    En producción: solo el dominio real del frontend.

    Llamar desde main.py antes de registrar otros middlewares:
        setup_cors(app, settings.ALLOWED_ORIGINS)

    Métodos permitidos:
      - GET    → health check, docs
      - POST   → evaluación de transacciones, checkout
      - OPTIONS → preflight requests del browser

    Headers permitidos:
      - Content-Type     → para enviar JSON
      - Authorization    → para futura autenticación JWT
      - X-Request-ID     → para tracing distribuido
      - X-Device-ID      → el frontend manda el device_id aquí también
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins     = allowed_origins,
        allow_credentials = True,
        allow_methods     = ["GET", "POST", "OPTIONS"],
        allow_headers     = [
            "Content-Type",
            "Authorization",
            "X-Request-ID",
            "X-Device-ID",
        ],
        # Cuánto tiempo el browser puede cachear el preflight (segundos)
        max_age           = 600,
    )