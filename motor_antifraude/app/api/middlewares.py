import json
import logging
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.services.external_apis import geoip_client, bin_lookup_client

logger = logging.getLogger(__name__)


class GeoEnrichmentMiddleware(BaseHTTPMiddleware):
    ENRICH_PATHS = {"/v1/transactions/evaluate"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self.ENRICH_PATHS:
            await self._enrich(request)

        response = await call_next(request)
        return response

    async def _enrich(self, request: Request) -> None:
        import asyncio

        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        else:
            ip_address = request.client.host if request.client else "127.0.0.1"

        card_bin = None
        try:
            body_bytes = await request.body()
            if body_bytes:
                body_data = json.loads(body_bytes)
                card_bin  = body_data.get("card_bin")
                request.state.body = body_data
        except Exception as e:
            logger.warning(f"[GeoEnrichment] No se pudo parsear el body: {e}")
            request.state.body = None

        tasks = [geoip_client.lookup(ip_address)]
        if card_bin:
            tasks.append(bin_lookup_client.lookup(card_bin))

        results: list = list(await asyncio.gather(*tasks, return_exceptions=True))

        raw_geo = results[0]
        geo_result = raw_geo if not isinstance(raw_geo, BaseException) else None
        if geo_result is not None and getattr(geo_result, "success", False):
            request.state.ip_address  = ip_address
            request.state.ip_country  = geo_result.ip_country
            request.state.ip_city     = geo_result.ip_city
            request.state.is_vpn      = geo_result.is_vpn
            request.state.is_hosting  = geo_result.is_hosting
        else:
            request.state.ip_address  = ip_address
            request.state.ip_country  = "XX"
            request.state.ip_city     = "Unknown"
            request.state.is_vpn      = False
            request.state.is_hosting  = False
            if isinstance(raw_geo, BaseException):
                logger.error(f"[GeoEnrichment] GeoIP falló: {raw_geo}")

        if card_bin and len(results) > 1:
            raw_bin = results[1]
            bin_result = raw_bin if not isinstance(raw_bin, BaseException) else None
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



class SecurityHeadersMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"

        response.headers["X-Frame-Options"] = "DENY"

        response.headers["X-XSS-Protection"] = "1; mode=block"

        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        if settings.DEBUG:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self' https://cdn.jsdelivr.net https://fastapi.tiangolo.com; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com"
            )
        else:
            response.headers["Content-Security-Policy"] = "default-src 'self'"

        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private"
        )

        response.headers["Server"] = "Plux-API"

        return response


def setup_cors(app: FastAPI, allowed_origins: list[str]) -> None:
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
            "X-Signature",
        ],
        max_age           = 600,
    )