"""
external_apis.py
----------------
Clientes para APIs externas del Motor Antifraude.

Provee:
  - GeoIPClient    → ip-api.com (país, ciudad, ISP, VPN/proxy detection)
  - BINLookupClient → binlist.net (país del BIN, tipo de tarjeta, banco emisor)

Principios de diseño:
  - Ambos clientes cachean resultados en Redis para no repetir llamadas
    por la misma IP o BIN en ventanas cortas de tiempo
  - Timeouts estrictos: si la API no responde en tiempo, retornan defaults
    seguros en lugar de bloquear el flujo del motor
  - En producción reemplazar GeoIPClient por MaxMind GeoLite2 local
    (sin llamadas HTTP, ~1ms de latencia, sin límite de requests)

Límites del plan gratuito de ip-api.com:
  - 45 requests/minuto desde la misma IP
  - Sin HTTPS en plan gratuito (usar solo en desarrollo)
  - En producción: MaxMind GeoLite2 o ip-api.com Pro
"""

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from app.infrastructure.cache.redis_client import redis_manager

logger = logging.getLogger(__name__)

# ── Timeouts ──────────────────────────────────────────────────────────
GEOIP_TIMEOUT_SEC  = 2.0   # ip-api.com debe responder en 2s
BIN_TIMEOUT_SEC    = 2.0   # binlist.net debe responder en 2s

# ── TTL de caché en Redis ─────────────────────────────────────────────
GEOIP_CACHE_TTL    = 60 * 60 * 6    # 6 horas — las IPs no cambian de país frecuentemente
BIN_CACHE_TTL      = 60 * 60 * 24   # 24 horas — los BINs son prácticamente estáticos


# ─────────────────────────────────────────────────────────────────────
# GeoIP
# ─────────────────────────────────────────────────────────────────────

@dataclass
class GeoIPResult:
    """Resultado del análisis geográfico de una IP."""
    ip_country:   str            # Código ISO del país (ej. "MX", "US")
    ip_city:      str            # Ciudad (ej. "Mexico City")
    ip_isp:       str            # Proveedor de internet (ej. "Telmex")
    is_vpn:       bool           # True si es VPN, proxy, Tor o datacenter
    is_hosting:   bool           # True si es un servidor/datacenter
    latitude:     float          # Coordenadas aproximadas de la IP
    longitude:    float
    success:      bool           # False si la consulta falló


# Resultado por defecto cuando la consulta falla
_GEO_DEFAULT = GeoIPResult(
    ip_country = "XX",     # XX = país desconocido
    ip_city    = "Unknown",
    ip_isp     = "Unknown",
    is_vpn     = False,
    is_hosting = False,
    latitude   = 0.0,
    longitude  = 0.0,
    success    = False,
)


class GeoIPClient:
    """
    Consulta ip-api.com para obtener información geográfica de una IP.

    Campos que solicitamos:
      status, country, countryCode, city, isp, proxy, hosting, lat, lon

    Caché en Redis:
      geo:ip:{ip_address} → JSON con el resultado
      TTL: 6 horas
    """

    API_URL    = "http://ip-api.com/json/{ip}"
    FIELDS     = "status,country,countryCode,city,isp,proxy,hosting,lat,lon"
    CACHE_KEY  = "geo:ip:{ip}"

    async def lookup(self, ip_address: str) -> GeoIPResult:
        """
        Obtiene información geográfica de una IP.
        Primero busca en caché Redis, si no está hace la llamada HTTP.
        """
        # IPs locales/privadas → retornar default sin consultar
        if self._is_private_ip(ip_address):
            logger.debug(f"[GeoIP] IP privada detectada: {ip_address}")
            return GeoIPResult(
                ip_country = "MX",   # Asumir México en desarrollo local
                ip_city    = "Local",
                ip_isp     = "Local",
                is_vpn     = False,
                is_hosting = False,
                latitude   = 19.4326,
                longitude  = -99.1332,
                success    = True,
            )

        # Intentar desde caché
        cached = await self._get_cache(ip_address)
        if cached:
            return cached

        # Llamada HTTP a ip-api.com
        try:
            async with httpx.AsyncClient(timeout=GEOIP_TIMEOUT_SEC) as client:
                url      = self.API_URL.format(ip=ip_address)
                response = await client.get(url, params={"fields": self.FIELDS})
                response.raise_for_status()
                data = response.json()

            if data.get("status") != "success":
                logger.warning(f"[GeoIP] ip-api retornó status!=success para {ip_address}")
                return _GEO_DEFAULT

            result = GeoIPResult(
                ip_country = data.get("countryCode", "XX"),
                ip_city    = data.get("city",        "Unknown"),
                ip_isp     = data.get("isp",         "Unknown"),
                is_vpn     = data.get("proxy",       False),
                is_hosting = data.get("hosting",     False),
                latitude   = data.get("lat",         0.0),
                longitude  = data.get("lon",         0.0),
                success    = True,
            )

            # Guardar en caché
            await self._set_cache(ip_address, result)
            return result

        except httpx.TimeoutException:
            logger.warning(f"[GeoIP] Timeout consultando {ip_address}")
        except Exception as e:
            logger.error(f"[GeoIP] Error consultando {ip_address}: {e}")

        return _GEO_DEFAULT

    async def _get_cache(self, ip: str) -> Optional[GeoIPResult]:
        key = self.CACHE_KEY.format(ip=ip)
        try:
            import json
            raw = await redis_manager.client.get(key)
            if raw:
                data = json.loads(raw)
                return GeoIPResult(**data)
        except Exception:
            pass
        return None

    async def _set_cache(self, ip: str, result: GeoIPResult) -> None:
        key = self.CACHE_KEY.format(ip=ip)
        try:
            import json
            from dataclasses import asdict
            await redis_manager.client.setex(
                key, GEOIP_CACHE_TTL, json.dumps(asdict(result))
            )
        except Exception:
            pass

    def _is_private_ip(self, ip: str) -> bool:
        """Detecta IPs privadas/locales que no tienen geolocalización pública."""
        private_prefixes = (
            "127.", "10.", "192.168.", "172.16.", "172.17.",
            "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
            "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.", "::1", "fc", "fd",
        )
        return any(ip.startswith(p) for p in private_prefixes)


# ─────────────────────────────────────────────────────────────────────
# BIN Lookup
# ─────────────────────────────────────────────────────────────────────

@dataclass
class BINResult:
    """Resultado del lookup de un BIN de tarjeta."""
    bin_country:   str    # Código ISO del país emisor (ej. "MX")
    card_type:     str    # "debit" | "credit" | "prepaid" | "unknown"
    card_brand:    str    # "visa" | "mastercard" | "amex" | "unknown"
    bank_name:     str    # Nombre del banco emisor
    success:       bool


# Resultado por defecto cuando el lookup falla
_BIN_DEFAULT = BINResult(
    bin_country = "XX",
    card_type   = "unknown",
    card_brand  = "unknown",
    bank_name   = "Unknown",
    success     = False,
)


class BINLookupClient:
    """
    Consulta binlist.net para obtener información de un BIN de tarjeta.

    binlist.net es gratuito y no requiere API key.
    Límite: 10 requests/hora por IP en plan gratuito.
    Para producción usar una base de datos BIN local o un proveedor de pago.

    Caché en Redis:
      bin:lookup:{card_bin} → JSON con el resultado
      TTL: 24 horas (los BINs son prácticamente estáticos)
    """

    API_URL   = "https://lookup.binlist.net/{bin}"
    CACHE_KEY = "bin:lookup:{bin}"

    async def lookup(self, card_bin: str) -> BINResult:
        """
        Obtiene información del banco y país emisor de un BIN.
        Los primeros 6-8 dígitos de la tarjeta identifican al emisor.
        """
        # Usar solo los primeros 6 dígitos (estándar BIN)
        bin6 = card_bin[:6]

        # Intentar desde caché primero
        cached = await self._get_cache(bin6)
        if cached:
            return cached

        try:
            async with httpx.AsyncClient(timeout=BIN_TIMEOUT_SEC) as client:
                response = await client.get(
                    self.API_URL.format(bin=bin6),
                    headers={"Accept-Version": "3"},
                )

                # 404 = BIN no encontrado en la base de datos
                if response.status_code == 404:
                    logger.debug(f"[BIN] BIN {bin6} no encontrado")
                    return _BIN_DEFAULT

                response.raise_for_status()
                data = response.json()

            result = BINResult(
                bin_country = (
                    data.get("country", {}).get("alpha2", "XX")
                ),
                card_type   = data.get("type",   "unknown").lower(),
                card_brand  = data.get("scheme", "unknown").lower(),
                bank_name   = (
                    data.get("bank", {}).get("name", "Unknown")
                ),
                success     = True,
            )

            await self._set_cache(bin6, result)
            return result

        except httpx.TimeoutException:
            logger.warning(f"[BIN] Timeout consultando BIN {bin6}")
        except Exception as e:
            logger.error(f"[BIN] Error consultando BIN {bin6}: {e}")

        return _BIN_DEFAULT

    async def _get_cache(self, bin6: str) -> Optional[BINResult]:
        key = self.CACHE_KEY.format(bin=bin6)
        try:
            import json
            raw = await redis_manager.client.get(key)
            if raw:
                data = json.loads(raw)
                return BINResult(**data)
        except Exception:
            pass
        return None

    async def _set_cache(self, bin6: str, result: BINResult) -> None:
        key = self.CACHE_KEY.format(bin=bin6)
        try:
            import json
            from dataclasses import asdict
            await redis_manager.client.setex(
                key, BIN_CACHE_TTL, json.dumps(asdict(result))
            )
        except Exception:
            pass


# ── Singletons ────────────────────────────────────────────────────────
geoip_client     = GeoIPClient()
bin_lookup_client = BINLookupClient()