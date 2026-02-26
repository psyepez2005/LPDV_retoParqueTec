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

GEOIP_TIMEOUT_SEC  = 2.0  
BIN_TIMEOUT_SEC    = 2.0   

GEOIP_CACHE_TTL    = 60 * 60 * 6    
BIN_CACHE_TTL      = 60 * 60 * 24   

@dataclass
class GeoIPResult:

    ip_country:   str            
    ip_city:      str           
    ip_isp:       str            
    is_vpn:       bool           
    is_hosting:   bool           
    latitude:     float          
    longitude:    float
    success:      bool           


_GEO_DEFAULT = GeoIPResult(
    ip_country = "XX",     
    ip_city    = "Unknown",
    ip_isp     = "Unknown",
    is_vpn     = False,
    is_hosting = False,
    latitude   = 0.0,
    longitude  = 0.0,
    success    = False,
)


class GeoIPClient:

    API_URL    = "http://ip-api.com/json/{ip}"
    FIELDS     = "status,country,countryCode,city,isp,proxy,hosting,lat,lon"
    CACHE_KEY  = "geo:ip:{ip}"

    async def lookup(self, ip_address: str) -> GeoIPResult:
        
        if self._is_private_ip(ip_address):
            logger.debug(f"[GeoIP] IP privada detectada: {ip_address}")
            return GeoIPResult(
                ip_country = "MX",  
                ip_city    = "Local",
                ip_isp     = "Local",
                is_vpn     = False,
                is_hosting = False,
                latitude   = 19.4326,
                longitude  = -99.1332,
                success    = True,
            )

        cached = await self._get_cache(ip_address)
        if cached:
            return cached

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
        private_prefixes = (
            "127.", "10.", "192.168.", "172.16.", "172.17.",
            "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
            "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.", "::1", "fc", "fd",
        )
        return any(ip.startswith(p) for p in private_prefixes)


@dataclass
class BINResult:
    """Resultado del lookup de un BIN de tarjeta."""
    bin_country:   str    
    card_type:     str   
    card_brand:    str    
    bank_name:     str    
    success:       bool

_BIN_DEFAULT = BINResult(
    bin_country = "XX",
    card_type   = "unknown",
    card_brand  = "unknown",
    bank_name   = "Unknown",
    success     = False,
)


class BINLookupClient:
    
    API_URL   = "https://lookup.binlist.net/{bin}"
    CACHE_KEY = "bin:lookup:{bin}"

    async def lookup(self, card_bin: str) -> BINResult:
        bin6 = card_bin[:6]

        cached = await self._get_cache(bin6)
        if cached:
            return cached

        try:
            async with httpx.AsyncClient(timeout=BIN_TIMEOUT_SEC) as client:
                response = await client.get(
                    self.API_URL.format(bin=bin6),
                    headers={"Accept-Version": "3"},
                )

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

geoip_client     = GeoIPClient()
bin_lookup_client = BINLookupClient()

