"""
geo_analyzer.py
---------------
Análisis geográfico multi-capa del Motor Antifraude.

Cruza tres fuentes de ubicación independientes para detectar fraude:
  1. País derivado de la IP (via MaxMind GeoIP — enriquecido en middleware)
  2. País derivado del GPS del dispositivo
  3. País de emisión del BIN de la tarjeta

Además detecta:
  - Viaje imposible: el usuario no pudo haber viajado físicamente desde
    su última ubicación conocida hasta la actual en el tiempo transcurrido
  - Modo Viajero: el usuario declaró un viaje legítimo → reduce penalización
  - Historial geográfico: países donde el usuario ya operó antes → menos riesgo
  - Países de alto riesgo (lista FATF) → penalización adicional

Principio de diseño anti falsos positivos:
  - SIEMPRE verificar el Modo Viajero ANTES de penalizar por país extranjero
  - SIEMPRE verificar historial de países antes de penalizar por país "nuevo"
  - El viaje imposible tiene buffer de 3h para cubrir escalas y esperas
  - Si Redis falla, retornar score neutro (no penalizar por infra caída)

Tiempo esperado: 5-15ms (Redis lookups + cálculo haversine en memoria).
"""

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Lista FATF de países de alto riesgo / jurisdicciones vigiladas    #
#  Fuente: FATF High-Risk Jurisdictions (actualizar periódicamente)  #
# ------------------------------------------------------------------ #
HIGH_RISK_COUNTRIES = frozenset({
    "AF", "AL", "BB", "BF", "BJ", "CD", "CF", "CI", "CM",
    "DJ", "ET", "GH", "GN", "GW", "HT", "IR", "KH", "KP",
    "LA", "LB", "LY", "ML", "MM", "MR", "MZ", "NE", "NG",
    "PH", "PK", "RU", "SC", "SN", "SO", "SS", "SY", "TG",
    "TN", "TT", "TZ", "UG", "VN", "VU", "YE", "ZW",
})

# ------------------------------------------------------------------ #
#  Penalizaciones                                                     #
# ------------------------------------------------------------------ #
PENALTY_TRIPLE_MISMATCH       = 25   # IP + GPS + BIN todos en países distintos
PENALTY_DUAL_MISMATCH         = 15   # Solo dos de los tres difieren
PENALTY_HIGH_RISK_COUNTRY     = 20   # País en lista FATF
PENALTY_GPS_IP_DISTANCE       = 10   # Distancia GPS vs IP > 500 km
PENALTY_IMPOSSIBLE_TRAVEL     = 40   # Viaje físicamente imposible
PENALTY_NEW_COUNTRY           = 15   # País nunca visto en historial del usuario
PENALTY_GPS_OBFUSCATED        = 50   # Coordenadas 0,0 → intento de ocultar ubicación

# ------------------------------------------------------------------ #
#  Reducciones (valores negativos → bajan el score)                  #
# ------------------------------------------------------------------ #
REDUCTION_TRAVELER_MODE       = -30  # Modo Viajero activo y país coincide
REDUCTION_COUNTRY_IN_HISTORY  = -10  # País ya visto en historial del usuario

# ------------------------------------------------------------------ #
#  Constantes de viaje imposible                                     #
# ------------------------------------------------------------------ #
MAX_FLIGHT_SPEED_KMH   = 900.0   # Velocidad máxima avión comercial
AIRPORT_BUFFER_HOURS   = 3.0     # Buffer para escala + espera en aeropuerto
MIN_DISTANCE_FOR_CHECK = 100.0   # Distancias < 100km nunca son "viaje imposible"
LAST_TX_TTL_DAYS       = 30      # Si no operó en 30 días, no aplica el check

# ------------------------------------------------------------------ #
#  Constantes de historial                                           #
# ------------------------------------------------------------------ #
HISTORY_MAX_COUNTRIES  = 20      # Máximo de países únicos en el historial
HISTORY_TTL_DAYS       = 90      # TTL del historial geográfico en Redis


@dataclass
class GeoAnalysisResult:
    """
    Resultado completo del análisis geográfico.
    reason_codes se agrega a la respuesta final para auditoría.
    """
    score: float
    reason_codes: list[str] = field(default_factory=list)
    impossible_travel_detected: bool = False
    traveler_mode_active: bool = False
    country_from_ip: Optional[str] = None
    is_new_country: bool = False


class GeoAnalyzer:
    """
    Analiza el contexto geográfico de una transacción.

    Estructura de keys en Redis:
      geo:user:{user_id}:last_tx
        → JSON: {"lat": float, "lon": float, "country": str, "ts": float}
        → TTL: 30 días

      geo:user:{user_id}:country_history
        → JSON: ["MX", "US", "ES", ...]
        → TTL: 90 días

      geo:user:{user_id}:traveler_mode
        → JSON: {"destination_countries": ["ES", "FR"], "expires_ts": float}
        → TTL: duración del viaje declarado

    El middleware del router debe enriquecer el payload ANTES de llegar
    aquí con los campos: ip_country, bin_country, is_vpn.
    Ver app/api/middlewares.py → GeoEnrichmentMiddleware
    """

    LAST_TX_KEY    = "geo:user:{user_id}:last_tx"
    HISTORY_KEY    = "geo:user:{user_id}:country_history"
    TRAVELER_KEY   = "geo:user:{user_id}:traveler_mode"

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    # ------------------------------------------------------------------ #
    #  Método principal — llamar dentro del asyncio.gather               #
    # ------------------------------------------------------------------ #

    async def analyze(
        self,
        user_id: str,
        latitude: float,
        longitude: float,
        ip_country: str,
        bin_country: str,
        is_vpn: bool = False,
    ) -> GeoAnalysisResult:
        """
        Ejecuta todos los checks geográficos y retorna el score acumulado.

        Parámetros:
          user_id     → para buscar historial y última ubicación en Redis
          latitude    → GPS del dispositivo (del payload)
          longitude   → GPS del dispositivo (del payload)
          ip_country  → código ISO del país de la IP (enriquecido en middleware)
          bin_country → código ISO del país de emisión del BIN
          is_vpn      → True si la IP fue detectada como VPN/proxy (enriquecido)
        """
        result = GeoAnalysisResult(score=0.0)
        result.country_from_ip = ip_country

        # ── CHECK 0: Coordenadas de ofuscación ────────────────────────
        # lat=0.0 lon=0.0 es el centro del océano Atlántico — ningún
        # usuario legítimo opera desde ahí. Es un intento de ocultar GPS.
        if latitude == 0.0 and longitude == 0.0:
            result.score += PENALTY_GPS_OBFUSCATED
            result.reason_codes.append("GPS_OBFUSCATED_ZERO_COORDS")
            # Sin coordenadas válidas no podemos calcular viaje imposible
            # ni distancia GPS/IP, así que retornamos aquí directamente
            await self._update_last_location(user_id, latitude, longitude, ip_country)
            return result

        # ── CHECK 1: Modo Viajero — SIEMPRE antes de penalizar ────────
        # Si el usuario declaró un viaje y el país coincide, reducimos
        # el score y saltamos los checks de mismatch geográfico
        traveler_mode = await self._get_traveler_mode(user_id)
        if traveler_mode and self._country_matches_traveler(ip_country, traveler_mode):
            result.traveler_mode_active = True
            result.score += REDUCTION_TRAVELER_MODE
            result.reason_codes.append("TRAVELER_MODE_ACTIVE")
            result.score = max(result.score, 0.0)
            # Actualizamos historial aunque esté en modo viajero
            await self._update_last_location(user_id, latitude, longitude, ip_country)
            await self._add_country_to_history(user_id, ip_country)
            return result

        # ── CHECK 2: Triple/Dual mismatch entre IP, GPS y BIN ─────────
        # Comparamos los países de las tres fuentes de ubicación.
        # Un mismatch triple (ej. IP=RU, GPS=MX, BIN=US) es señal fuerte.
        gps_country = self._approximate_country_from_coords(latitude, longitude)
        countries = {c for c in [ip_country, gps_country, bin_country] if c}

        if len(countries) == 3:
            # Los tres países son diferentes entre sí
            result.score += PENALTY_TRIPLE_MISMATCH
            result.reason_codes.append("TRIPLE_COUNTRY_MISMATCH")
        elif len(countries) == 2 and (ip_country != bin_country):
            # Al menos IP y BIN difieren (el más relevante de los pares)
            result.score += PENALTY_DUAL_MISMATCH
            result.reason_codes.append("DUAL_COUNTRY_MISMATCH")

        # ── CHECK 3: País de alto riesgo (lista FATF) ─────────────────
        # Revisamos tanto el país de la IP como el del GPS.
        # Rompemos al primer match para no penalizar doble.
        for country in [ip_country, gps_country]:
            if country and country in HIGH_RISK_COUNTRIES:
                result.score += PENALTY_HIGH_RISK_COUNTRY
                result.reason_codes.append(f"HIGH_RISK_COUNTRY_{country}")
                break

        # ── CHECK 4: Distancia entre GPS e IP ─────────────────────────
        # Si el GPS dice que el usuario está en CDMX pero la IP
        # geolocaliza en Moscú → diferencia de ~10,000 km → fraude.
        # En producción el middleware debe pasar las coordenadas de la IP.
        # Aquí se usa una aproximación por centro de país.
        ip_coords = self._get_country_centroid(ip_country)
        if ip_coords:
            distance_km = self._haversine(
                latitude, longitude,
                ip_coords[0], ip_coords[1],
            )
            if distance_km > 500:
                result.score += PENALTY_GPS_IP_DISTANCE
                result.reason_codes.append(
                    f"GPS_IP_DISTANCE_{int(distance_km)}KM"
                )

        # ── CHECK 5: Viaje imposible ───────────────────────────────────
        # Compara la posición actual con la última posición registrada.
        # Si la distancia implica viajar más rápido que un avión → fraude.
        impossible = await self._check_impossible_travel(
            user_id, latitude, longitude, ip_country
        )
        if impossible:
            result.score += PENALTY_IMPOSSIBLE_TRAVEL
            result.reason_codes.append("IMPOSSIBLE_TRAVEL_DETECTED")
            result.impossible_travel_detected = True

        country_history = await self._get_country_history(user_id)
        is_new_country  = ip_country not in country_history
        result.is_new_country = is_new_country

        if is_new_country:
            result.score += PENALTY_NEW_COUNTRY
            result.reason_codes.append(f"NEW_COUNTRY_{ip_country}")
        elif ip_country in country_history:
            result.score += REDUCTION_COUNTRY_IN_HISTORY
            result.reason_codes.append(f"KNOWN_COUNTRY_REDUCTION_{ip_country}")

        await self._update_last_location(user_id, latitude, longitude, ip_country)
        await self._add_country_to_history(user_id, ip_country)

        result.score = max(0.0, min(100.0, result.score))

        logger.debug(
            f"[GeoAnalyzer] user={user_id}  score={result.score:.1f}  "
            f"ip={ip_country}  codes={result.reason_codes}"
        )
        return result

    # ------------------------------------------------------------------ #
    #  Viaje imposible                                                   #
    # ------------------------------------------------------------------ #

    async def _check_impossible_travel(
        self,
        user_id: str,
        current_lat: float,
        current_lon: float,
        current_country: str,
    ) -> bool:
        """
        Detecta si el usuario no pudo haber viajado físicamente desde
        su última ubicación conocida hasta la actual.

        Lógica:
          distancia_km / 900 km/h + 3h buffer = tiempo mínimo de viaje
          Si elapsed_hours < tiempo_mínimo → viaje imposible

        Ejemplo:
          CDMX → Moscú = ~10,500 km
          10,500 / 900 = 11.7h + 3h buffer = 14.7h mínimo
          Si el usuario aparece en Moscú 2 horas después → FRAUDE

        Buffer de 3 horas cubre:
          - Tiempo en aeropuerto (check-in, seguridad, embarque)
          - Escala corta
          - Diferencia de zona horaria en el timestamp
        """
        key = self.LAST_TX_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            if not raw:
                return False

            last = json.loads(raw)
            last_lat     = last.get("lat")
            last_lon     = last.get("lon")
            last_ts      = last.get("ts")
            last_country = last.get("country")

            if None in (last_lat, last_lon, last_ts):
                return False

            if last_country and last_country == current_country:
                return False

            distance_km = self._haversine(
                last_lat, last_lon,
                current_lat, current_lon,
            )

            if distance_km < MIN_DISTANCE_FOR_CHECK:
                return False

            elapsed_seconds = datetime.now(timezone.utc).timestamp() - last_ts
            elapsed_hours   = elapsed_seconds / 3600

            min_hours_needed = (distance_km / MAX_FLIGHT_SPEED_KMH) + AIRPORT_BUFFER_HOURS

            if elapsed_hours < min_hours_needed:
                logger.warning(
                    f"[GeoAnalyzer] Viaje imposible detectado — "
                    f"user={user_id}  distancia={distance_km:.0f}km  "
                    f"elapsed={elapsed_hours:.1f}h  "
                    f"min_needed={min_hours_needed:.1f}h  "
                    f"ruta={last_country}→{current_country}"
                )
                return True

        except Exception as e:
            logger.error(f"[GeoAnalyzer] Error en check_impossible_travel: {e}")

        return False

    async def _update_last_location(
        self,
        user_id: str,
        lat: float,
        lon: float,
        country: str,
    ) -> None:
        """Guarda la última posición conocida del usuario en Redis."""
        key  = self.LAST_TX_KEY.format(user_id=user_id)
        data = {
            "lat":     lat,
            "lon":     lon,
            "country": country,
            "ts":      datetime.now(timezone.utc).timestamp(),
        }
        try:
            await self.redis.setex(
                key,
                60 * 60 * 24 * LAST_TX_TTL_DAYS,
                json.dumps(data),
            )
        except Exception as e:
            logger.error(f"[GeoAnalyzer] Error guardando última ubicación: {e}")

    # ------------------------------------------------------------------ #
    #  Historial de países                                               #
    # ------------------------------------------------------------------ #

    async def _get_country_history(self, user_id: str) -> set:
        """Retorna el conjunto de países donde el usuario ha operado."""
        key = self.HISTORY_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            if raw:
                return set(json.loads(raw))
        except Exception as e:
            logger.error(f"[GeoAnalyzer] Error leyendo historial de países: {e}")
        return set()

    async def _add_country_to_history(self, user_id: str, country: str) -> None:
        """Agrega un país al historial del usuario."""
        key = self.HISTORY_KEY.format(user_id=user_id)
        try:
            history = await self._get_country_history(user_id)
            history.add(country)
            if len(history) > HISTORY_MAX_COUNTRIES:
                history = set(list(history)[-HISTORY_MAX_COUNTRIES:])
            await self.redis.setex(
                key,
                60 * 60 * 24 * HISTORY_TTL_DAYS,
                json.dumps(list(history)),
            )
        except Exception as e:
            logger.error(f"[GeoAnalyzer] Error actualizando historial: {e}")

    # ------------------------------------------------------------------ #
    #  Modo Viajero                                                      #
    # ------------------------------------------------------------------ #

    async def _get_traveler_mode(self, user_id: str) -> Optional[dict]:
        """
        Retorna los datos del Modo Viajero activo o None si no está activo.
        Estructura: {"destination_countries": ["ES", "FR"], "expires_ts": float}
        """
        key = self.TRAVELER_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            if raw:
                data = json.loads(raw)
                # Verificar que no haya expirado manualmente
                if data.get("expires_ts", 0) > datetime.now(timezone.utc).timestamp():
                    return data
        except Exception as e:
            logger.error(f"[GeoAnalyzer] Error leyendo Modo Viajero: {e}")
        return None

    def _country_matches_traveler(self, country: str, traveler_data: dict) -> bool:
        """Verifica si el país actual está en los destinos declarados."""
        destinations = traveler_data.get("destination_countries", [])
        return country.upper() in [d.upper() for d in destinations]

    async def set_traveler_mode(
        self,
        user_id: str,
        destination_countries: list,
        duration_days: int = 30,
    ) -> None:
        """
        Activa el Modo Viajero para un usuario.
        Llamar desde el endpoint de la app cuando el usuario declara un viaje.

        Ejemplo de uso desde el router:
            await geo_analyzer.set_traveler_mode(
                user_id="abc123",
                destination_countries=["ES", "FR", "IT"],
                duration_days=14,
            )
        """
        key  = self.TRAVELER_KEY.format(user_id=user_id)
        data = {
            "destination_countries": [c.upper() for c in destination_countries],
            "expires_ts": (
                datetime.now(timezone.utc) + timedelta(days=duration_days)
            ).timestamp(),
        }
        try:
            await self.redis.setex(
                key,
                60 * 60 * 24 * duration_days,
                json.dumps(data),
            )
            logger.info(
                f"[GeoAnalyzer] Modo Viajero activado — "
                f"user={user_id}  destinos={destination_countries}  "
                f"duración={duration_days}d"
            )
        except Exception as e:
            logger.error(f"[GeoAnalyzer] Error activando Modo Viajero: {e}")

    async def cancel_traveler_mode(self, user_id: str) -> None:
        """Cancela el Modo Viajero de forma inmediata."""
        key = self.TRAVELER_KEY.format(user_id=user_id)
        try:
            await self.redis.delete(key)
            logger.info(f"[GeoAnalyzer] Modo Viajero cancelado para user={user_id}")
        except Exception as e:
            logger.error(f"[GeoAnalyzer] Error cancelando Modo Viajero: {e}")

    # ------------------------------------------------------------------ #
    #  Utilidades geográficas                                            #
    # ------------------------------------------------------------------ #

    def _haversine(
        self,
        lat1: float, lon1: float,
        lat2: float, lon2: float,
    ) -> float:
        """
        Calcula la distancia en kilómetros entre dos puntos geográficos
        usando la fórmula de Haversine.

        Es más precisa que la distancia euclidiana para distancias largas
        porque tiene en cuenta la curvatura de la Tierra.
        Error máximo: < 0.5% para cualquier distancia en la Tierra.
        """
        R    = 6371.0   
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)

        a = (
            math.sin(dphi / 2) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
        )
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    def _approximate_country_from_coords(
        self,
        lat: float,
        lon: float,
    ) -> Optional[str]:
        """
        Aproximación muy básica del país por coordenadas.
        En producción REEMPLAZAR con MaxMind GeoIP2 reverse geocoding
        o Google Maps Geocoding API para precisión real.

        Este método solo sirve como fallback cuando el middleware
        no pudo enriquecer el payload con el país del GPS.
        """
        if 14 <= lat <= 33 and -118 <= lon <= -86:
            return "MX"
        if 24 <= lat <= 49 and -125 <= lon <= -66:
            return "US"
        if 36 <= lat <= 44 and -9 <= lon <= 4:
            return "ES"
        return None   

    def _get_country_centroid(self, country_code: str) -> Optional[tuple]:
        """
        Retorna las coordenadas del centroide aproximado de un país.
        Se usa para estimar la distancia cuando solo tenemos el país de la IP
        y no las coordenadas exactas del servidor.

        En producción el middleware debe pasar las coordenadas reales de la IP
        (MaxMind las provee) y este método no sería necesario.
        """
        centroids = {
            "MX": (23.6345, -102.5528),
            "US": (37.0902, -95.7129),
            "ES": (40.4637, -3.7492),
            "BR": (-14.2350, -51.9253),
            "AR": (-38.4161, -63.6167),
            "CO": (4.5709, -74.2973),
            "RU": (61.5240, 105.3188),
            "CN": (35.8617, 104.1954),
            "DE": (51.1657, 10.4515),
            "FR": (46.2276, 2.2137),
            "GB": (55.3781, -3.4360),
            "JP": (36.2048, 138.2529),
            "NG": (9.0820, 8.6753),
            "KP": (40.3399, 127.5101),
        }
        return centroids.get(country_code.upper())