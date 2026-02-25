"""
gps_ip_mismatch.py
------------------
Detecta discrepancia entre las coordenadas GPS del payload
y el país real de la dirección IP.

Si el GPS dice "estoy en México" pero la IP geolocalizó en Alemania
→ el usuario está usando VPN, independientemente de lo que declare
  en el campo network_type del payload.

No requiere APIs externas — usa una tabla estática de bounding boxes
para los países más relevantes del motor (LATAM, US, EU).
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Bounding boxes: (lat_min, lat_max, lon_min, lon_max)
# Fuente: WorldBank / Natural Earth — aproximaciones generosas para
# evitar falsos positivos en zonas fronterizas.
_COUNTRY_BOXES: dict[str, tuple[float, float, float, float]] = {
    "MX": (14.5,  32.7,  -118.4, -86.7),
    "US": (24.4,  49.4,  -125.0, -66.9),
    "CA": (41.7,  83.1,  -141.0, -52.6),
    "CO": (-4.2,  13.4,   -79.0, -66.8),
    "AR": (-55.1,  -21.8, -73.6, -53.5),
    "BR": (-33.8,   5.3,  -73.9, -34.8),
    "CL": (-56.0, -17.5,  -75.6, -66.4),
    "PE": (-18.4,  -0.0,  -81.3, -68.7),
    "VE": (  0.7,  12.2,  -73.4, -59.8),
    "EC": ( -5.0,   1.4,  -80.9, -75.2),
    "BO": (-22.9,  -9.6,  -69.6, -57.5),
    "PY": (-27.6, -19.3,  -62.6, -54.3),
    "UY": (-34.9, -30.1,  -58.4, -53.1),
    "GT": ( 13.7,  18.0,  -92.2, -88.2),
    "HN": ( 12.9,  16.5,  -89.4, -83.1),
    "SV": ( 13.1,  14.5,  -90.1, -87.7),
    "NI": ( 10.7,  15.0,  -87.6, -82.7),
    "CR": (  8.0,  11.2,  -85.9, -82.6),
    "PA": (  7.2,   9.6,  -83.0, -77.2),
    "CU": ( 19.8,  23.3,  -85.0, -74.1),
    "DO": ( 17.5,  19.9,  -72.0, -68.3),
    "ES": ( 35.9,  43.8,   -9.3,   4.3),
    "DE": ( 47.3,  55.1,    5.8,  15.0),
    "FR": ( 42.3,  51.1,   -5.1,   9.6),
    "GB": ( 49.9,  60.8,   -8.6,   1.8),
    "IT": ( 35.5,  47.1,    6.6,  18.5),
    "RU": ( 41.1,  81.9,   19.6, 180.0),
    "CN": ( 18.2,  53.6,   73.5, 134.8),
    "JP": ( 24.0,  45.5,  122.9, 153.9),
    "IN": (  8.0,  37.1,   68.1,  97.4),
    "AU": (-43.6,  -10.7, 113.3, 153.6),
}

# Países considerados zona de alto riesgo para pagos LATAM
_HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "NG", "GH", "CM"}


@dataclass
class GPSIPResult:
    penalty:      int       = 0
    reason_codes: list[str] = field(default_factory=list)


def _country_from_coords(lat: float, lon: float) -> Optional[str]:
    """Devuelve el código de país a partir de coordenadas GPS."""
    for country, (lat_min, lat_max, lon_min, lon_max) in _COUNTRY_BOXES.items():
        if lat_min <= lat <= lat_max and lon_min <= lon <= lon_max:
            return country
    return None


class GPSIPMismatchDetector:
    """
    Cruza el país estimado por GPS vs el país real de la IP.
    Un mismatch indica que el usuario está usando VPN o proxy.
    """

    def check(
        self,
        latitude:   float,
        longitude:  float,
        ip_country: str,
    ) -> GPSIPResult:
        result      = GPSIPResult()
        gps_country = _country_from_coords(latitude, longitude)

        if gps_country is None:
            # Coordenadas en zona sin cobertura de la tabla → neutro
            return result

        if gps_country != ip_country:
            result.penalty += 30
            result.reason_codes.append(
                f"GPS_IP_COUNTRY_MISMATCH_{gps_country}_VS_{ip_country}"
            )
            logger.info(
                f"[GPSIPMismatch] GPS={gps_country} vs IP={ip_country} → VPN probable"
            )

        if ip_country in _HIGH_RISK_COUNTRIES:
            result.penalty += 10
            result.reason_codes.append(f"HIGH_RISK_IP_COUNTRY_{ip_country}")

        return result


gps_ip_mismatch_detector = GPSIPMismatchDetector()
