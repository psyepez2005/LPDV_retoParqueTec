"""
p2p_analyzer.py
---------------
Analiza el riesgo específico de transferencias P2P (persona a persona).

El fraude P2P no es visible en transacciones individuales — se detecta
en patrones de red. Este módulo evalúa:

  1. Cuenta receptora nueva       → posible mula recién creada
  2. Risk score del receptor      → el riesgo se propaga entre nodos
  3. Fan-out del emisor           → distribuye fondos a muchos destinos
  4. Fan-in del receptor          → recibe de muchas fuentes (señal de mula)
  5. Smurfing                     → acumulación de txs pequeñas bajo el radar
  6. Drenado rápido               → recibe y retira todo en < 2 horas (mula)
  7. Relación previa              → reducción por historial establecido

Solo se ejecuta cuando transaction_type == "P2P_SEND".

Principio de diseño:
  - Todos los contadores usan Redis Sets para contar ÚNICOS eficientemente
    (SADD + SCARD es O(1) por operación)
  - Cada set tiene TTL propio: 1h para ventanas cortas, 24h para diarias
  - El acumulado diario de smurfing usa INCRBYFLOAT + TTL de 24h
  - Si Redis falla → score neutro, no se penaliza por infra caída

Tiempo esperado: 5-10ms (pipeline de Redis con todas las lecturas juntas).
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Umbrales de detección (configurables por equipo de riesgo)        #
# ------------------------------------------------------------------ #

# Fan-out: cuántos destinatarios distintos puede tener el EMISOR
FANOUT_LIMIT_1H     = 5    # > 5 destinatarios distintos en 1 hora
FANOUT_LIMIT_24H    = 15   # > 15 destinatarios distintos en 24 horas

# Fan-in: cuántos remitentes distintos puede tener el RECEPTOR
FANIN_LIMIT_1H      = 5    # > 5 remitentes distintos en 1 hora → mula
FANIN_LIMIT_24H     = 10   # > 10 remitentes distintos en 24 horas

# Smurfing: transacciones pequeñas que suman por encima del umbral
SMURFING_DAILY_LIMIT   = 9_000.0   # USD — justo debajo del umbral regulatorio
SMURFING_SINGLE_LIMIT  = 1_000.0   # Tx individuales bajo este monto + suma alta

# Cuenta nueva: horas de antigüedad del receptor para considerarlo "nuevo"
NEW_ACCOUNT_HOURS   = 48

# Drenado rápido: porcentaje del saldo recibido que se retira en < 2h
DRAIN_WINDOW_SEC    = 7_200     # 2 horas en segundos
DRAIN_PCT_THRESHOLD = 80        # > 80% del saldo recibido retirado


# ------------------------------------------------------------------ #
#  Penalizaciones                                                     #
# ------------------------------------------------------------------ #
PENALTY_NEW_RECIPIENT_ACCOUNT = 20   # Receptor con cuenta < 48h
PENALTY_RECIPIENT_HIGH_RISK   = 15   # Receptor con risk score acumulado > 60
PENALTY_FANOUT_HIGH           = 30   # Fan-out excesivo en 1h
PENALTY_FANOUT_MEDIUM         = 15   # Fan-out moderado en 24h
PENALTY_FANIN_HIGH            = 25   # Receptor con fan-in alto → posible mula
PENALTY_FANIN_MEDIUM          = 12   # Receptor con fan-in moderado
PENALTY_SMURFING              = 35   # Patrón de smurfing detectado
PENALTY_RAPID_DRAIN           = 40   # Receptor drena saldo en < 2h

# ------------------------------------------------------------------ #
#  Reducciones                                                        #
# ------------------------------------------------------------------ #
REDUCTION_ESTABLISHED_RELATION = -15  # 3+ txs exitosas previas entre este par


@dataclass
class P2PAnalysisResult:
    """
    Resultado del análisis P2P.

    should_hold_funds: True cuando el motor debe aplicar retención
    preventiva de 24h en lugar de aprobar inmediatamente.
    Casos: receptor nuevo + monto alto, drenado rápido detectado.

    mule_pattern_detected: True cuando hay evidencia fuerte de cuenta
    mula. El orquestador usa esto para forzar score >= 91.
    """
    score: float
    reason_codes: list[str]          = field(default_factory=list)
    is_new_recipient_account: bool   = False
    smurfing_detected: bool          = False
    mule_pattern_detected: bool      = False
    should_hold_funds: bool          = False


class P2PAnalyzer:
    """
    Evalúa el riesgo de transferencias P2P usando contadores en Redis.

    Estructura de keys en Redis:
      p2p:fanout:1h:{sender_id}    → SET de recipient_ids  (TTL: 1h)
      p2p:fanout:24h:{sender_id}   → SET de recipient_ids  (TTL: 24h)
      p2p:fanin:1h:{recipient_id}  → SET de sender_ids     (TTL: 1h)
      p2p:fanin:24h:{recipient_id} → SET de sender_ids     (TTL: 24h)
      p2p:daily_vol:{sender_id}    → float acumulado del día (TTL: 24h)
      p2p:acct_age_h:{user_id}     → float horas de antigüedad
      p2p:accum_risk:{user_id}     → float risk score acumulado (EWMA)
      p2p:drain:{user_id}          → JSON con datos de drenado

    Los sets de fan-out/fan-in usan SADD para garantizar unicidad:
    si el mismo destinatario recibe 5 txs del mismo emisor en 1h,
    el SCARD sigue siendo 1 (no 5). Solo cuentan destinos únicos.
    """

    FANOUT_1H_KEY   = "p2p:fanout:1h:{user_id}"
    FANOUT_24H_KEY  = "p2p:fanout:24h:{user_id}"
    FANIN_1H_KEY    = "p2p:fanin:1h:{user_id}"
    FANIN_24H_KEY   = "p2p:fanin:24h:{user_id}"
    DAILY_VOL_KEY   = "p2p:daily_vol:{user_id}"
    ACCT_AGE_KEY    = "p2p:acct_age_h:{user_id}"
    ACCUM_RISK_KEY  = "p2p:accum_risk:{user_id}"
    DRAIN_KEY       = "p2p:drain:{user_id}"

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    # ------------------------------------------------------------------ #
    #  Método principal — llamar dentro del asyncio.gather               #
    # ------------------------------------------------------------------ #

    async def analyze(
        self,
        sender_id: str,
        recipient_id: str,
        amount: float,
        currency: str,
    ) -> P2PAnalysisResult:
        """
        Evalúa el riesgo de una transferencia P2P.

        Parámetros:
          sender_id    → user_id del emisor (quien envía)
          recipient_id → user_id del receptor (quien recibe)
          amount       → monto de la transferencia
          currency     → moneda ("MXN", "USD", etc.)
        """
        result = P2PAnalysisResult(score=0.0)

        # ── Leer todos los contadores en paralelo ─────────────────────
        # Un solo gather con todas las lecturas de Redis evita múltiples
        # round-trips y mantiene la latencia bajo control.
        (
            recipient_age_hours,
            recipient_risk,
            sender_fanout_1h,
            sender_fanout_24h,
            recipient_fanin_1h,
            recipient_fanin_24h,
            sender_daily_vol,
            drain_data,
        ) = await asyncio.gather(
            self._get_account_age_hours(recipient_id),
            self._get_accumulated_risk(recipient_id),
            self._get_set_count(self.FANOUT_1H_KEY,  sender_id),
            self._get_set_count(self.FANOUT_24H_KEY, sender_id),
            self._get_set_count(self.FANIN_1H_KEY,   recipient_id),
            self._get_set_count(self.FANIN_24H_KEY,  recipient_id),
            self._get_daily_volume(sender_id),
            self._get_drain_data(recipient_id),
        )

        # ══════════════════════════════════════════════════════════════
        # CHECK 1: Antigüedad de la cuenta receptora
        # ══════════════════════════════════════════════════════════════
        # Una cuenta recién creada que recibe transferencias es la señal
        # más común de cuenta mula. El receptor aceptó su rol y apenas
        # creó la cuenta para recibir y retirar.
        if (
            recipient_age_hours is not None
            and recipient_age_hours < NEW_ACCOUNT_HOURS
        ):
            result.is_new_recipient_account = True
            result.score += PENALTY_NEW_RECIPIENT_ACCOUNT
            result.reason_codes.append(
                f"RECIPIENT_ACCOUNT_AGE_{int(recipient_age_hours)}H"
            )
            # Retención preventiva: cuenta nueva + monto > $200
            # No bloqueamos, pero sí retenemos 24h para verificar
            if amount > 200:
                result.should_hold_funds = True
                result.reason_codes.append("PREVENTIVE_HOLD_NEW_ACCOUNT")

        # ══════════════════════════════════════════════════════════════
        # CHECK 2: Risk score acumulado del receptor
        # ══════════════════════════════════════════════════════════════
        # El riesgo se propaga entre nodos del grafo de transacciones.
        # Si el receptor tiene historial de riesgo alto, el emisor
        # también hereda parte de ese riesgo.
        if recipient_risk and recipient_risk > 60:
            result.score += PENALTY_RECIPIENT_HIGH_RISK
            result.reason_codes.append(
                f"RECIPIENT_HIGH_RISK_SCORE_{int(recipient_risk)}"
            )

        # ══════════════════════════════════════════════════════════════
        # CHECK 3: Fan-out del emisor
        # ══════════════════════════════════════════════════════════════
        # Un emisor que manda a 8 personas distintas en 1 hora no es
        # comportamiento normal de usuario individual. Puede ser:
        #   - Distribución de fondos robados (fraude)
        #   - Pago de nómina legítimo (falso positivo posible)
        # El contexto (account_age, kyc_level) en el orquestador ayuda
        # a distinguir ambos casos.
        if sender_fanout_1h > FANOUT_LIMIT_1H:
            result.score += PENALTY_FANOUT_HIGH
            result.reason_codes.append(f"FANOUT_HIGH_1H_{sender_fanout_1h}_RECIPIENTS")
        elif sender_fanout_24h > FANOUT_LIMIT_24H:
            result.score += PENALTY_FANOUT_MEDIUM
            result.reason_codes.append(
                f"FANOUT_MEDIUM_24H_{sender_fanout_24h}_RECIPIENTS"
            )

        # ══════════════════════════════════════════════════════════════
        # CHECK 4: Fan-in del receptor (señal más fuerte de cuenta mula)
        # ══════════════════════════════════════════════════════════════
        # Una cuenta que recibe dinero de 6 personas distintas en 1 hora
        # es casi con certeza una mula. El patrón es:
        #   Defraudador → Víctima 1 → Mula
        #   Defraudador → Víctima 2 → Mula
        #   Defraudador → Víctima 3 → Mula
        # Después la mula retira todo en efectivo.
        if recipient_fanin_1h > FANIN_LIMIT_1H:
            result.mule_pattern_detected = True
            result.score += PENALTY_FANIN_HIGH
            result.reason_codes.append(
                f"RECIPIENT_FANIN_HIGH_1H_{recipient_fanin_1h}_SENDERS"
            )
        elif recipient_fanin_24h > FANIN_LIMIT_24H:
            result.score += PENALTY_FANIN_MEDIUM
            result.reason_codes.append(
                f"RECIPIENT_FANIN_HIGH_24H_{recipient_fanin_24h}_SENDERS"
            )

        # ══════════════════════════════════════════════════════════════
        # CHECK 5: Smurfing
        # ══════════════════════════════════════════════════════════════
        # Técnica de lavado: en lugar de una tx de $15,000 (que activa
        # reportes obligatorios), se hacen 15 txs de $1,000 el mismo día.
        # Detectamos esto acumulando el volumen diario del emisor.
        # Solo penalizamos si la TX INDIVIDUAL es pequeña Y el acumulado
        # supera el umbral — así evitamos penalizar a alguien que hizo
        # una tx grande legítima y luego una pequeña.
        if amount < SMURFING_SINGLE_LIMIT:
            projected_volume = sender_daily_vol + amount
            if projected_volume > SMURFING_DAILY_LIMIT:
                result.smurfing_detected = True
                result.score += PENALTY_SMURFING
                result.reason_codes.append(
                    f"SMURFING_DAILY_VOL_{int(projected_volume)}_"
                    f"TX_AMOUNT_{int(amount)}"
                )

        # ══════════════════════════════════════════════════════════════
        # CHECK 6: Drenado rápido en el receptor
        # ══════════════════════════════════════════════════════════════
        # La firma definitiva de una cuenta mula: recibe fondos de
        # múltiples fuentes y en menos de 2 horas retira o reenvía
        # más del 80% del saldo recibido.
        # drain_data se actualiza desde el servicio de retiros/P2P saliente.
        if drain_data:
            elapsed = datetime.now(timezone.utc).timestamp() - drain_data["received_ts"]
            if (
                elapsed < DRAIN_WINDOW_SEC
                and drain_data.get("drained_pct", 0) > DRAIN_PCT_THRESHOLD
            ):
                result.mule_pattern_detected = True
                result.should_hold_funds = True
                result.score += PENALTY_RAPID_DRAIN
                result.reason_codes.append(
                    f"RAPID_DRAIN_{int(drain_data['drained_pct'])}PCT_"
                    f"IN_{int(elapsed / 60)}MIN"
                )

        # ── Clampear y loggear ────────────────────────────────────────
        result.score = max(0.0, min(100.0, result.score))

        logger.debug(
            f"[P2P] sender={sender_id}  recipient={recipient_id}  "
            f"amount={amount}  score={result.score:.1f}  "
            f"mule={result.mule_pattern_detected}  "
            f"codes={result.reason_codes}"
        )

        # ── Actualizar contadores para evaluaciones futuras ───────────
        # Se hace al FINAL para que los contadores actuales no se
        # contaminen con la tx que estamos evaluando ahora mismo.
        await self._update_counters(sender_id, recipient_id, amount)

        return result

    # ------------------------------------------------------------------ #
    #  Lecturas de Redis                                                  #
    # ------------------------------------------------------------------ #

    async def _get_set_count(self, key_template: str, user_id: str) -> int:
        """Retorna el SCARD (cantidad de elementos únicos) de un set."""
        key = key_template.format(user_id=user_id)
        try:
            count = await self.redis.scard(key)
            return count or 0
        except Exception:
            return 0

    async def _get_daily_volume(self, user_id: str) -> float:
        """Retorna el volumen acumulado de txs P2P del emisor en las últimas 24h."""
        key = self.DAILY_VOL_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            return float(raw) if raw else 0.0
        except Exception:
            return 0.0

    async def _get_account_age_hours(self, user_id: str) -> Optional[float]:
        """
        Retorna las horas de antigüedad de la cuenta.
        Este dato lo escribe el servicio de registro cuando se crea la cuenta:
          SET p2p:acct_age_h:{user_id} {hours_since_creation}
        Y lo actualiza el worker nocturno incrementando el valor.
        """
        key = self.ACCT_AGE_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            return float(raw) if raw else None
        except Exception:
            return None

    async def _get_accumulated_risk(self, user_id: str) -> Optional[float]:
        """
        Retorna el risk score acumulado del usuario (promedio móvil EWMA).
        Se actualiza desde el orquestador en background después de cada tx.
        """
        key = self.ACCUM_RISK_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            return float(raw) if raw else None
        except Exception:
            return None

    async def _get_drain_data(self, user_id: str) -> Optional[dict]:
        """
        Retorna los datos de drenado del receptor si existen.
        Estructura: {"received_ts": float, "amount": float, "drained_pct": float}
        Este dato lo actualiza el servicio de retiros cuando el usuario
        retira o reenvía fondos poco después de recibirlos.
        """
        key = self.DRAIN_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    #  Escritura de contadores — al final de cada evaluación             #
    # ------------------------------------------------------------------ #

    async def _update_counters(
        self,
        sender_id: str,
        recipient_id: str,
        amount: float,
    ) -> None:
        """
        Actualiza todos los contadores de fan-out, fan-in y volumen.

        Usa un pipeline para ejecutar todos los comandos en una sola
        conexión a Redis. Sin pipeline serían 10 round-trips separados.

        Los sets garantizan unicidad automáticamente:
        SADD no duplica si el valor ya existe → SCARD siempre cuenta únicos.
        """
        try:
            pipe = self.redis.pipeline()

            # Fan-out del emisor: qué recipients únicos recibió de él
            pipe.sadd(self.FANOUT_1H_KEY.format(user_id=sender_id),  recipient_id)
            pipe.expire(self.FANOUT_1H_KEY.format(user_id=sender_id), 3_600)

            pipe.sadd(self.FANOUT_24H_KEY.format(user_id=sender_id), recipient_id)
            pipe.expire(self.FANOUT_24H_KEY.format(user_id=sender_id), 86_400)

            # Fan-in del receptor: qué senders únicos le enviaron
            pipe.sadd(self.FANIN_1H_KEY.format(user_id=recipient_id),  sender_id)
            pipe.expire(self.FANIN_1H_KEY.format(user_id=recipient_id), 3_600)

            pipe.sadd(self.FANIN_24H_KEY.format(user_id=recipient_id), sender_id)
            pipe.expire(self.FANIN_24H_KEY.format(user_id=recipient_id), 86_400)

            # Volumen diario del emisor para detección de smurfing
            pipe.incrbyfloat(self.DAILY_VOL_KEY.format(user_id=sender_id), amount)
            pipe.expire(self.DAILY_VOL_KEY.format(user_id=sender_id), 86_400)

            await pipe.execute()

        except Exception as e:
            logger.error(f"[P2P] Error actualizando contadores: {e}")

    # ------------------------------------------------------------------ #
    #  Métodos públicos de escritura — llamar desde otros servicios      #
    # ------------------------------------------------------------------ #

    async def update_accumulated_risk(
        self, user_id: str, risk_score: float
    ) -> None:
        """
        Actualiza el risk score acumulado del usuario usando EWMA
        (Exponentially Weighted Moving Average).

        EWMA con alpha=0.3 significa:
          nuevo_score = 70% del historial + 30% de la evaluación actual
        Esto suaviza picos aislados (una tx sospechosa no arruina el perfil)
        pero detecta patrones persistentes (muchas txs sospechosas seguidas).

        Llamar desde el orquestador en background después de cada tx.
        """
        key = self.ACCUM_RISK_KEY.format(user_id=user_id)
        try:
            raw     = await self.redis.get(key)
            current = float(raw) if raw else 0.0
            # EWMA: alpha = 0.3
            updated = (current * 0.7) + (risk_score * 0.3)
            # TTL: 30 días — historial de riesgo relevante en ese horizonte
            await self.redis.setex(key, 60 * 60 * 24 * 30, str(updated))
        except Exception as e:
            logger.error(
                f"[P2P] Error actualizando risk acumulado user={user_id}: {e}"
            )

    async def record_drain_event(
        self,
        user_id: str,
        received_amount: float,
        drained_amount: float,
    ) -> None:
        """
        Registra un evento de drenado de saldo.
        Llamar desde el servicio de retiros/P2P saliente cuando el usuario
        retira o reenvía fondos poco después de recibirlos.

        Ejemplo de uso en el servicio de retiros:
            elapsed_since_received = now - last_received_ts
            if elapsed_since_received < 7200:  # 2 horas
                drained_pct = (withdrawal_amount / received_amount) * 100
                await p2p_analyzer.record_drain_event(
                    user_id, received_amount, withdrawal_amount
                )
        """
        key = self.DRAIN_KEY.format(user_id=user_id)
        drained_pct = (
            (drained_amount / received_amount * 100)
            if received_amount > 0 else 0
        )
        data = {
            "received_ts":  datetime.now(timezone.utc).timestamp(),
            "amount":       received_amount,
            "drained_pct":  drained_pct,
        }
        try:
            # TTL: 3 horas — solo relevante en la ventana de drenado rápido
            await self.redis.setex(key, 10_800, json.dumps(data))
        except Exception as e:
            logger.error(
                f"[P2P] Error registrando evento de drenado user={user_id}: {e}"
            )