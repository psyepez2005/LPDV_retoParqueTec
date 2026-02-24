"""
exceptions.py
-------------
Excepciones personalizadas del Motor Antifraude.

Todas heredan de FraudMotorException para poder capturarlas
en un solo handler global en main.py.

Uso en main.py:
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from app.core.exceptions import FraudMotorException

    @app.exception_handler(FraudMotorException)
    async def fraud_exception_handler(request: Request, exc: FraudMotorException):
        return JSONResponse(status_code=exc.status_code, content={"error": exc.message})
"""


class FraudMotorException(Exception):
    """Base de todas las excepciones del motor."""
    status_code: int = 500
    message: str = "Error interno del motor antifraude."

    def __init__(self, message: str | None = None):
        self.message = message or self.__class__.message
        super().__init__(self.message)


# ─────────────────────────────────────────────────────────────────────
# Errores de validación y payload
# ─────────────────────────────────────────────────────────────────────

class InvalidPayloadException(FraudMotorException):
    """El payload recibido no cumple con el esquema esperado."""
    status_code = 422
    message = "Payload de transacción inválido."


class MissingEnrichedDataException(FraudMotorException):
    """El middleware no pudo enriquecer el payload con datos de GeoIP o BIN."""
    status_code = 422
    message = "No se pudo obtener información geográfica para evaluar la transacción."


# ─────────────────────────────────────────────────────────────────────
# Errores de autenticación y OTP
# ─────────────────────────────────────────────────────────────────────

class OtpExpiredException(FraudMotorException):
    """El OTP ingresado ya expiró (TTL de 5 minutos superado)."""
    status_code = 400
    message = "El código de verificación ha expirado. Solicita uno nuevo."


class OtpInvalidException(FraudMotorException):
    """El OTP ingresado no coincide con el emitido."""
    status_code = 400
    message = "Código de verificación incorrecto."


class OtpMaxAttemptsException(FraudMotorException):
    """Se superaron los 3 intentos permitidos para ingresar el OTP."""
    status_code = 429
    message = "Demasiados intentos fallidos. Solicita un nuevo código."


class OtpAlreadyUsedException(FraudMotorException):
    """El OTP ya fue utilizado anteriormente."""
    status_code = 400
    message = "Este código de verificación ya fue utilizado."


# ─────────────────────────────────────────────────────────────────────
# Errores de transacción
# ─────────────────────────────────────────────────────────────────────

class TransactionBlockedException(FraudMotorException):
    """La transacción fue bloqueada por el motor antifraude."""
    status_code = 403
    message = "Operación declinada por políticas de seguridad."


class TransactionUnderReviewException(FraudMotorException):
    """La transacción está en revisión manual."""
    status_code = 202
    message = "Tu transacción está siendo revisada. Te notificaremos pronto."


class BlacklistHitException(FraudMotorException):
    """Una entidad de la transacción está en lista negra."""
    status_code = 403
    message = "Operación no permitida."


# ─────────────────────────────────────────────────────────────────────
# Errores de infraestructura
# ─────────────────────────────────────────────────────────────────────

class RedisUnavailableException(FraudMotorException):
    """Redis no está disponible. El motor opera en modo degradado."""
    status_code = 503
    message = "Servicio temporalmente no disponible. Intenta en unos momentos."


class DatabaseUnavailableException(FraudMotorException):
    """PostgreSQL no está disponible."""
    status_code = 503
    message = "Servicio temporalmente no disponible. Intenta en unos momentos."


class ExternalApiUnavailableException(FraudMotorException):
    """La API externa (Sift/Kount/MaxMind) no respondió en el tiempo límite."""
    status_code = 503
    message = "No se pudo completar la verificación externa. Intenta nuevamente."


# ─────────────────────────────────────────────────────────────────────
# Errores de cifrado
# ─────────────────────────────────────────────────────────────────────

class EncryptionException(FraudMotorException):
    """Error durante el cifrado o descifrado de datos sensibles."""
    status_code = 500
    message = "Error al procesar datos sensibles."


class InvalidSignatureException(FraudMotorException):
    """La firma HMAC de la respuesta no es válida."""
    status_code = 400
    message = "Firma de respuesta inválida."