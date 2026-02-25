
class FraudMotorException(Exception):
    """Base de todas las excepciones del motor."""
    status_code: int = 500
    message: str = "Error interno del motor antifraude."

    def __init__(self, message: str | None = None):
        self.message = message or self.__class__.message
        super().__init__(self.message)


class InvalidPayloadException(FraudMotorException):
    status_code = 422
    message = "Payload de transacción inválido."


class MissingEnrichedDataException(FraudMotorException):
    status_code = 422
    message = "No se pudo obtener información geográfica para evaluar la transacción."


class InvalidTokenException(FraudMotorException):
    """El JWT es inválido o expiró."""
    status_code = 401
    message = "Token inválido o expirado."


class EmailAlreadyExistsException(FraudMotorException):
    status_code = 409
    message = "Este correo ya está registrado."


class UsernameAlreadyExistsException(FraudMotorException):
    status_code = 409
    message = "Este nombre de usuario ya está en uso."


class CedulaAlreadyExistsException(FraudMotorException):
    status_code = 409
    message = "Esta cédula ya está registrada."


class InvalidCredentialsException(FraudMotorException):
    status_code = 401
    message = "Correo o contraseña incorrectos."


class AccountSuspendedException(FraudMotorException):
    status_code = 403
    message = "Tu cuenta ha sido suspendida. Contacta a soporte."


class FaceNotDetectedException(FraudMotorException):
    status_code = 422
    message = "No se detectó un rostro claro en la foto. Por favor sube una foto frontal con buena iluminación."


class OtpExpiredException(FraudMotorException):
    status_code = 400
    message = "El código de verificación ha expirado. Solicita uno nuevo."


class OtpInvalidException(FraudMotorException):
    status_code = 400
    message = "Código de verificación incorrecto."


class OtpMaxAttemptsException(FraudMotorException):
    status_code = 429
    message = "Demasiados intentos fallidos. Solicita un nuevo código."


class OtpAlreadyUsedException(FraudMotorException):
    status_code = 400
    message = "Este código de verificación ya fue utilizado."


class TransactionBlockedException(FraudMotorException):
    status_code = 403
    message = "Operación declinada por políticas de seguridad."


class TransactionUnderReviewException(FraudMotorException):
    status_code = 202
    message = "Tu transacción está siendo revisada. Te notificaremos pronto."


class BlacklistHitException(FraudMotorException):
    status_code = 403
    message = "Operación no permitida."


class RedisUnavailableException(FraudMotorException):
    status_code = 503
    message = "Servicio temporalmente no disponible. Intenta en unos momentos."


class DatabaseUnavailableException(FraudMotorException):
    status_code = 503
    message = "Servicio temporalmente no disponible. Intenta en unos momentos."


class ExternalApiUnavailableException(FraudMotorException):
    status_code = 503
    message = "No se pudo completar la verificación externa. Intenta nuevamente."


class EncryptionException(FraudMotorException):
    status_code = 500
    message = "Error al procesar datos sensibles."


class InvalidSignatureException(FraudMotorException):
    status_code = 400
    message = "Firma de respuesta inválida."