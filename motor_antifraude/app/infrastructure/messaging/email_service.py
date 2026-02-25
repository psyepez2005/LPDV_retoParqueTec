"""
email_service.py
----------------
Servicio de envío de emails via SMTP con Gmail.

Usa aiosmtplib para envío asíncrono sin bloquear el event loop.
Compatible con cualquier servidor SMTP — configurado para Gmail.

Instalación requerida:
    pip install aiosmtplib

Uso:
    from app.infrastructure.messaging.email_service import email_service
    await email_service.send_otp(to="usuario@gmail.com", otp_code="847291")
"""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """
    Envía emails transaccionales via SMTP asíncrono.

    Métodos disponibles:
      - send_otp()          → envía el código OTP de verificación
      - send_confirmation() → envía confirmación de transacción aprobada
      - send_rejection()    → notifica que la transacción fue rechazada
    """

    async def _send(self, to: str, subject: str, html: str) -> bool:
        """
        Método base de envío. Maneja la conexión SMTP y el envío.
        Retorna True si se envió correctamente, False si hubo error.
        """
        message = MIMEMultipart("alternative")
        message["From"]    = settings.EMAIL_FROM
        message["To"]      = to
        message["Subject"] = subject
        message.attach(MIMEText(html, "html"))

        try:
            await aiosmtplib.send(
                message,
                hostname  = settings.SMTP_HOST,
                port      = settings.SMTP_PORT,
                username  = settings.SMTP_USER,
                password  = settings.SMTP_PASSWORD,
                start_tls = True,
            )
            logger.info(f"[Email] Enviado correctamente a {to} — asunto: {subject}")
            return True

        except aiosmtplib.SMTPException as e:
            logger.error(f"[Email] Error SMTP enviando a {to}: {e}")
        except Exception as e:
            logger.error(f"[Email] Error inesperado enviando a {to}: {e}")

        return False

    # ------------------------------------------------------------------ #
    #  Templates de email                                                 #
    # ------------------------------------------------------------------ #

    async def send_otp(self, to: str, otp_code: str) -> bool:
        """
        Envía el código OTP de verificación de compra.

        Parámetros:
          to       → email del usuario
          otp_code → código de 6 dígitos generado por OtpService
        """
        subject = "Tu código de verificación — Wallet Plux"
        html = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial,sans-serif;">
            <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                    <td align="center" style="padding:40px 0;">
                        <table width="480" cellpadding="0" cellspacing="0"
                               style="background:#ffffff; border-radius:8px;
                                      box-shadow:0 2px 8px rgba(0,0,0,0.08);">

                            <!-- Header -->
                            <tr>
                                <td style="background:#1a1a2e; border-radius:8px 8px 0 0;
                                           padding:24px 32px;">
                                    <h1 style="color:#ffffff; margin:0; font-size:22px;
                                               font-weight:700; letter-spacing:1px;">
                                        Wallet Plux
                                    </h1>
                                </td>
                            </tr>

                            <!-- Body -->
                            <tr>
                                <td style="padding:32px;">
                                    <p style="color:#333333; font-size:16px; margin:0 0 8px;">
                                        Código de verificación
                                    </p>
                                    <p style="color:#666666; font-size:14px; margin:0 0 24px;">
                                        Ingresa este código para confirmar tu transacción.
                                        Válido por <strong>5 minutos</strong>.
                                    </p>

                                    <!-- OTP Box -->
                                    <div style="background:#f0f4ff; border:2px solid #4361ee;
                                                border-radius:8px; padding:20px;
                                                text-align:center; margin:0 0 24px;">
                                        <span style="font-size:36px; font-weight:700;
                                                     color:#4361ee; letter-spacing:10px;">
                                            {otp_code}
                                        </span>
                                    </div>

                                    <p style="color:#999999; font-size:12px; margin:0;">
                                        Si no solicitaste este código, ignora este mensaje.
                                        Nunca compartas tu código con nadie.
                                    </p>
                                </td>
                            </tr>

                            <!-- Footer -->
                            <tr>
                                <td style="background:#f9f9f9; border-radius:0 0 8px 8px;
                                           padding:16px 32px; border-top:1px solid #eeeeee;">
                                    <p style="color:#aaaaaa; font-size:11px; margin:0;
                                               text-align:center;">
                                        © 2026 Wallet Plux. Este es un mensaje automático.
                                    </p>
                                </td>
                            </tr>

                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        return await self._send(to=to, subject=subject, html=html)

    async def send_confirmation(
        self,
        to: str,
        amount: str,
        currency: str,
        transaction_id: str,
    ) -> bool:
        """
        Envía confirmación de transacción aprobada.
        """
        subject = "Transacción confirmada — Wallet Plux"
        html = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head><meta charset="UTF-8"></head>
        <body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial,sans-serif;">
            <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                    <td align="center" style="padding:40px 0;">
                        <table width="480" cellpadding="0" cellspacing="0"
                               style="background:#ffffff; border-radius:8px;
                                      box-shadow:0 2px 8px rgba(0,0,0,0.08);">
                            <tr>
                                <td style="background:#1a1a2e; border-radius:8px 8px 0 0;
                                           padding:24px 32px;">
                                    <h1 style="color:#ffffff; margin:0; font-size:22px;">
                                        Wallet Plux
                                    </h1>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:32px;">
                                    <div style="text-align:center; margin-bottom:24px;">
                                        <span style="font-size:48px;">✅</span>
                                    </div>
                                    <h2 style="color:#333333; text-align:center;
                                               margin:0 0 8px;">
                                        Transacción aprobada
                                    </h2>
                                    <p style="color:#666666; text-align:center;
                                              font-size:14px; margin:0 0 24px;">
                                        Tu pago fue procesado exitosamente.
                                    </p>
                                    <table width="100%" style="background:#f9f9f9;
                                                               border-radius:8px;
                                                               padding:16px;">
                                        <tr>
                                            <td style="color:#666666; font-size:14px;
                                                       padding:4px 0;">Monto:</td>
                                            <td style="color:#333333; font-size:14px;
                                                       font-weight:700; text-align:right;
                                                       padding:4px 0;">
                                                {amount} {currency}
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="color:#666666; font-size:12px;
                                                       padding:4px 0;">ID:</td>
                                            <td style="color:#aaaaaa; font-size:11px;
                                                       text-align:right; padding:4px 0;">
                                                {transaction_id}
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                            <tr>
                                <td style="background:#f9f9f9; border-radius:0 0 8px 8px;
                                           padding:16px 32px; border-top:1px solid #eeeeee;">
                                    <p style="color:#aaaaaa; font-size:11px; margin:0;
                                               text-align:center;">
                                        © 2026 Wallet Plux. Este es un mensaje automático.
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        return await self._send(to=to, subject=subject, html=html)

    async def send_rejection(self, to: str) -> bool:
        """
        Notifica al usuario que su transacción fue rechazada.
        El mensaje es genérico a propósito — no revelar la razón del rechazo.
        """
        subject = "Transacción no procesada — Wallet Plux"
        html = """
        <!DOCTYPE html>
        <html lang="es">
        <head><meta charset="UTF-8"></head>
        <body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial,sans-serif;">
            <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                    <td align="center" style="padding:40px 0;">
                        <table width="480" cellpadding="0" cellspacing="0"
                               style="background:#ffffff; border-radius:8px;
                                      box-shadow:0 2px 8px rgba(0,0,0,0.08);">
                            <tr>
                                <td style="background:#1a1a2e; border-radius:8px 8px 0 0;
                                           padding:24px 32px;">
                                    <h1 style="color:#ffffff; margin:0; font-size:22px;">
                                        Wallet Plux
                                    </h1>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:32px; text-align:center;">
                                    <span style="font-size:48px;">❌</span>
                                    <h2 style="color:#333333; margin:16px 0 8px;">
                                        Transacción no procesada
                                    </h2>
                                    <p style="color:#666666; font-size:14px; margin:0 0 16px;">
                                        No pudimos procesar tu transacción por políticas
                                        de seguridad. Si crees que esto es un error,
                                        contacta a soporte.
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <td style="background:#f9f9f9; border-radius:0 0 8px 8px;
                                           padding:16px 32px; border-top:1px solid #eeeeee;">
                                    <p style="color:#aaaaaa; font-size:11px; margin:0;
                                               text-align:center;">
                                        © 2026 Wallet Plux. Este es un mensaje automático.
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        return await self._send(to=to, subject=subject, html=html)


# Singleton
email_service = EmailService()