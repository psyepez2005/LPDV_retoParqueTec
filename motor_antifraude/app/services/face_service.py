"""
face_service.py
---------------
Servicio de procesamiento facial para registro y prueba de vida.

Responsabilidades:
  1. Al registrarse: detectar cara en la foto, extraer vector facial
     de 128 dimensiones, cifrar imagen y vector con AES-256-GCM
  2. En prueba de vida: recibir foto nueva, extraer vector, comparar
     con el vector guardado en DB, retornar True/False

Instalación requerida:
    pip install face_recognition cryptography

face_recognition usa dlib internamente. En el Dockerfile agregar:
    RUN apt-get update && apt-get install -y cmake build-essential
    RUN pip install face_recognition

Nota: face_recognition es pesado (~500MB con dlib). En producción
considerar AWS Rekognition o Face++ para no cargar el servidor.
Por ahora es la opción gratuita más precisa disponible.
"""

import json
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings
from app.services.auth_service import FaceNotDetectedException

logger = logging.getLogger(__name__)

# ── Clave AES-256 derivada del SECRET_KEY ─────────────────────────────
# AES-256 necesita exactamente 32 bytes de clave
# Usamos los primeros 32 bytes del hash SHA-256 del SECRET_KEY
import hashlib
_AES_KEY: bytes = hashlib.sha256(settings.SECRET_KEY.encode()).digest()


class FaceService:
    """
    Procesa fotos de cara para registro y comparación biométrica.

    Todos los datos biométricos se cifran con AES-256-GCM antes de
    guardarlos en la DB. La clave se deriva del SECRET_KEY de la app.

    Threshold de similitud: 0.6
    - < 0.6 → misma persona (menor distancia = más similar)
    - > 0.6 → personas distintas
    - El valor estándar de face_recognition es 0.6
    """

    SIMILARITY_THRESHOLD = 0.6

    async def process_registration_photo(
        self,
        image_bytes: bytes,
    ) -> tuple[bytes, bytes]:
        """
        Procesa la foto de registro.

        1. Detecta que haya exactamente una cara en la imagen
        2. Extrae el vector facial de 128 dimensiones
        3. Cifra la imagen original con AES-256-GCM
        4. Cifra el vector con AES-256-GCM
        5. Retorna (imagen_cifrada, vector_cifrado)

        Lanza FaceNotDetectedException si:
          - No se detecta ninguna cara
          - Se detectan múltiples caras (foto grupal)
        """
        try:
            import face_recognition
            import numpy as np

            # Decodificar imagen desde bytes
            image = face_recognition.load_image_file(
                __import__('io').BytesIO(image_bytes)
            )

            # Detectar caras en la imagen
            face_locations = face_recognition.face_locations(image)

            if len(face_locations) == 0:
                logger.warning("[Face] No se detectó ninguna cara en la foto de registro")
                raise FaceNotDetectedException()

            if len(face_locations) > 1:
                logger.warning(f"[Face] Se detectaron {len(face_locations)} caras — se esperaba 1")
                raise FaceNotDetectedException(
                    "Se detectaron múltiples rostros. Por favor sube una foto individual."
                )

            # Extraer vector facial (128 números flotantes)
            encodings = face_recognition.face_encodings(image, face_locations)
            if not encodings:
                raise FaceNotDetectedException()

            face_vector = encodings[0]   # numpy array de 128 floats

            # Cifrar imagen original
            image_encrypted = self._encrypt(image_bytes)

            # Cifrar vector como JSON
            vector_json    = json.dumps(face_vector.tolist()).encode()
            vector_encrypted = self._encrypt(vector_json)

            logger.info("[Face] Foto de registro procesada correctamente")
            return image_encrypted, vector_encrypted

        except FaceNotDetectedException:
            raise
        except ImportError:
            logger.error(
                "[Face] face_recognition no está instalado. "
                "Ejecutar: pip install face_recognition"
            )
            raise FaceNotDetectedException(
                "El servicio de verificación facial no está disponible."
            )
        except Exception as e:
            logger.error(f"[Face] Error procesando foto de registro: {e}")
            raise FaceNotDetectedException()

    async def verify_liveness(
        self,
        live_image_bytes: bytes,
        stored_encoding_encrypted: bytes,
    ) -> bool:
        """
        Compara la foto tomada en tiempo real con el vector guardado en DB.

        Parámetros:
          live_image_bytes            → bytes de la foto tomada ahora
          stored_encoding_encrypted   → vector cifrado guardado en DB

        Retorna True si la cara coincide, False si no coincide.
        Lanza FaceNotDetectedException si no se detecta cara en la foto nueva.
        """
        try:
            import face_recognition
            import numpy as np

            # Descifrar vector guardado
            vector_json   = self._decrypt(stored_encoding_encrypted)
            stored_vector = np.array(json.loads(vector_json))

            # Procesar foto nueva
            live_image    = face_recognition.load_image_file(
                __import__('io').BytesIO(live_image_bytes)
            )
            live_locations = face_recognition.face_locations(live_image)

            if not live_locations:
                raise FaceNotDetectedException(
                    "No se detectó un rostro en la foto. Intenta con mejor iluminación."
                )

            live_encodings = face_recognition.face_encodings(live_image, live_locations)
            if not live_encodings:
                raise FaceNotDetectedException()

            live_vector = live_encodings[0]

            # Calcular distancia euclidiana entre vectores
            # Menor distancia = más similar
            distance = face_recognition.face_distance([stored_vector], live_vector)[0]

            match = bool(distance < self.SIMILARITY_THRESHOLD)
            logger.info(
                f"[Face] Prueba de vida — distancia={distance:.4f}  "
                f"threshold={self.SIMILARITY_THRESHOLD}  match={match}"
            )
            return match

        except FaceNotDetectedException:
            raise
        except Exception as e:
            logger.error(f"[Face] Error en prueba de vida: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  Cifrado AES-256-GCM                                               #
    # ------------------------------------------------------------------ #

    def _encrypt(self, data: bytes) -> bytes:
        """
        Cifra datos con AES-256-GCM.

        Formato del output: nonce (12 bytes) + ciphertext + tag (16 bytes)
        El nonce es aleatorio y único por operación — se guarda junto
        al ciphertext para poder descifrar después.
        """
        aesgcm = AESGCM(_AES_KEY)
        nonce  = os.urandom(12)   # 96 bits, recomendado para GCM
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # Guardar nonce al inicio para recuperarlo al descifrar
        return nonce + ciphertext

    def _decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Descifra datos cifrados con AES-256-GCM.
        Extrae el nonce de los primeros 12 bytes.
        """
        aesgcm    = AESGCM(_AES_KEY)
        nonce     = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)


# Singleton
face_service = FaceService()