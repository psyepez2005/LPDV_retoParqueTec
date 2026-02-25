FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /code

# ── Dependencias del sistema para compilar dlib y face_recognition ───
# cmake, build-essential → compilar dlib desde fuente
# libopenblas-dev        → operaciones matemáticas optimizadas
# liblapack-dev          → álgebra lineal (requerido por dlib)
# libx11-dev             → display (requerido por dlib)
# python3-dev            → headers de Python para extensiones C
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# ── Instalar dlib primero por separado (tarda ~5 min en compilar) ────
RUN pip install --no-cache-dir dlib

# ── Instalar el resto de dependencias ────────────────────────────────
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app /code/app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]