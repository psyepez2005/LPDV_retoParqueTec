# Usamos una imagen de Python ligera
FROM python:3.11-slim

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiamos primero el requirements para aprovechar la caché de Docker
COPY requirements.txt .

# Instalamos las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos TODO el código y el modelo entrenado (.pkl) al contenedor
COPY . .

# Exponemos el puerto
EXPOSE 8001

# Comando para arrancar el servidor
CMD ["uvicorn", "ml_api:app", "--host", "0.0.0.0", "--port", "8001"]