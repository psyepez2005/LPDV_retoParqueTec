from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Configuracion general del entorno de ejecucion
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str

    # Credenciales y conexion a la base de datos PostgreSQL
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str

    # Parametros de conexion a Redis para el manejo de cache y estado
    REDIS_HOST: str
    REDIS_PORT: int = 6379
    REDIS_URL: str

    # Claves de acceso para servicios de terceros (enriquecimiento de datos)
    EXTERNAL_API_KEY: str | None = None

    # Carga automatica de variables desde el archivo local .env
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        case_sensitive=True,
        extra="ignore"
    )

# Instancia global para ser importada en el resto de la aplicacion
settings = Settings()