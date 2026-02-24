from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Configuracion general
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str

    # PostgreSQL
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str

    # Redis
    REDIS_HOST: str
    REDIS_PORT: int = 6379
    REDIS_URL: str

    # HMAC para firma de respuestas del motor
    FRAUD_HMAC_SECRET: str = "dev-secret-change-in-production"

    # CORS — lista de orígenes permitidos separados por coma en el .env
    # Ejemplo en .env: ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # APIs externas
    EXTERNAL_API_KEY: str | None = None

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_origins(cls, v):
        """Permite definir ALLOWED_ORIGINS como string separado por comas en .env"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    model_config = SettingsConfigDict(
        env_file          = ".env",
        env_file_encoding = "utf-8",
        case_sensitive    = True,
        extra             = "ignore",
    )


settings = Settings()