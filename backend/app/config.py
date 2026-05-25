from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/gsl_centinel"
    REDIS_URL: str = "redis://localhost:6379/0"
    MONGO_URL: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "gsl_centinel_tokens"
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60
    RESET_TOKEN_EXPIRY_MINUTES: int = 15
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    model_config = {"env_prefix": "GSL_"}


settings = Settings()
