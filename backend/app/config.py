from __future__ import annotations

import os


class Settings:
    APP_NAME = os.getenv("PHANTOM_APP_NAME", "PHANTOM Security API")
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/phantom",
    )
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv("PHANTOM_CORS_ORIGINS", "http://localhost:5173").split(",")
        if origin.strip()
    ]


settings = Settings()
