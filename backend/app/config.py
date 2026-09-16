from __future__ import annotations
import os

class Settings:
    APP_NAME = os.getenv("PHANTOM_APP_NAME", "PHANTOM Security API")
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/phantom")
    CORS_ORIGINS = [origin.strip() for origin in os.getenv("PHANTOM_CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip()]
    AUTH_SECRET = os.getenv("PHANTOM_AUTH_SECRET", "change-this-development-secret")
    BOOTSTRAP_EMAIL = os.getenv("PHANTOM_BOOTSTRAP_EMAIL", "admin@phantom.local")
    BOOTSTRAP_PASSWORD = os.getenv("PHANTOM_BOOTSTRAP_PASSWORD", "change-me-before-production")
    BOOTSTRAP_ROLE = os.getenv("PHANTOM_BOOTSTRAP_ROLE", "owner")
    SESSION_HOURS = int(os.getenv("PHANTOM_SESSION_HOURS", "12"))
    SCAN_MODULE_TIMEOUT_SECONDS = int(os.getenv("PHANTOM_SCAN_MODULE_TIMEOUT_SECONDS", "120"))
    SCAN_TOTAL_TIMEOUT_SECONDS = int(os.getenv("PHANTOM_SCAN_TOTAL_TIMEOUT_SECONDS", "900"))
    SCAN_MAX_MODULES = int(os.getenv("PHANTOM_SCAN_MAX_MODULES", "32"))
    MAX_CONCURRENT_SCANS = int(os.getenv("PHANTOM_MAX_CONCURRENT_SCANS", "2"))
    SCAN_REQUEST_BUDGET = int(os.getenv("PHANTOM_SCAN_REQUEST_BUDGET", "250"))
    SCAN_MAX_REDIRECTS = int(os.getenv("PHANTOM_SCAN_MAX_REDIRECTS", "3"))

settings = Settings()
