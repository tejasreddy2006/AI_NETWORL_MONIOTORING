"""NetGuard AI — Application configuration.

Defines configuration classes for different environments (development,
production, testing).  All sensitive values are read from environment
variables with sensible defaults so the app can start without a .env file
during local development / demo mode.
"""

from __future__ import annotations

import os
from typing import Dict, Type

from dotenv import load_dotenv

# Load .env file
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))



class BaseConfig:
    """Base configuration shared across all environments."""

    # ── Flask core ────────────────────────────────────────────────────
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "netguard-dev-secret-key-change-me")

    # ── Database ──────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        "mysql+pymysql://netguard:netguard@localhost:3306/netguard_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # ── Redis ─────────────────────────────────────────────────────────
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # ── CORS ──────────────────────────────────────────────────────────
    CORS_ORIGINS: str = os.environ.get("CORS_ORIGINS", "*")

    # ── Packet capture ────────────────────────────────────────────────
    PACKET_CAPTURE_INTERFACE: str = os.environ.get("PACKET_CAPTURE_INTERFACE", "eth0")
    PACKET_BATCH_SIZE: int = int(os.environ.get("PACKET_BATCH_SIZE", "100"))
    PACKET_BATCH_INTERVAL: int = int(os.environ.get("PACKET_BATCH_INTERVAL", "2"))

    # ── Demo mode ─────────────────────────────────────────────────────
    DEMO_MODE: bool = os.environ.get("DEMO_MODE", "true").lower() == "true"

    # ── AI provider ───────────────────────────────────────────────────
    AI_PROVIDER: str = os.environ.get("AI_PROVIDER", "ollama")  # ollama | openai
    OLLAMA_URL: str = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.environ.get("OLLAMA_MODEL", "llama3")
    OPENAI_API_KEY: str = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    # ── GeoIP ─────────────────────────────────────────────────────────
    GEOIP_DB_PATH: str = os.environ.get(
        "GEOIP_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "GeoLite2-City.mmdb")
    )

    # ── ML ────────────────────────────────────────────────────────────
    ML_MODELS_DIR: str = os.environ.get(
        "ML_MODELS_DIR", os.path.join(os.path.dirname(__file__), "..", "ml_models")
    )

    # ── Logging ───────────────────────────────────────────────────────
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

    # ── Data retention ────────────────────────────────────────────────
    DATA_RETENTION_DAYS: int = int(os.environ.get("DATA_RETENTION_DAYS", "7"))


class DevelopmentConfig(BaseConfig):
    """Development-specific configuration."""

    DEBUG: bool = True


class ProductionConfig(BaseConfig):
    """Production-specific configuration."""

    DEBUG: bool = False


class TestingConfig(BaseConfig):
    """Testing-specific configuration."""

    TESTING: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"


# Mapping of config name → class for use by the app factory.
config_map: Dict[str, Type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
