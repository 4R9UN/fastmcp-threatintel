import logging
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger("threatintel.settings")


def find_and_load_dotenv():
    """Search for and load .env file from common locations."""
    # Start from the current directory and go up
    current_dir = Path.cwd()
    search_paths: list[Path] = [current_dir] + list(current_dir.parents)

    # Also check user's home directory
    home_dir = Path.home()
    if home_dir not in search_paths:
        search_paths.append(home_dir)

    # Check for .env file in each path
    for path in search_paths:
        dotenv_path = path / ".env"
        if dotenv_path.exists():
            load_dotenv(dotenv_path=dotenv_path)
            logger.info(f"Loaded .env file from: {dotenv_path}")
            return

    logger.info("No .env file found in common locations.")


# Load environment variables
find_and_load_dotenv()


class Settings(BaseModel):
    """Application settings including API keys and performance configurations."""

    # API Keys
    virustotal_api_key: str | None = Field(
        default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"), description="VirusTotal API Key"
    )
    otx_api_key: str | None = Field(
        default_factory=lambda: os.getenv("OTX_API_KEY"), description="AlienVault OTX API Key"
    )
    abuseipdb_api_key: str | None = Field(
        default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY"), description="AbuseIPDB API Key"
    )
    ipinfo_api_key: str | None = Field(
        default_factory=lambda: os.getenv("IPINFO_API_KEY"), description="IPinfo API Key"
    )

    @field_validator(
        "virustotal_api_key",
        "otx_api_key",
        "abuseipdb_api_key",
        "ipinfo_api_key",
        mode="before",
    )
    @classmethod
    def strip_api_keys(cls, v: str | None) -> str | None:
        """Remove leading/trailing whitespace from API keys."""
        if isinstance(v, str):
            return v.strip()
        return v

    # Performance settings
    max_retries: int = Field(default=3, description="Maximum number of API request retries")
    request_timeout: float = Field(default=10.0, description="API request timeout in seconds")
    cache_ttl: int = Field(default=3600, description="Cache TTL in seconds (1 hour)")

    # Connection settings
    user_agent: str = Field(
        default="FastMCP-ThreatIntel/1.0", description="User agent used for API requests"
    )

    @field_validator("max_retries")
    @classmethod
    def validate_max_retries(cls, v: int) -> int:
        if v < 0:
            raise ValueError("max_retries cannot be negative")
        return v

    @field_validator("request_timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("request_timeout must be positive")
        return v

    @model_validator(mode="after")
    def log_missing_keys(self) -> "Settings":
        missing_keys = []
        if not self.virustotal_api_key:
            missing_keys.append("VIRUSTOTAL_API_KEY")
        if not self.otx_api_key:
            missing_keys.append("OTX_API_KEY")
        if not self.abuseipdb_api_key:
            missing_keys.append("ABUSEIPDB_API_KEY")

        if missing_keys:
            logger.warning(f"Missing API keys: {', '.join(missing_keys)}")

        return self


@lru_cache
def get_settings() -> Settings:
    """Get cached application settings."""
    return Settings()


# Singleton instance
settings = get_settings()
