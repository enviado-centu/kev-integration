"""Configuration management for Kev integration."""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class KevConfig:
    """Configuration for Kev client and service.
    
    All settings can be overridden via environment variables:
    - KEV_BASE_URL: Base URL for Kev server (default: http://localhost:8009)
    - KEV_MODEL: Model name to use (default: kev-latest)
    - KEV_TIMEOUT: Request timeout in seconds (default: 30)
    - KEV_API_KEY: API key for authentication (optional)
    """
    
    base_url: str = "http://localhost:8009"
    model: str = "kev-latest"
    timeout: int = 30
    api_key: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "KevConfig":
        """Create configuration from environment variables."""
        return cls(
            base_url=os.environ.get("KEV_BASE_URL", "http://localhost:8009"),
            model=os.environ.get("KEV_MODEL", "kev-latest"),
            timeout=int(os.environ.get("KEV_TIMEOUT", "30")),
            api_key=os.environ.get("KEV_API_KEY"),
        )
    
    def validate(self) -> None:
        """Validate configuration values."""
        if not self.base_url:
            raise ValueError("base_url cannot be empty")
        if not self.model:
            raise ValueError("model cannot be empty")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
