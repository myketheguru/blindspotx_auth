from pydantic_settings import BaseSettings
from pydantic import ConfigDict
import os
from typing import List

class Settings(BaseSettings):
    model_config = ConfigDict(extra="allow", env_file=".env", case_sensitive=True)

    PROJECT_NAME: str = "BlindspotX Authentication"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "super-secret-key-change-in-prod")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 4  # 4 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database config
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./blindspotx.db")

    # CORS settings
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    # Microsoft OAuth settings
    MS_CLIENT_ID: str = os.environ.get("MS_CLIENT_ID", "")
    MS_CLIENT_SECRET: str = os.environ.get("MS_CLIENT_SECRET", "")
    MS_TENANT_ID: str = os.environ.get("MS_TENANT_ID", "")
    MS_REDIRECT_URI: str = os.environ.get("MS_REDIRECT_URI", "http://localhost:8000/api/auth/callback")
    MS_AUTHORITY: str = f"https://login.microsoftonline.com/{os.environ.get('MS_TENANT_ID', '')}"
    MS_SCOPES: List[str] = ["User.Read", "offline_access"]

    # Key Vault settings (for production)
    USE_KEY_VAULT: bool = os.environ.get("USE_KEY_VAULT", "false").lower() == "true"
    KEY_VAULT_NAME: str = os.environ.get("KEY_VAULT_NAME", "")

settings = Settings()
