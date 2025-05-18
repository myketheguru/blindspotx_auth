from pydantic_settings import BaseSettings
from pydantic import ConfigDict, computed_field
import os
from typing import List

class Settings(BaseSettings):
    model_config = ConfigDict(extra="allow", env_file=".env", case_sensitive=True)

    PROJECT_NAME: str = "BlindspotX Authentication"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = "super-secret-key-change-in-prod"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 4
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    DATABASE_URL: str = "sqlite:///./blindspotx.db"
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    MS_CLIENT_ID: str = ""
    MS_CLIENT_SECRET: str = ""
    MS_TENANT_ID: str = ""
    MS_REDIRECT_URI: str = "http://localhost:8000/api/auth/callback"
    MS_SCOPES: List[str] = ["User.Read"]

    USE_KEY_VAULT: bool = False
    KEY_VAULT_NAME: str = ""
    ENVIRONMENT: str = ""

    @computed_field
    @property
    def MS_AUTHORITY(self) -> str:
        return f"https://login.microsoftonline.com/{self.MS_TENANT_ID}"

settings = Settings()
