from pydantic_settings import BaseSettings
from pydantic import ConfigDict, computed_field, Field
import os
from typing import List, Union, Optional

class Settings(BaseSettings):
    model_config = ConfigDict(extra="allow", env_file=".env", case_sensitive=True)
    
    DEBUG: bool = False
    PROJECT_NAME: str = "BlindspotX Authentication"
    VERSION: str = "0.1.0"
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
    MS_SCOPES: Union[str, List[str]] = Field(
        default="https://graph.microsoft.com/User.Read"
    )

    USE_KEY_VAULT: bool = False
    KEY_VAULT_NAME: str = ""
    ENVIRONMENT: str = ""

    # Drift Detection settings
    DRIFT_DETECTION_ENABLED: bool = False
    DRIFT_CHECK_INTERVAL: int = 3600  # Default to hourly checks (in seconds)
    DRIFT_RETENTION_POLICY: str = "medium_term"
    DRIFT_ALERT_ENABLED: bool = False
    DRIFT_SECURITY_ALERTS: bool = False

     # Celery Configuration
    CELERY_BROKER_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Celery broker URL (Redis recommended)"
    )
    CELERY_RESULT_BACKEND: str = Field(
        default="redis://localhost:6379/0", 
        description="Celery result backend URL"
    )
    
    # Drift Detection Settings
    DRIFT_DETECTION_INTERVAL: int = Field(
        default=1800,  # 30 minutes
        description="Drift detection interval in seconds"
    )
    DRIFT_RETENTION_DAYS: int = Field(
        default=90,
        description="Number of days to retain drift snapshots"
    )
    DRIFT_BATCH_SIZE: int = Field(
        default=100,
        description="Batch size for processing drift items"
    )
    
    # Notification Settings
    DRIFT_ALERT_WEBHOOK: Optional[str] = Field(
        default=None,
        description="Webhook URL for drift alerts"
    )
    DRIFT_ALERT_EMAIL: Optional[str] = Field(
        default=None,
        description="Email address for drift alerts"
    )

    @computed_field
    @property
    def MS_AUTHORITY(self) -> str:
        return f"https://login.microsoftonline.com/{self.MS_TENANT_ID}"

    @computed_field
    @property
    def PARSED_MS_SCOPES(self) -> List[str]:
        """Parse MS_SCOPES from space-separated string if needed"""
        if isinstance(self.MS_SCOPES, str):
            return self.MS_SCOPES.split()
        return self.MS_SCOPES

    @computed_field
    @property
    def REFRESH_TOKEN_EXPIRE_MINUTES(self) -> int:
        """Convert refresh token expiry from days to minutes"""
        return self.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60

settings = Settings()
