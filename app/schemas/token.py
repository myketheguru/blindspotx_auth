from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until token expires


class TokenPayload(BaseModel):
    sub: str  # Subject (typically user email)
    uid: str  # User ID
    exp: int  # Expiration time (integer UTC timestamp)
    iat: int  # Issued at time (integer UTC timestamp)
    type: str  # Token type (access or refresh)
    jti: str  # JWT ID (unique identifier for this token)
    permissions: Optional[List[str]] = None  # User permissions


class AzureADToken(BaseModel):
    id_token: Optional[str] = None
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: int
    scope: str
    token_type: str
    
    # Additional fields from decoded id_token
    user_id: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str