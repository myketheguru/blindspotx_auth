from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until token expires


class TokenPayload(BaseModel):
    sub: Optional[str] = None  # Subject (typically user ID or email)
    exp: int  # Expiration time (UTC timestamp)
    iat: Optional[int] = None  # Issued at time
    type: str  # Token type (access or refresh)
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