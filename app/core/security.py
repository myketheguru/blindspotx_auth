import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User, get_user_by_email
from app.schemas.token import TokenPayload

# Create logger
logger = logging.getLogger(__name__)

# OAuth2 scheme for token validation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


def create_access_token(subject: str, permissions: list = None, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a new access token with given subject (typically user ID)
    and optional expiration delta
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "access"
    }

    # Add permissions to the token if provided
    if permissions:
        to_encode["permissions"] = permissions

    # Add issued at time for token freshness checks
    to_encode["iat"] = datetime.utcnow()

    # Encode the JWT token
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    # Log token creation (without the actual token)
    logger.info(f"Access token created for user {subject}, expires at {expire}")

    return encoded_jwt


def create_refresh_token(subject: str) -> str:
    """Create a refresh token with longer expiration"""
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "refresh",
        "iat": datetime.utcnow()
    }

    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    # Log refresh token creation (without the actual token)
    logger.info(f"Refresh token created for user {subject}, expires at {expire}")

    return encoded_jwt


async def decode_token(token: str) -> Dict[str, Any]:
    """Decode and verify JWT token"""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)

        # Check if token has expired
        if datetime.fromtimestamp(token_data.exp) < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload

    except jwt.PyJWTError as e:
        logger.warning(f"Token validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except ValidationError as e:
        logger.warning(f"Token payload validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current user from JWT token.
    Tries:
      - Authorization header (API clients)
      - access_token cookie (browser clients)
    """
    # Try getting token from Authorization header first
    authorization: str = request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    else:
        # Fallback to cookie
        token = request.cookies.get("access_token")
        if token and token.startswith("Bearer "):
            token = token.split(" ")[1]

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = await decode_token(token)

    email: str = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # Fetch user from DB
    user = await get_user_by_email(email, db)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")

    return user


def verify_permission(required_permission: str):
    """
    Dependency for checking if user has specific permission
    Usage:
        @router.get("/protected", dependencies=[Depends(verify_permission("read:data"))])
    """
    async def has_permission(token: str = Depends(oauth2_scheme)) -> bool:
        payload = await decode_token(token)

        # Check if user has required permission
        permissions = payload.get("permissions", [])
        if required_permission not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied. Required: {required_permission}",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return True

    return has_permission