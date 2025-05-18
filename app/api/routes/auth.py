import base64
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union

import httpx
import jwt
import msal
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db, secure_store
from app.core.security import create_access_token, create_refresh_token, get_current_user

from app.models.user import User, create_user, get_user_by_azure_id, get_user_by_email, get_user_permissions
from app.schemas.token import AzureADToken, RefreshTokenRequest, Token

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize MSAL confidential client application
def get_msal_app():
    """Get MSAL confidential client application"""
    return msal.ConfidentialClientApplication(
        client_id=settings.MS_CLIENT_ID,
        client_credential=settings.MS_CLIENT_SECRET,
        authority=settings.MS_AUTHORITY
    )

@router.get("/login")
async def login():
    """
    Initiate OAuth2 login flow with Microsoft Entra ID
    Returns URL for redirecting user to Microsoft login page
    """
    # Generate and store state parameter to prevent CSRF
    state = str(uuid.uuid4())
    await secure_store.store_value(f"state:{state}", state, {"created_at": datetime.utcnow().isoformat()})
    
    # Get login URL from MSAL
    msal_app = get_msal_app()
    auth_url = msal_app.get_authorization_request_url(
        scopes=settings.MS_SCOPES,
        state=state,
        redirect_uri=settings.MS_REDIRECT_URI
    )
    
    logger.info(f"Initiating OAuth2 flow with state: {state}")
    
    # Return the authorization URL
    return {"login_url": auth_url}

@router.get("/callback")
async def auth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Handle OAuth2 callback from Microsoft Entra ID
    Exchanges code for tokens and creates/updates user
    """
    # Check for errors
    if error:
        logger.error(f"OAuth2 callback error: {error} - {error_description}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authentication failed: {error_description}"
        )
    
    # Validate state parameter to prevent CSRF
    if not state:
        logger.warning("Missing state parameter in OAuth callback")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing state parameter"
        )
    
    stored_state = await secure_store.get_value(f"state:{state}")
    if not stored_state or stored_state != state:
        logger.warning(f"Invalid state parameter: {state}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter"
        )
    
    # Clean up stored state
    await secure_store.delete_value(f"state:{state}")
    
    # Exchange code for tokens
    if not code:
        logger.warning("Missing authorization code in OAuth callback")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code"
        )
    
    # Get tokens from Microsoft
    msal_app = get_msal_app()
    result = msal_app.acquire_token_by_authorization_code(
        code=code,
        scopes=settings.MS_SCOPES,
        redirect_uri=settings.MS_REDIRECT_URI
    )
    
    # Check for errors in token response
    if "error" in result:
        logger.error(f"Error acquiring token: {result.get('error')} - {result.get('error_description')}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error acquiring token: {result.get('error_description')}"
        )
    
    # Extract tokens and user info
    access_token = result.get("access_token")
    refresh_token = result.get("refresh_token")
    id_token = result.get("id_token")
    expires_in = result.get("expires_in", 3600)
    
    # Decode the ID token to get user info
    user_info = {}
    if id_token:
        try:
            # ID token is a JWT, split and decode the payload (middle part)
            # Note: This doesn't verify the token signature as it's already verified by MSAL
            id_token_parts = id_token.split('.')
            if len(id_token_parts) >= 2:
                # Add padding if needed
                padded = id_token_parts[1] + '=' * (4 - len(id_token_parts[1]) % 4)
                payload = json.loads(base64.b64decode(padded).decode('utf-8'))
                
                # Extract user information
                user_info = {
                    "object_id": payload.get("oid"),
                    "email": payload.get("preferred_username") or payload.get("email"),
                    "name": payload.get("name"),
                }
        except Exception as e:
            logger.warning(f"Error decoding ID token: {str(e)}")
    
    # If ID token wasn't available or couldn't be decoded, fetch user info using Graph API
    if not user_info.get("email") and access_token:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://graph.microsoft.com/v1.0/me",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                if response.status_code == 200:
                    user_data = response.json()
                    user_info = {
                        "object_id": user_data.get("id"),
                        "email": user_data.get("userPrincipalName") or user_data.get("mail"),
                        "name": user_data.get("displayName"),
                    }
                else:
                    logger.warning(f"Error fetching user info from Graph API: {response.status_code} {response.text}")
        except Exception as e:
            logger.warning(f"Error calling Microsoft Graph API: {str(e)}")
    
    # Ensure we have at least email
    if not user_info.get("email"):
        logger.error("Could not obtain user email from tokens or Graph API")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not obtain user information"
        )
    
    # Check if user exists, create if not
    user = await get_user_by_azure_id(user_info.get("object_id"))
    if not user:
        # Check if user exists with email
        user = await get_user_by_email(user_info.get("email"))
        
        if not user:
            # Create new user
            user_data = {
                "email": user_info.get("email"),
                "full_name": user_info.get("name"),
                "azure_object_id": user_info.get("object_id"),
                "is_active": True
            }
            user = await create_user(user_data, db)
            logger.info(f"Created new user: {user.email}")
        else:
            # Update existing user with Azure Object ID
            user.azure_object_id = user_info.get("object_id")
            if user_info.get("name"):
                user.full_name = user_info.get("name")
            db.add(user)
            await db.commit()
            await db.refresh(user)
            logger.info(f"Updated existing user with Azure ID: {user.email}")
    
    # Store refresh token securely (encrypted in database)
    if refresh_token:
        await secure_store.store_value(
            f"refresh_token:{user.id}", 
            refresh_token,
            {
                "user_id": str(user.id),
                "created_at": datetime.utcnow().isoformat()
            }
        )
    
    # Get user permissions
    permissions = await get_user_permissions(user.id, db)
    
    # Create our own access and refresh tokens
    access_token = create_access_token(
        subject=user.email,
        permissions=permissions,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    refresh_token = create_refresh_token(subject=user.email)
    
    # Return tokens in response
    token_response = Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    # Redirect to frontend with tokens (in production, use a more secure method)
    frontend_url = "http://localhost:3000/auth/callback"
    redirect_url = f"{frontend_url}?access_token={access_token}&refresh_token={refresh_token}&expires_in={settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60}"
    
    return RedirectResponse(url=redirect_url)

@router.post("/refresh", response_model=Token)
async def refresh_token(
    request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token
    """
    try:
        # Decode the refresh token to get the subject (user email)
        payload = jwt.decode(
            request.refresh_token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        # Check token type
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user email from token
        email = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user from database
        user = await get_user_by_email(email, db)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user permissions
        permissions = await get_user_permissions(user.id, db)
        
        # Create new access token
        new_access_token = create_access_token(
            subject=email,
            permissions=permissions,
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        # Create new refresh token
        new_refresh_token = create_refresh_token(subject=email)
        
        return Token(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except jwt.PyJWTError as e:
        logger.warning(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """
    Logout user and invalidate tokens
    """
    # In a real implementation, we would add the token to a blocklist or revoke it
    # For now, just return success
    try:
        # Delete stored refresh token
        await secure_store.delete_value(f"refresh_token:{current_user.id}")
        
        # Add JWT to a blocklist (not implemented in this example)
        # In production, use Redis or similar for token blocklisting
        
        return {"message": "Successfully logged out"}
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing logout"
        )