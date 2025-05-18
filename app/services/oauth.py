from app.core.security import get_current_user

"""
This module implements the OAuth2 client for Microsoft Entra ID integration.
It handles token acquisition, validation, and refresh processes.
"""

import json
import logging
from typing import Dict, Optional

import msal
from fastapi import Depends, HTTPException, status

from app.core.config import settings
from app.core.database import secure_store
from app.models.user import User

logger = logging.getLogger(__name__)

class OAuth2Service:
    """Service to handle OAuth2 operations with Microsoft Entra ID"""
    
    def __init__(self):
        """Initialize the OAuth2 service with MSAL app"""
        self._msal_app = msal.ConfidentialClientApplication(
            client_id=settings.MS_CLIENT_ID,
            client_credential=settings.MS_CLIENT_SECRET,
            authority=settings.MS_AUTHORITY
        )
    
    def get_authorization_url(self, state: str) -> str:
        """Get authorization URL for Microsoft login"""
        return self._msal_app.get_authorization_request_url(
            scopes=settings.MS_SCOPES,
            state=state,
            redirect_uri=settings.MS_REDIRECT_URI
        )
    
    def acquire_token_by_auth_code(self, code: str) -> Dict:
        """Exchange authorization code for tokens"""
        result = self._msal_app.acquire_token_by_authorization_code(
            code=code,
            scopes=settings.MS_SCOPES,
            redirect_uri=settings.MS_REDIRECT_URI
        )
        
        # Check for errors
        if "error" in result:
            logger.error(f"Error acquiring token: {result.get('error')} - {result.get('error_description')}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error acquiring token: {result.get('error_description')}"
            )
        
        return result
    
    async def refresh_microsoft_token(self, user: User) -> Optional[Dict]:
        """Refresh Microsoft access token using stored refresh token"""
        # Get stored refresh token
        stored_refresh_token = await secure_store.get_value(f"refresh_token:{user.id}")
        if not stored_refresh_token:
            logger.warning(f"No refresh token found for user {user.id}")
            return None
        
        # Refresh the token
        result = self._msal_app.acquire_token_by_refresh_token(
            refresh_token=stored_refresh_token,
            scopes=settings.MS_SCOPES
        )
        
        # Check for errors
        if "error" in result:
            logger.error(f"Error refreshing token: {result.get('error')} - {result.get('error_description')}")
            return None
        
        # Store new refresh token
        if "refresh_token" in result:
            await secure_store.store_value(
                f"refresh_token:{user.id}", 
                result["refresh_token"],
                {
                    "user_id": str(user.id),
                    "refreshed_at": datetime.utcnow().isoformat()
                }
            )
        
        return result
    
    async def get_valid_ms_token(self, user: User) -> Optional[str]:
        """
        Get a valid Microsoft access token for the given user
        Refreshes the token if necessary
        """
        # Try to refresh the token
        token_result = await self.refresh_microsoft_token(user)
        
        if token_result and "access_token" in token_result:
            return token_result["access_token"]
        
        return None

# Create singleton instance
oauth2_service = OAuth2Service()

# Dependency to get valid Microsoft token
async def get_ms_token(user: User = Depends(get_current_user)) -> str:
    """Dependency to get a valid Microsoft token for API calls"""
    token = await oauth2_service.get_valid_ms_token(user)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not get valid Microsoft token"
        )
    return token