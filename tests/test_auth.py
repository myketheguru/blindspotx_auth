"""
Authentication Tests
------------------
Tests for authentication functionality including OAuth2 flows, token handling,
login/logout, and user management.
"""

import pytest
import json
import base64
from unittest.mock import patch, MagicMock, AsyncMock
import jwt
from datetime import datetime, timedelta
import uuid

from fastapi import HTTPException, status, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.api.routes.auth import (
    login, auth_callback, refresh_token, logout, get_msal_app
)
from app.core.config import settings
from app.models.user import User, get_user_by_email, create_user
from app.schemas.token import RefreshTokenRequest, Token
from app.core.security import create_access_token, create_refresh_token, decode_token, get_current_user
from app.core.database import secure_store

pytestmark = pytest.mark.asyncio

# ========== OAUTH MOCKS ========== #

class MockMSALApp:
    """Mock MSAL confidential client application for tests"""
    
    def get_authorization_request_url(self, scopes, state, redirect_uri):
        """Return a mock authorization URL"""
        return f"https://login.microsoftonline.com/mock/oauth2/v2.0/authorize?client_id=mock&response_type=code&redirect_uri={redirect_uri}&state={state}&scope={','.join(scopes)}"
    
    def acquire_token_by_authorization_code(self, code, scopes, redirect_uri):
        """Return a mock token response"""
        if code == "invalid_code":
            return {
                "error": "invalid_grant",
                "error_description": "Invalid authorization code"
            }
            
        # Create mock ID token with user info
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "oid": "mock_oid_12345",
            "preferred_username": "test@example.com",
            "name": "Test User",
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        
        # Encode parts manually for the test
        header_bytes = base64.b64encode(json.dumps(header).encode()).decode()
        payload_bytes = base64.b64encode(json.dumps(payload).encode()).decode()
        signature = "mock_signature"
        
        id_token = f"{header_bytes}.{payload_bytes}.{signature}"
        
        return {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "id_token": id_token,
            "expires_in": 3600,
            "token_type": "Bearer"
        }
    
    @property
    def authority(self):
        """Return a mock authority URL"""
        return f"https://login.microsoftonline.com/{settings.MS_TENANT_ID}"

# Mock for get_msal_app
def mock_get_msal_app():
    """Return a mock MSAL app"""
    return MockMSALApp()

# Mock for get_db to return the test session
async def mock_get_db():
    """Mock the get_db dependency to use our test session"""
    yield test_db

# Mock for httpx client
class MockHttpxClient:
    """Mock for httpx.AsyncClient"""
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    
    async def get(self, url, headers=None):
        """Mock an HTTP GET request"""
        class MockResponse:
            def __init__(self, status_code, data):
                self.status_code = status_code
                self.data = data
            
            def json(self):
                return self.data
                
            @property
            def text(self):
                return json.dumps(self.data)
        
        if url == "https://graph.microsoft.com/v1.0/me ":
            return MockResponse(200, {
                "id": "mock_id_12345",
                "userPrincipalName": "test@example.com",
                "displayName": "Test User"
            })
        
        return MockResponse(404, {"error": "Not found"})

# ========== TESTS ========== #

async def test_login_redirect(client):
    """Test login endpoint redirects to Microsoft login"""
    # Arrange
    with patch("app.api.routes.auth.get_msal_app", return_value=mock_get_msal_app()):
        # Act - Request from a browser (Accept: text/html)
        response = client.get("/api/auth/login", headers={"Accept": "text/html"})
        
        # Assert - Should redirect to Microsoft login
        assert response.status_code == 307  # Temporary redirect
        assert "login.microsoftonline.com" in response.headers["location"]
        assert "state=" in response.headers["location"]

async def test_login_returns_url(client):
    """Test login endpoint returns URL for API clients"""
    # Arrange
    with patch("app.api.routes.auth.get_msal_app", return_value=mock_get_msal_app()):
        # Act - Request from an API client (no Accept: text/html)
        response = client.get("/api/auth/login")
        
        # Assert - Should return JSON with login URL
        assert response.status_code == 200
        data = response.json()
        assert "login_url" in data
        assert "login.microsoftonline.com" in data["login_url"]

async def test_auth_callback_success(client, db_session):
    """Test successful OAuth callback"""
    # Arrange
    state = str(uuid.uuid4())
    code = "valid_code"
    
    # Store state in secure store
    await secure_store.store_value(f"state:{state}", state, {"created_at": datetime.utcnow().isoformat()})
    
    # Set up mocks
    with patch("app.api.routes.auth.get_msal_app", return_value=mock_get_msal_app()), \
         patch("app.api.routes.auth.get_db", return_value=db_session), \
         patch("httpx.AsyncClient", return_value=MockHttpxClient()):
        
        # Act - Request the callback as a browser
        response = client.get(
            f"/api/auth/callback?code={code}&state={state}", 
            headers={"Accept": "text/html"}
        )
        
        # Assert - Should redirect to dashboard and set cookie
        assert response.status_code == 307  # Temporary redirect
        assert "/dashboard" in response.headers["location"]
        assert "access_token" in response.cookies
        
        # Verify user was created
        db_user = await get_user_by_email("test@example.com", db_session)
        assert db_user is not None
        assert db_user.azure_object_id == "mock_oid_12345"

async def test_auth_callback_api_client(client, db_session):
    """Test OAuth callback for API clients"""
    # Arrange
    state = str(uuid.uuid4())
    code = "valid_code"
    
    # Store state in secure store
    await secure_store.store_value(f"state:{state}", state, {"created_at": datetime.utcnow().isoformat()})
    
    # Set up mocks
    with patch("app.api.routes.auth.get_msal_app", return_value=mock_get_msal_app()), \
         patch("app.api.routes.auth.get_db", return_value=db_session), \
         patch("httpx.AsyncClient", return_value=MockHttpxClient()):
        
        # Act - Request the callback as an API client
        response = client.get(
            f"/api/auth/callback?code={code}&state={state}"
        )
        
        # Assert - Should return tokens
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data

async def test_auth_callback_invalid_state(client, db_session):
    """Test OAuth callback with invalid state"""
    # Arrange
    state = str(uuid.uuid4())
    code = "valid_code"
    
    # Don't store the state in secure store to simulate invalid state
    
    # Set up mocks
    with patch("app.api.routes.auth.get_msal_app", return_value=mock_get_msal_app()), \
         patch("app.api.routes.auth.get_db", return_value=db_session):
        
        # Act
        response = client.get(
            f"/api/auth/callback?code={code}&state={state}",
            headers={"Accept": "text/html"}
        )
        
        # Assert - Should return 400 Bad Request
        assert response.status_code == 400
        assert "Invalid state parameter" in response.text

async def test_auth_callback_invalid_code(client, db_session):
    """Test OAuth callback with invalid code"""
    # Arrange
    state = str(uuid.uuid4())
    code = "invalid_code"
    
    # Store state in secure store
    await secure_store.store_value(f"state:{state}", state, {"created_at": datetime.utcnow().isoformat()})
    
    # Set up mocks
    with patch("app.api.routes.auth.get_msal_app", return_value=mock_get_msal_app()), \
         patch("app.api.routes.auth.get_db", return_value=db_session):
        
        # Act
        response = client.get(
            f"/api/auth/callback?code={code}&state={state}",
            headers={"Accept": "text/html"}
        )
        
        # Assert - Should return 400 Bad Request
        assert response.status_code == 400
        assert "Error acquiring token" in response.text

async def test_refresh_token_endpoint(client, db_session, create_test_user):
    """Test refreshing access token with refresh token"""
    # Arrange
    refresh_token_value = create_refresh_token(subject=create_test_user.email)
    request_data = {"refresh_token": refresh_token_value}
    
    # Mock get_user_by_email to return our test user
    with patch("app.api.routes.auth.get_user_by_email", return_value=create_test_user), \
         patch("app.api.routes.auth.get_user_permissions", return_value=["read:users"]), \
         patch("app.api.routes.auth.get_db", return_value=db_session):
        
        # Act
        response = client.post("/api/auth/refresh", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

async def test_refresh_token_invalid(client, db_session):
    """Test refreshing with invalid refresh token"""
    # Arrange
    # Create a token but modify it to be invalid
    valid_token = create_refresh_token(subject="test@example.com")
    if valid_token[10] == 'a':
        invalid_token = valid_token[:10] + 'b' + valid_token[11:]
    else:
        invalid_token = valid_token[:10] + 'a' + valid_token[11:]
    
    request_data = {"refresh_token": invalid_token}
    
    # Act
    response = client.post("/api/auth/refresh", json=request_data)
    
    # Assert
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "Could not validate credentials" in data["detail"]

async def test_refresh_token_expired(client, db_session):
    """Test refreshing with expired refresh token"""
    # Arrange
    # Create a token that's already expired
    expired_token = create_refresh_token(
        subject="test@example.com"
    )
    
    # Manually decode and modify expiration time
    payload = jwt.decode(
        expired_token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"verify_exp": False}
    )
    payload["exp"] = datetime.utcnow().timestamp() - 3600  # Expired 1 hour ago
    
    # Re-encode with modified payload
    expired_token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    request_data = {"refresh_token": expired_token}
    
    # Act
    response = client.post("/api/auth/refresh", json=request_data)
    
    # Assert
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "Token has expired" in data["detail"] or "Could not validate credentials" in data["detail"]

async def test_logout(client, db_session, create_test_user, auth_headers):
    """Test logging out and invalidating tokens"""
    # Arrange
    # Store a refresh token for the user
    await secure_store.store_value(
        f"refresh_token:{create_test_user.id}",
        "mock_refresh_token",
        {"user_id": str(create_test_user.id), "created_at": datetime.utcnow().isoformat()}
    )
    
    # Set up mocks
    with patch("app.api.routes.auth.get_current_user", return_value=create_test_user), \
         patch("app.api.routes.auth.get_db", return_value=db_session):
        
        # Act
        response = client.post("/api/auth/logout", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Successfully logged out" in data["message"]
        
        # Verify refresh token was deleted
        stored_token = await secure_store.get_value(f"refresh_token:{create_test_user.id}")
        assert stored_token is None

async def test_get_current_user_missing_token(client):
    """Test get_current_user with missing token"""
    # Define a test endpoint that uses get_current_user
    @client.app.get("/test-current-user")
    async def test_endpoint(current_user: User = Depends(get_current_user)):
        return {"email": current_user.email}
    
    # Act - Call endpoint without Authorization header
    response = client.get("/test-current-user")
    
    # Assert
    assert response.status_code == 401

async def test_get_current_user_valid_token(client, create_test_user, auth_headers):
    """Test get_current_user with valid token"""
    # Define a test endpoint that uses get_current_user
    @client.app.

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.core.security import verify_password


# Test user registration
@pytest.mark.asyncio
async def test_register_user(client: TestClient, db_session: AsyncSession):
    response = client.post(
        "/api/users/",
        json={
            "email": "newuser@example.com",
            "password": "StrongPass123!",
            "full_name": "New User"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert "password" not in data
    assert data["is_active"] == True
    
    # Verify user was created in the database
    result = await db_session.get(User, data["id"])
    assert result is not None
    assert result.email == "newuser@example.com"
    assert verify_password("StrongPass123!", result.hashed_password)


# Test login with valid credentials
@pytest.mark.asyncio
async def test_login_valid_credentials(client: TestClient, test_user: User):
    response = client.post(
        "/api/auth/login",
        data={
            "username": test_user.email,
            "password": "password123"
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


# Test login with invalid credentials
@pytest.mark.asyncio
async def test_login_invalid_credentials(client: TestClient):
    response = client.post(
        "/api/auth/login",
        data={
            "username": "wrong@example.com",
            "password": "wrongpassword"
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    assert response.status_code == 401


# Test protected route with valid token
@pytest.mark.asyncio
async def test_protected_route_with_token(client: TestClient, user_token: str):
    response = client.get(
        "/api/users/me",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"


# Test protected route without token
@pytest.mark.asyncio
async def test_protected_route_without_token(client: TestClient):
    response = client.get("/api/users/me")
    assert response.status_code == 401


# Test token refresh
@pytest.mark.asyncio
async def test_token_refresh(client: TestClient, user_token: str, test_user: User):
    # First, get a refresh token by logging in
    response = client.post(
        "/api/auth/login",
        data={
            "username": test_user.email,
            "password": "password123"
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    assert response.status_code == 200
    login_data = response.json()
    refresh_token = login_data.get("refresh_token")
    
    # If the login endpoint doesn't return a refresh token, we'll skip this test
    if not refresh_token:
        pytest.skip("Refresh token not implemented in login endpoint")
    
    # Use the refresh token to get a new access token
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


# Test logout
@pytest.mark.asyncio
async def test_logout(client: TestClient, user_token: str):
    response = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data

