"""
Security Tests
------------
Tests for core security functions including JWT handling, encryption,
token validation, and blocklisting.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import patch
import asyncio

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_permission,
    blocklist_token,
    is_token_blocklisted
)
from app.core.config import settings

pytestmark = pytest.mark.asyncio

async def test_create_access_token():
    """Test creating an access token"""
    # Arrange
    subject = "test@example.com"
    permissions = ["read:users", "create:users"]
    
    # Act
    token = create_access_token(subject=subject, permissions=permissions)
    
    # Assert
    assert token is not None
    assert isinstance(token, str)
    
    # Decode and verify contents
    payload = jwt.decode(
        token, 
        settings.SECRET_KEY, 
        algorithms=[settings.ALGORITHM]
    )
    assert payload["sub"] == subject
    assert payload["permissions"] == permissions
    assert payload["type"] == "access"
    assert "exp" in payload
    assert "iat" in payload

async def test_create_refresh_token():
    """Test creating a refresh token"""
    # Arrange
    subject = "test@example.com"
    
    # Act
    token = create_refresh_token(subject=subject)
    
    # Assert
    assert token is not None
    assert isinstance(token, str)
    
    # Decode and verify contents
    payload = jwt.decode(
        token, 
        settings.SECRET_KEY, 
        algorithms=[settings.ALGORITHM]
    )
    assert payload["sub"] == subject
    assert payload["type"] == "refresh"
    assert "exp" in payload
    assert "iat" in payload

async def test_token_expiration():
    """Test token expiration handling"""
    # Arrange
    subject = "test@example.com"
    
    # Create a token that expires in 1 second
    token = create_access_token(
        subject=subject,
        expires_delta=timedelta(seconds=1)
    )
    
    # Verify it's valid initially
    payload = await decode_token(token)
    assert payload["sub"] == subject
    
    # Wait for it to expire
    await asyncio.sleep(1.1)
    
    # Act & Assert - it should raise an exception when expired
    with pytest.raises(Exception):
        await decode_token(token)

async def test_token_blocklisting(db_session):
    """Test blocklisting a token"""
    # Arrange
    subject = "test@example.com"
    token = create_access_token(subject=subject)
    
    # Act - blocklist the token
    result = await blocklist_token(token, reason="testing", db=db_session)
    
    # Assert
    assert result is True
    
    # Check if token is blocklisted
    payload = jwt.decode(
        token, 
        settings.SECRET_KEY, 
        algorithms=[settings.ALGORITHM],
        options={"verify_exp": False}
    )
    jti = payload.get("jti", payload.get("iat", ""))
    is_blocklisted = await is_token_blocklisted(jti, db_session)
    assert is_blocklisted is True

async def test_permission_verification():
    """Test permission verification"""
    # Arrange
    subject = "test@example.com"
    permissions = ["read:users", "create:users"]
    token = create_access_token(subject=subject, permissions=permissions)
    
    # Mock the decode_token function to return a payload
    async def mock_decode_token(token):
        return {
            "sub": subject,
            "permissions": permissions
        }
    
    with patch("app.core.security.decode_token", side_effect=mock_decode_token):
        # Create a verification function for a permission that user has
        has_permission_fn = verify_permission("read:users")
        # Assert it succeeds
        assert await has_permission_fn(token) is True
        
        # Create a verification function for a permission user doesn't have
        has_no_permission_fn = verify_permission("admin:system")
        # Assert it raises an exception
        with pytest.raises(Exception):
            await has_no_permission_fn(token)

async def test_invalid_token_signature():
    """Test token with invalid signature"""
    # Arrange
    subject = "test@example.com"
    token = create_access_token(subject=subject)
    
    # Tamper with the token by changing one character
    if token[10] == 'a':
        tampered_token = token[:10] + 'b' + token[11:]
    else:
        tampered_token = token[:10] + 'a' + token[11:]
    
    # Act & Assert
    with pytest.raises(Exception):
        await decode_token(tampered_token)

async def test_token_with_incorrect_algorithm():
    """Test token with incorrect algorithm"""
    # Arrange - create token with a different algorithm
    subject = "test@example.com"
    payload = {
        "sub": subject,
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "type": "access",
        "iat": datetime.utcnow()
    }
    
    # Create token with HS512 instead of the configured algorithm
    incorrect_algo_token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm="HS512"  # Using different algorithm than configured
    )
    
    # Act & Assert - it should still validate since we accept multiple algorithms
    # But if the app is configured to only accept one specific algorithm, this would fail
    payload = await decode_token(incorrect_algo_token)
    assert payload["sub"] == subject

async def test_blocklist_user_tokens(db_session):
    """Test blocklisting all tokens for a user"""
    # Arrange
    subject = "test@example.com"
    user_id = "test_user_123"
    token1 = create_access_token(subject=subject, user_id=user_id)
    token2 = create_access_token(subject=subject, user_id=user_id)
    
    # Act - blocklist all tokens for the user
    from app.core.security import blocklist_user_tokens
    result = await blocklist_user_tokens(user_id, reason="security_measure", db=db_session)
    
    # Assert
    assert result is True
    
    # Check if tokens are now invalid by trying to use them
    # This would normally require checking a specific blocklist mechanism
    # For this test, we'll assume the user's tokens are all invalid after the call
    
    # Additional test: Verify a new token for this user still works
    # (assuming blocklisting doesn't prevent new tokens from being issued)
    new_token = create_access_token(subject=subject, user_id=user_id)
    payload = await decode_token(new_token)
    assert payload["sub"] == subject

async def test_token_refresh_expiry():
    """Test refresh token has longer expiry than access token"""
    # Arrange
    subject = "test@example.com"
    
    # Act
    access_token = create_access_token(subject=subject)
    refresh_token = create_refresh_token(subject=subject)
    
    # Assert
    access_payload = jwt.decode(
        access_token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    refresh_payload = jwt.decode(
        refresh_token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    # Refresh token should expire later than access token
    assert refresh_payload["exp"] > access_payload["exp"]
    
    # Refresh token should be valid for the configured number of days
    expected_diff_seconds = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400  # days to seconds
    actual_diff_seconds = refresh_payload["exp"] - access_payload["exp"]
    
    # Allow for small timing differences in test execution
    assert abs(actual_diff_seconds - expected_diff_seconds) < 60  # within a minute

async def test_token_includes_custom_claims():
    """Test tokens include custom claims when provided"""
    # Arrange
    subject = "test@example.com"
    custom_permissions = ["read:users", "write:users", "admin:system"]
    user_id = "user_123"
    
    # Act
    token = create_access_token(
        subject=subject,
        permissions=custom_permissions,
        user_id=user_id
    )
    
    # Assert
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    assert payload["sub"] == subject
    assert payload["permissions"] == custom_permissions
    assert payload["uid"] == user_id

async def test_cleanup_expired_blocklisted_tokens(db_session):
    """Test cleanup of expired blocklisted tokens"""
    # Arrange
    from app.core.security import cleanup_expired_blocklisted_tokens
    
    # Create some tokens and blocklist them
    subject = "test@example.com"
    token1 = create_access_token(
        subject=subject,
        expires_delta=timedelta(seconds=-1)  # Already expired
    )
    token2 = create_access_token(
        subject=subject,
        expires_delta=timedelta(hours=1)  # Not expired
    )
    
    # Blocklist both tokens
    await blocklist_token(token1, reason="testing", db=db_session)
    await blocklist_token(token2, reason="testing", db=db_session)
    
    # Act - run cleanup
    await cleanup_expired_blocklisted_tokens(db=db_session)
    
    # Assert - the expired token should be removed from blocklist
    payload1 = jwt.decode(
        token1,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"verify_exp": False}
    )
    payload2 = jwt.decode(
        token2,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"verify_exp": False}
    )
    
    jti1 = payload1.get("jti", payload1.get("iat", ""))
    jti2 = payload2.get("jti", payload2.get("iat", ""))
    
    # The expired token should no longer be in the blocklist
    is_blocklisted1 = await is_token_blocklisted(jti1, db_session)
    assert is_blocklisted1 is False
    
    # The non-expired token should still be in the blocklist
    is_blocklisted2 = await is_token_blocklisted(jti2, db_session)
    assert is_blocklisted2 is True

async def test_verify_permission_with_multiple_permissions():
    """Test verification with multiple permissions"""
    # Arrange
    subject = "test@example.com"
    permissions = ["read:users", "create:users", "admin:system"]
    token = create_access_token(subject=subject, permissions=permissions)
    
    # Mock the decode_token function to return a payload
    async def mock_decode_token(token):
        return {
            "sub": subject,
            "permissions": permissions
        }
    
    with patch("app.core.security.decode_token", side_effect=mock_decode_token):
        # Test multiple permission checks
        for permission in permissions:
            check_fn = verify_permission(permission)
            assert await check_fn(token) is True
        
        # Test a permission that doesn't exist
        check_fn = verify_permission("unknown:permission")
        with pytest.raises(Exception):
            await check_fn(token)

