# Token Management

## Overview

BlindspotX implements a comprehensive token management system that handles JWT tokens, refresh tokens, and session management. This document details the token lifecycle, security measures, and implementation details.

## Token Types

### Access Tokens (JWT)
- **Format**: JSON Web Token (JWT)
- **Signing Algorithm**: RS256
- **Default Lifetime**: 15 minutes
- **Claims**:
  ```json
  {
    "sub": "user@example.com",
    "uid": "user-uuid",
    "exp": 1234567890,
    "iat": 1234567890,
    "type": "access",
    "permissions": ["read:users", "write:roles"],
    "jti": "unique-token-id"
  }
  ```

### Refresh Tokens
- **Format**: Opaque token
- **Storage**: Securely hashed in database
- **Default Lifetime**: 7 days
- **Properties**:
  - One-time use
  - Automatic rotation
  - Family-based tracking
  - Revocation capabilities

## Token Security Measures

### JWT Security
1. **Key Management**
   - Regular key rotation
   - Secure key storage
   - Multiple active keys support
   - Key versioning

2. **Token Validation**
   - Signature verification
   - Expiration checking
   - Permission validation
   - Blocklist checking

3. **Token Claims**
   - Minimal payload
   - Required claims enforcement
   - Permission inclusion
   - Unique token IDs (JTI)

### Session Management

1. **Token Storage**
   ```python
   class SessionData(BaseModel):
       user_id: str
       session_id: str
       token_jti: str
       ip_address: Optional[str]
       user_agent: Optional[str]
       expires_at: int
       last_activity: int
       data: Dict[str, Any]
   ```

2. **Storage Backends**
   - Redis (primary)
   - In-memory fallback
   - Database backup

## Token Lifecycle

### Access Token Flow
1. **Creation**
   ```python
   async def create_access_token(
       subject: str,
       user_id: UUID,
       permissions: List[str],
       expires_delta: Optional[timedelta] = None
   ) -> str
   ```

2. **Validation**
   ```python
   async def validate_token(token: str) -> Dict[str, Any]
   ```

3. **Revocation**
   ```python
   async def revoke_token(token: str, reason: str = "user_logout")
   ```

### Refresh Token Flow
1. **Issuance**
   ```python
   async def create_refresh_token(
       subject: str,
       user_id: UUID,
       access_token_jti: str
   ) -> str
   ```

2. **Usage**
   ```python
   async def refresh_access_token(refresh_token: str) -> Tuple[str, str]
   ```

3. **Rotation**
   ```python
   async def rotate_refresh_token(old_token: str) -> str
   ```

## Token Blocklist

### Implementation
- Uses database table for persistence
- Redis cache for fast lookups
- Automatic cleanup of expired entries

### Structure
```python
class BlocklistedToken(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    jti: str = Field(index=True)
    token_type: str
    user_id: Optional[str] = Field(index=True)
    expires_at: datetime
    reason: str = "logout"
    created_at: datetime = Field(default_factory=datetime.utcnow)
```

## Security Features

### Rate Limiting
- Token generation limits
- Refresh attempt limits
- IP-based restrictions
- User-based quotas

### Monitoring
- Failed validation tracking
- Refresh token usage monitoring
- Suspicious activity detection
- Automatic blocklisting

## Error Handling

### Common Scenarios
1. **Token Expired**
   ```python
   HTTPException(
       status_code=401,
       detail="Token has expired",
       headers={"WWW-Authenticate": "Bearer"}
   )
   ```

2. **Token Invalid**
   ```python
   HTTPException(
       status_code=401,
       detail="Could not validate credentials",
       headers={"WWW-Authenticate": "Bearer"}
   )
   ```

3. **Token Blocklisted**
   ```python
   HTTPException(
       status_code=401,
       detail="Token has been revoked",
       headers={"WWW-Authenticate": "Bearer"}
   )
   ```

## Best Practices

### Implementation Guidelines
1. Always verify token signatures
2. Use short-lived access tokens
3. Implement token rotation
4. Enable comprehensive logging
5. Use secure token storage

### Security Recommendations
1. Regular key rotation
2. Token encryption at rest
3. Secure transport (TLS)
4. Proper error handling
5. Audit trail maintenance

## Related Documentation
- [Security Overview](./overview.md)
- [Encryption Details](./encryption.md)
- [Audit Logging](./audit_logging.md)
- [Authentication Flow](../architecture/authentication_flow.md)

