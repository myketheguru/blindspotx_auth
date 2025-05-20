import json
import logging
import time
import uuid
import asyncio
import os
import base64
import hashlib
import secrets
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable, Set, Union, Tuple, Literal
from uuid import UUID

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError, BaseModel
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel, select, delete
import redis.asyncio as redis

from app.core.config import settings
from app.core.database import get_db, secure_store
from app.models.user import User, get_user_by_email
from app.schemas.token import TokenPayload

# Try to import prometheus client for metrics if available
try:
    from prometheus_client import Counter, Histogram, Gauge
    METRICS_ENABLED = True
except ImportError:
    METRICS_ENABLED = False

# Enhanced logger for security events
logger = logging.getLogger(__name__)

# OAuth2 scheme for token validation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"/api/auth/login")

# Configure metrics if available
if METRICS_ENABLED:
    # Authentication metrics
    AUTH_REQUESTS = Counter(
        'auth_requests_total', 
        'Total number of authentication requests',
        ['method', 'endpoint', 'status']
    )
    TOKEN_OPERATIONS = Counter(
        'token_operations_total',
        'Total number of token operations',
        ['operation', 'token_type', 'status']
    )
    AUTH_REQUEST_DURATION = Histogram(
        'auth_request_duration_seconds',
        'Authentication request duration in seconds',
        ['endpoint']
    )
    ACTIVE_SESSIONS = Gauge(
        'active_sessions',
        'Number of active user sessions'
    )
    BLOCKED_IPS = Gauge(
        'blocked_ips',
        'Number of currently blocked IPs'
    )
    
# Redis connection for distributed session management
redis_client = None

# In-memory fallback for session management when Redis is unavailable
class InMemorySessionStore:
    def __init__(self):
        self.sessions = {}
        self.session_tokens = defaultdict(set)
        
    async def add_session(self, session_id: str, user_id: str, data: dict, expires_at: int):
        self.sessions[session_id] = {
            "user_id": user_id,
            "data": data,
            "expires_at": expires_at
        }
        self.session_tokens[user_id].add(session_id)
        
    async def get_session(self, session_id: str) -> Optional[dict]:
        session = self.sessions.get(session_id)
        if session and session["expires_at"] > time.time():
            return session
        elif session:
            # Expired session, remove it
            await self.remove_session(session_id)
        return None
        
    async def remove_session(self, session_id: str):
        if session_id in self.sessions:
            user_id = self.sessions[session_id]["user_id"]
            del self.sessions[session_id]
            if user_id in self.session_tokens:
                self.session_tokens[user_id].discard(session_id)
                
    async def get_user_sessions(self, user_id: str) -> List[str]:
        return list(self.session_tokens.get(user_id, set()))
        
    async def remove_user_sessions(self, user_id: str) -> int:
        session_ids = self.session_tokens.get(user_id, set()).copy()
        for session_id in session_ids:
            await self.remove_session(session_id)
        return len(session_ids)
        
    async def cleanup_expired_sessions(self):
        now = time.time()
        to_remove = []
        for session_id, session in self.sessions.items():
            if session["expires_at"] < now:
                to_remove.append(session_id)
                
        for session_id in to_remove:
            await self.remove_session(session_id)
            
        return len(to_remove)

# Initialize in-memory session store
in_memory_session_store = InMemorySessionStore()

# Permission cache with TTL
class PermissionCache:
    def __init__(self, ttl_seconds: int = 300):  # Default 5 minute TTL
        self.cache = {}
        self.ttl = ttl_seconds
        
    def get(self, key: str) -> Optional[List[str]]:
        if key in self.cache:
            timestamp, permissions = self.cache[key]
            if time.time() < timestamp + self.ttl:
                return permissions
            else:
                # Remove expired entry
                del self.cache[key]
        return None
        
    def set(self, key: str, permissions: List[str]):
        self.cache[key] = (time.time(), permissions)
        
    def invalidate(self, key: str):
        if key in self.cache:
            del self.cache[key]
            
    def clear(self):
        self.cache.clear()

# Initialize permission cache
permission_cache = PermissionCache()

async def initialize_redis():
    """Initialize Redis connection for session management if configured"""
    global redis_client
    if settings.REDIS_URL:
        try:
            redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
            await redis_client.ping()
            logger.info("Redis connection established successfully")
            return True
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {str(e)}. Falling back to in-memory session store.")
            redis_client = None
            return False
    return False

# JWT Key management
class JWTKeyManager:
    """
    Manages JWT signing keys with rotation capability
    """
    def __init__(self, 
                 primary_key: str = None, 
                 backup_keys: List[str] = None,
                 key_id: str = None,
                 algorithm: str = "HS256"):
        """
        Initialize the JWT key manager
        
        Args:
            primary_key: The primary signing key (falls back to settings.SECRET_KEY)
            backup_keys: List of backup keys that can still verify tokens
            key_id: Identifier for the current primary key
            algorithm: The JWT algorithm to use
        """
        self.primary_key = primary_key or settings.SECRET_KEY
        self.backup_keys = backup_keys or []
        self.key_id = key_id or self._generate_key_id(self.primary_key)
        self.algorithm = algorithm or settings.ALGORITHM
        self.all_keys = {self.key_id: self.primary_key}
        
        # Add backup keys to the dictionary
        for i, key in enumerate(self.backup_keys):
            key_id = f"bk{i+1}"
            self.all_keys[key_id] = key
            
    def _generate_key_id(self, key: str) -> str:
        """Generate a deterministic key ID based on key content"""
        hash_obj = hashlib.sha256(key.encode())
        return f"k{hash_obj.hexdigest()[:8]}"
        
    def generate_new_key(self, key_length: int = 64) -> Tuple[str, str]:
        """Generate a new random signing key"""
        # Generate a secure random key
        random_bytes = secrets.token_bytes(key_length)
        new_key = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
        new_key_id = self._generate_key_id(new_key)
        return new_key, new_key_id
        
    def rotate_keys(self, new_key: str = None, max_backup_keys: int = 2):
        """
        Rotate JWT keys - current primary becomes backup, new key becomes primary
        
        Args:
            new_key: New key to use as primary (generates one if not provided)
            max_backup_keys: Maximum number of backup keys to keep
        """
        # If no new key provided, generate one
        if not new_key:
            new_key, new_key_id = self.generate_new_key()
        else:
            new_key_id = self._generate_key_id(new_key)
            
        # Current primary becomes backup
        self.backup_keys.insert(0, self.primary_key)
        
        # Trim backup keys if needed
        if len(self.backup_keys) > max_backup_keys:
            self.backup_keys = self.backup_keys[:max_backup_keys]
            
        # Set new primary key
        self.primary_key = new_key
        self.key_id = new_key_id
        
        # Update all_keys dictionary
        self.all_keys = {self.key_id: self.primary_key}
        for i, key in enumerate(self.backup_keys):
            key_id = f"bk{i+1}"
            self.all_keys[key_id] = key
            
        logger.info(f"JWT keys rotated. New key ID: {self.key_id}")
        return new_key_id
        
    def encode_token(self, payload: dict) -> str:
        """
        Encode a JWT token with the primary key
        
        Args:
            payload: Token payload to encode
            
        Returns:
            str: Encoded JWT token
        """
        # Add key ID to the header
        headers = {"kid": self.key_id}
        return jwt.encode(
            payload, 
            self.primary_key, 
            algorithm=self.algorithm,
            headers=headers
        )
        
    def decode_token(self, token: str, verify: bool = True) -> dict:
        """
        Decode a JWT token using appropriate key
        
        Args:
            token: JWT token to decode
            verify: Whether to verify the token signature
            
        Returns:
            dict: Decoded token payload
        """
        if not verify:
            return jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False}
            )
            
        # First try to get the key ID from the token header
        try:
            header = jwt.get_unverified_header(token)
            key_id = header.get("kid")
            
            # If we have this key ID, use the corresponding key
            if key_id and key_id in self.all_keys:
                return jwt.decode(
                    token,
                    self.all_keys[key_id],
                    algorithms=[self.algorithm]
                )
        except Exception:
            # If header parsing fails, continue with normal decoding attempts
            pass
            
        # If no key ID or unknown key ID, try all keys
        # Start with primary key
        exceptions = []
        try:
            return jwt.decode(
                token,
                self.primary_key,
                algorithms=[self.algorithm]
            )
        except Exception as e:
            exceptions.append(str(e))
            
        # Try backup keys
        for key in self.backup_keys:
            try:
                return jwt.decode(
                    token,
                    key,
                    algorithms=[self.algorithm]
                )
            except Exception as e:
                exceptions.append(str(e))
                
        # If all keys fail, raise the last exception
        raise jwt.InvalidTokenError(f"Could not validate token with any keys: {'; '.join(exceptions)}")

# Initialize the JWT key manager with the current secret key
jwt_manager = JWTKeyManager(primary_key=settings.SECRET_KEY, algorithm=settings.ALGORITHM)

async def create_access_token(
    subject: Union[str, Any],
    user_id: Union[str, UUID],
    permissions: List[str] = None,
    expires_delta: Optional[timedelta] = None,
    additional_claims: dict = None,
) -> str:
    """
    Create a JWT access token
    
    Args:
        subject: Token subject (typically user email)
        user_id: User ID for the token
        permissions: List of user permissions to include
        expires_delta: Optional custom expiration time
        additional_claims: Any additional claims to include
        
    Returns:
        str: Encoded JWT access token
    """
    if METRICS_ENABLED:
        TOKEN_OPERATIONS.labels(operation="create", token_type="access", status="success").inc()
        
    # Calculate expiration time
    expires_delta = expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    
    # Base token data
    to_encode = {
        "sub": str(subject),
        "uid": str(user_id),
        "exp": int(expire.timestamp()),  # Convert to integer timestamp
        "iat": int(datetime.utcnow().timestamp()),  # Convert to integer timestamp
        "type": "access",
        "jti": str(uuid.uuid4()),  # Unique token ID
    }
    
    # Add permissions if provided
    if permissions:
        to_encode["permissions"] = permissions
        
    # Add any additional claims
    if additional_claims:
        to_encode.update(additional_claims)
    
    # Log token creation with minimal data (avoid logging sensitive info)
    logger.info(f"Access token created for user {user_id} with JTI {to_encode['jti'][:8]}...")
    
    # Use the JWT manager to encode the token
    return jwt_manager.encode_token(to_encode)

async def create_refresh_token(
    subject: Union[str, Any],
    user_id: Union[str, UUID],
    access_token_jti: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a JWT refresh token
    
    Args:
        subject: Token subject (typically user email)
        user_id: User ID for the token
        access_token_jti: JTI of the related access token (for token binding)
        expires_delta: Optional custom expiration time
        
    Returns:
        str: Encoded JWT refresh token
    """
    if METRICS_ENABLED:
        TOKEN_OPERATIONS.labels(operation="create", token_type="refresh", status="success").inc()
        
    # Calculate expiration time - refresh tokens last longer
    expires_delta = expires_delta or timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    
    # Base token data
    to_encode = {
        "sub": str(subject),
        "uid": str(user_id),
        "exp": int(expire.timestamp()),  # Convert to integer timestamp
        "iat": int(datetime.utcnow().timestamp()),  # Convert to integer timestamp
        "type": "refresh",
        "jti": str(uuid.uuid4())
    }
    
    # Add access token JTI if provided (for token binding)
    if access_token_jti:
        to_encode["access_jti"] = access_token_jti
    
    # Log token creation with minimal data
    logger.info(f"Refresh token created for user {user_id} with JTI {to_encode['jti'][:8]}...")
    
    # Use the JWT manager to encode the token
    return jwt_manager.encode_token(to_encode)

# Token blocklist model
class BlocklistedToken(SQLModel, table=True):
    """Model for storing blocklisted tokens"""
    id: Optional[UUID] = Field(default_factory=uuid.uuid4, primary_key=True)
    jti: str = Field(index=True)  # Token ID
    token_type: str  # "access" or "refresh"
    user_id: Optional[str] = Field(default=None, index=True)  # User ID associated with token
    expires_at: datetime
    reason: str = "logout"  # Reason for blocklisting
    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    
# Session schema for Redis/in-memory storage
class SessionData(BaseModel):
    """Schema for session data"""
    user_id: str
    session_id: str
    token_jti: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    expires_at: int  # Unix timestamp
    last_activity: int  # Unix timestamp
    data: Dict[str, Any] = {}

# Rate limiter middleware
class RateLimiter(BaseHTTPMiddleware):
    """
    Rate limiting middleware to protect against brute force attacks
    
    This implementation uses a sliding window algorithm with in-memory storage
    For production, consider using Redis or another distributed cache
    """
    
    def __init__(
        self, 
        app: ASGIApp, 
        window_size: int = 60,  # Window size in seconds
        max_requests: int = 100,  # Max requests per window per IP
        login_window_size: int = 60,  # Smaller window for login attempts
        login_max_requests: int = 5,  # Fewer login attempts allowed
        whitelist: Set[str] = None,  # IPs to exempt from rate limiting
    ):
        """Initialize the rate limiter middleware"""
        super().__init__(app)
        self.window_size = window_size
        self.max_requests = max_requests
        self.login_window_size = login_window_size
        self.login_max_requests = login_max_requests
        self.whitelist = whitelist or set()
        
        # Store request timestamps per client
        self.request_records = defaultdict(deque)
        # Store login attempt timestamps per client
        self.login_records = defaultdict(deque)
        # Track blocked IPs with unblock time
        self.blocked_ips = {}
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_task())
    
    async def _cleanup_task(self):
        """Periodically clean up old request records"""
        while True:
            try:
                now = time.time()
                # Clean up request records
                for ip, timestamps in list(self.request_records.items()):
                    while timestamps and now - timestamps[0] > self.window_size:
                        timestamps.popleft()
                    if not timestamps:
                        del self.request_records[ip]
                
                # Clean up login records
                for ip, timestamps in list(self.login_records.items()):
                    while timestamps and now - timestamps[0] > self.login_window_size:
                        timestamps.popleft()
                    if not timestamps:
                        del self.login_records[ip]
                
                # Clean up blocked IPs
                for ip in list(self.blocked_ips.keys()):
                    if now > self.blocked_ips[ip]:
                        del self.blocked_ips[ip]
                        logger.info(f"IP {ip} unblocked after timeout")
            except Exception as e:
                logger.error(f"Error in rate limiter cleanup: {str(e)}")
            
            # Run cleanup every 10 seconds
            await asyncio.sleep(10)
    
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """
        Process requests through the rate limiter
        
        Args:
            request: The FastAPI request
            call_next: The next middleware or endpoint
            
        Returns:
            Response: The HTTP response
        """
        # Get client IP - in production, use X-Forwarded-For with proper validation
        client_ip = request.client.host if request.client else "unknown"
        
        # Skip rate limiting for whitelisted IPs
        if client_ip in self.whitelist:
            return await call_next(request)
        
        # Check if IP is currently blocked
        if client_ip in self.blocked_ips:
            if time.time() < self.blocked_ips[client_ip]:
                retry_after = int(self.blocked_ips[client_ip] - time.time())
                logger.warning(f"Blocked request from rate-limited IP: {client_ip}")
                return Response(
                    content=json.dumps({
                        "detail": "Too many requests. Please try again later."
                    }),
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(retry_after)},
                    media_type="application/json"
                )
        
        # Track request based on path
        path = request.url.path.lower()
        now = time.time()
        
        # Apply stricter limits for login attempts
        if "/auth/login" in path or "/auth/token" in path:
            records = self.login_records[client_ip]
            records.append(now)
            
            # If too many login attempts, block IP temporarily
            if len(records) > self.login_max_requests:
                # Block for 15 minutes (900 seconds)
                block_duration = 900
                self.blocked_ips[client_ip] = now + block_duration
                logger.warning(f"IP {client_ip} blocked for {block_duration}s due to login rate limit exceeded")
                
                return Response(
                    content=json.dumps({
                        "detail": "Too many login attempts. Please try again later."
                    }),
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(block_duration)},
                    media_type="application/json"
                )
        
        # Standard rate limiting for all requests
        records = self.request_records[client_ip]
        records.append(now)
        
        # If too many requests, respond with 429
        if len(records) > self.max_requests:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return Response(
                content=json.dumps({
                    "detail": "Rate limit exceeded. Please try again later."
                }),
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(self.window_size)},
                media_type="application/json"
            )
        
        # Process the request normally
        return await call_next(request)

# Token management functions
async def blocklist_token(
    token: str,
    reason: str = "logout",
    db: AsyncSession = None
) -> bool:
    """
    Add a token to the blocklist
    
    Args:
        token: The JWT token to blocklist
        reason: Reason for blocklisting (e.g., "logout", "security_incident")
        db: Database session
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Determine if we need to close the DB session when done
        close_db = False
        if db is None:
            close_db = True
            db = next(get_db())
        
        # Decode token without verification to extract claims
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False}
            )
        except Exception as e:
            logger.error(f"Failed to decode token for blocklisting: {str(e)}")
            return False
        
        # Extract token ID (JTI) or use IAT as fallback
        jti = payload.get("jti", str(payload.get("iat", int(time.time()))))
        user_id = payload.get("uid")
        token_type = payload.get("type", "access")
        exp = payload.get("exp", int(time.time()) + 3600)  # Default 1 hour if no exp
        
        # Create blocklist entry
        blocklisted = BlocklistedToken(
            jti=jti,
            token_type=token_type,
            user_id=user_id,
            expires_at=datetime.fromtimestamp(exp),
            reason=reason
        )
        db.add(blocklisted)
        await db.commit()
        
        logger.info(f"Token {jti[:8]}... blocklisted (Type: {token_type}, Reason: {reason})")
        
        if close_db:
            await db.close()
            
        return True
    except Exception as e:
        logger.error(f"Error blocklisting token: {str(e)}")
        return False

async def is_token_blocklisted(jti: str, db: AsyncSession) -> bool:
    """
    Check if a token is blocklisted by its JTI
    
    Args:
        jti: The JWT token ID
        db: Database session
        
    Returns:
        bool: True if token is blocklisted, False otherwise
    """
    try:
        result = await db.execute(
            select(BlocklistedToken).where(BlocklistedToken.jti == jti)
        )
        return result.first() is not None
    except Exception as e:
        logger.error(f"Error checking token blocklist: {str(e)}")
        # In case of error, assume token is not blocklisted
        # This is safer than blocking legitimate requests
        return False

async def blocklist_user_tokens(user_id: Union[str, UUID], reason: str = "security_measure", db: AsyncSession = None) -> bool:
    """
    Blocklist all tokens for a specific user
    
    Args:
        user_id: User ID whose tokens should be invalidated
        reason: Reason for blocklisting
        db: Database session
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Determine if we need to close the DB session when done
        close_db = False
        if db is None:
            close_db = True
            db = next(get_db())
        
        # Create special blocklist entry with "all" type
        all_tokens_jti = f"all_tokens_{user_id}_{int(time.time())}"
        expires_at = datetime.utcnow() + timedelta(days=365)  # 1 year expiry
        
        blocklisted = BlocklistedToken(
            jti=all_tokens_jti,
            token_type="all",
            user_id=str(user_id),
            expires_at=expires_at,
            reason=reason
        )
        db.add(blocklisted)
        await db.commit()
        
        logger.warning(f"All tokens blocklisted for user {user_id} (Reason: {reason})")
        
        if close_db:
            await db.close()
            
        return True
    except Exception as e:
        logger.error(f"Error blocklisting user tokens: {str(e)}")
        return False

async def cleanup_expired_blocklisted_tokens(db: AsyncSession = None):
    """
    Delete expired blocklisted tokens
    
    Args:
        db: Database session
    """
    try:
        # Determine if we need to close the DB session when done
        close_db = False
        if db is None:
            close_db = True
            db = next(get_db())
        
        # Delete expired tokens
        current_time = datetime.utcnow()
        stmt = delete(BlocklistedToken).where(
            BlocklistedToken.expires_at < current_time,
            BlocklistedToken.token_type != "all"
        )
        
        # Execute the delete statement
        result = await db.execute(stmt)
        await db.commit()
        
        # Log the operation
        deleted_count = result.rowcount if hasattr(result, 'rowcount') else 0
        logger.info(f"Cleaned up {deleted_count} expired blocklisted tokens")
        
        if close_db:
            await db.close()
            
        return deleted_count
        
    except Exception as e:
        logger.error(f"Error cleaning up expired blocklisted tokens: {str(e)}")
        if db and close_db:
            await db.close()
        return 0

async def decode_token(token: str) -> Dict[str, Any]:
    """Decode and verify JWT token"""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        
        # Convert timestamps to integers if they're floats
        if isinstance(payload.get("exp"), float):
            payload["exp"] = int(payload["exp"])
        if isinstance(payload.get("iat"), float):
            payload["iat"] = int(payload["iat"])
            
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
    
    Note: Authorization header tokens should have "Bearer " prefix,
    but cookie tokens should not have the prefix.
    """
    try:
        # Try getting token from Authorization header first
        authorization: str = request.headers.get("Authorization")
        token_source = "header"
        
        if authorization and authorization.startswith("Bearer "):
            # Strip "Bearer " prefix from Authorization header tokens
            token = authorization.split(" ")[1]
            logger.debug("Using token from Authorization header")
        else:
            # Fallback to cookie - cookies have raw tokens without "Bearer " prefix
            token = request.cookies.get("access_token")
            token_source = "cookie"
            logger.debug(f"Using token from cookie: {token is not None}")

        if not token:
            logger.warning("Authentication failed: No valid token found in headers or cookies")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"}
            )

        try:
            payload = await decode_token(token)
        except jwt.ExpiredSignatureError:
            logger.warning(f"Expired token from {token_source}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token from {token_source}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception as e:
            logger.error(f"Unexpected error decoding token from {token_source}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication error",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if token is blocklisted
        jti = payload.get("jti")
        user_id = payload.get("uid")
        
        if jti:
            # Check if this specific token is blocklisted
            is_blocklisted = await is_token_blocklisted(jti, db)
            if is_blocklisted:
                logger.warning(f"Rejected blocklisted token with JTI {jti[:8]}...")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        if user_id:
            # Check if all tokens for this user are blocklisted
            result = await db.execute(
                select(BlocklistedToken).where(
                    BlocklistedToken.user_id == str(user_id),
                    BlocklistedToken.token_type == "all"
                )
            )
            user_blocklisted = result.first() is not None
            
            if user_blocklisted:
                logger.warning(f"Rejected token for blocklisted user {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User access has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        # Validate token payload
        email: str = payload.get("sub")
        if email is None:
            logger.error(f"Invalid token payload from {token_source}: missing 'sub' field")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Fetch user from DB
        user = await get_user_by_email(email, db)
        if not user:
            logger.warning(f"User not found for email: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if not user.is_active:
            logger.warning(f"Inactive user attempted to authenticate: {email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"}
            )

        return user
    except HTTPException:
        # Re-raise HTTP exceptions without modification
        raise
    except Exception as e:
        # Catch any other unexpected errors
        logger.error(f"Unexpected error in authentication: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication",
            headers={"WWW-Authenticate": "Bearer"}
        )


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