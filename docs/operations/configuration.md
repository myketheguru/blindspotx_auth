# Configuration Guide

## Overview

This guide details all configuration options available in the BlindspotX Authentication System, including environment variables, application settings, and security configurations.

## Environment Variables

### Core Settings
```ini
# Application settings
PROJECT_NAME=BlindspotX
DEBUG=false
ENVIRONMENT=production  # development, staging, production
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Security settings
SECRET_KEY=your-super-secret-key-here
ALGORITHM=HS256  # JWT signing algorithm
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_MINUTES=1440  # 24 hours
```

### Authentication Configuration
```ini
# Microsoft Entra ID Settings
MS_CLIENT_ID=your-client-id
MS_CLIENT_SECRET=your-client-secret
MS_TENANT_ID=your-tenant-id
MS_REDIRECT_URI=http://localhost:8000/api/auth/callback

# Optional Azure Key Vault integration
USE_KEY_VAULT=false
KEY_VAULT_NAME=your-key-vault-name
```

### Database Configuration
```ini
# Database settings
DATABASE_URL=sqlite:///./blindspotx.db  # Development
# DATABASE_URL=postgresql://user:password@localhost/blindspotx  # Production

# Database pool settings
DB_POOL_SIZE=5
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT=30
```

### Security Settings
```ini
# CORS Configuration
CORS_ORIGINS=["http://localhost:3000", "http://localhost:8000"]
CORS_METHODS=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
CORS_HEADERS=["*"]

# Rate Limiting
RATE_LIMIT_ENABLED=true
MAX_REQUESTS_PER_MIN=100
LOGIN_MAX_ATTEMPTS=5
LOGIN_BLOCK_MINUTES=15
```

### Caching & Sessions
```ini
# Redis Configuration (optional)
REDIS_URL=redis://localhost:6379/0
REDIS_MAX_CONNECTIONS=10
REDIS_TIMEOUT=30

# Session Settings
SESSION_COOKIE_NAME=session
SESSION_EXPIRE_MINUTES=60
SECURE_COOKIES=true
```

## Application Configuration

### Logging Configuration
```python
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "json": {
            "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default"
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "app.log",
            "formatter": "json"
        }
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"]
    }
}
```

### Security Settings
```python
SECURITY_CONFIG = {
    "password_hashers": ["bcrypt"],
    "hash_rounds": 12,
    "token_algorithms": ["HS256", "RS256"],
    "minimum_key_length": 32,
    "session_token_bytes": 32
}
```

### Rate Limiting Configuration
```python
RATE_LIMIT_CONFIG = {
    "default": {
        "window_size": 60,  # seconds
        "max_requests": 100
    },
    "auth": {
        "window_size": 300,  # 5 minutes
        "max_requests": 5
    },
    "api": {
        "window_size": 60,
        "max_requests": 1000
    }
}
```

## Feature Configuration

### Drift Detection Settings
```ini
# Drift Detection Configuration
DRIFT_DETECTION_ENABLED=true
DRIFT_CHECK_INTERVAL=3600  # seconds
DRIFT_RETENTION_DAYS=30
DRIFT_ALERT_ENABLED=true
```

### RBAC Configuration
```python
RBAC_CONFIG = {
    "case_sensitive_permissions": True,
    "permission_delimiter": ":",
    "permission_cache_ttl": 300,  # seconds
    "role_cache_ttl": 300,  # seconds
    "superuser_role": "admin"
}
```

## Development Settings

### Debug Configuration
```ini
# Debug settings (development only)
DEBUG=true
DEBUG_TOOLBAR_ENABLED=true
SQL_ECHO=true
CORS_ORIGINS=["*"]
```

### Testing Configuration
```ini
# Test settings
TEST_DATABASE_URL=sqlite:///./test.db
TEST_EMAIL=test@example.com
TEST_PASSWORD=test_password
```

## Production Settings

### Performance Tuning
```ini
# Worker configuration
WORKERS=4
WORKER_CLASS=uvicorn.workers.UvicornWorker
KEEPALIVE=65

# Connection handling
BACKLOG=2048
TIMEOUT=30
```

### SSL/TLS Configuration
```ini
# SSL settings
SSL_KEYFILE=/path/to/keyfile
SSL_CERTFILE=/path/to/certfile
SSL_CA_CERTS=/path/to/ca_certs
SSL_VERIFY_MODE=CERT_REQUIRED
```

## Environment-Specific Configurations

### Development
```ini
DEBUG=true
LOG_LEVEL=DEBUG
DATABASE_URL=sqlite:///./dev.db
CORS_ORIGINS=["*"]
```

### Staging
```ini
DEBUG=false
LOG_LEVEL=INFO
DATABASE_URL=postgresql://user:password@localhost/blindspotx_staging
CORS_ORIGINS=["https://staging.example.com"]
```

### Production
```ini
DEBUG=false
LOG_LEVEL=WARNING
DATABASE_URL=postgresql://user:password@localhost/blindspotx_prod
CORS_ORIGINS=["https://example.com"]
USE_KEY_VAULT=true
```

## Configuration Management

### Best Practices
1. Never commit secrets to version control
2. Use environment variables for sensitive data
3. Maintain separate configs for different environments
4. Document all configuration changes
5. Validate configurations before deployment

### Configuration Validation
```python
# Example configuration validation
def validate_config():
    required_vars = [
        "SECRET_KEY",
        "MS_CLIENT_ID",
        "MS_CLIENT_SECRET",
        "DATABASE_URL"
    ]
    
    for var in required_vars:
        if not os.getenv(var):
            raise ValueError(f"Missing required environment variable: {var}")
```

## Related Documentation
- [Deployment Guide](./deployment.md)
- [Monitoring Guide](./monitoring.md)
- [Security Overview](../security/overview.md)

