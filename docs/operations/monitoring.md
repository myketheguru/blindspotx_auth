# Monitoring Guide

## Overview

This guide details the monitoring and observability features of the BlindspotX Authentication System, including metrics collection, logging, alerting, and health checks.

## Metrics Collection

### Core Metrics

1. **Authentication Metrics**
```python
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
```

2. **User Metrics**
```python
ACTIVE_SESSIONS = Gauge(
    'active_sessions',
    'Number of active user sessions'
)

USER_OPERATIONS = Counter(
    'user_operations_total',
    'Total number of user operations',
    ['operation', 'status']
)
```

3. **System Metrics**
```python
API_REQUEST_DURATION = Histogram(
    'api_request_duration_seconds',
    'API request duration in seconds',
    ['endpoint', 'method', 'status_code']
)

DRIFT_DETECTIONS = Counter(
    'drift_detections_total',
    'Total number of drift detections',
    ['severity', 'status']
)
```

## Health Checks

### Endpoint Implementation
```python
@app.get("/api/health")
async def health_check():
    components = {
        "database": await check_db_health(),
        "redis": await check_redis_health(),
        "oauth": await check_oauth_health(),
        "drift_detection": await check_drift_health()
    }
    
    status = all(c["healthy"] for c in components.values())
    return {
        "status": "healthy" if status else "unhealthy",
        "components": components,
        "timestamp": datetime.utcnow().isoformat()
    }
```

### Component Health Checks

1. **Database Health**
```python
async def check_db_health():
    try:
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
        return {"healthy": True}
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }
```

2. **Redis Health**
```python
async def check_redis_health():
    try:
        await redis_client.ping()
        return {"healthy": True}
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }
```

## Logging System

### Log Levels
- DEBUG: Detailed information for debugging
- INFO: General operational information
- WARNING: Minor issues that need attention
- ERROR: Serious problems that need immediate attention
- CRITICAL: System-wide failures

### Log Categories

1. **Security Logs**
```python
security_logger = logging.getLogger("security")
security_logger.info("Authentication attempt", extra={
    "user_id": user_id,
    "ip_address": request.client.host,
    "success": True
})
```

2. **Audit Logs**
```python
audit_logger = logging.getLogger("audit")
audit_logger.info("Role modified", extra={
    "role_id": role.id,
    "modifier_id": current_user.id,
    "changes": changes
})
```

3. **Performance Logs**
```python
perf_logger = logging.getLogger("performance")
perf_logger.info("API request completed", extra={
    "endpoint": request.url.path,
    "duration_ms": duration,
    "status_code": response.status_code
})
```

## Alerting System

### Alert Categories

1. **Security Alerts**
- Failed authentication attempts
- Permission violations
- Token revocations
- Configuration changes

2. **Performance Alerts**
- High response times
- Error rate spikes
- Resource utilization
- Connection pool exhaustion

3. **System Alerts**
- Component failures
- Configuration drift
- Certificate expiration
- Database issues

### Alert Configuration
```python
ALERT_CONFIG = {
    "auth_failures": {
        "threshold": 5,
        "window": 300,  # 5 minutes
        "severity": "high"
    },
    "api_errors": {
        "threshold": 10,
        "window": 60,   # 1 minute
        "severity": "medium"
    },
    "drift_detected": {
        "threshold": 1,
        "window": 3600, # 1 hour
        "severity": "high"
    }
}
```

## Dashboard Integration

### Grafana Dashboards

1. **Authentication Dashboard**
- Login success/failure rates
- Token operations
- Active sessions
- OAuth2 flow metrics

2. **Performance Dashboard**
- Request latencies
- Error rates
- Resource utilization
- Cache hit rates

3. **Security Dashboard**
- Permission changes
- Role assignments
- Configuration drifts
- Security events

### Prometheus Configuration
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'blindspotx'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

## Maintenance Monitoring

### Database Monitoring
- Connection pool usage
- Query performance
- Lock contention
- Index usage

### Cache Monitoring
- Hit/miss rates
- Memory usage
- Eviction rates
- Connection status

### OAuth Monitoring
- Token validation rates
- Provider availability
- Authorization flows
- Error rates

## Incident Response

### Monitoring Alerts
1. Set up alert channels (email, Slack, etc.)
2. Define escalation paths
3. Create incident response procedures
4. Document resolution steps

### Alert Examples
```python
async def handle_security_alert(alert: SecurityAlert):
    if alert.severity == "critical":
        await notify_security_team(alert)
        await revoke_affected_tokens(alert)
        await log_security_incident(alert)
```

## Best Practices

### Implementation Guidelines
1. Use structured logging
2. Implement proper error handling
3. Set up comprehensive metrics
4. Configure appropriate alerts

### Security Considerations
1. Protect sensitive log data
2. Secure metrics endpoints
3. Control access to dashboards
4. Audit monitoring access

## Related Documentation
- [Deployment Guide](./deployment.md)
- [Configuration Guide](./configuration.md)
- [Troubleshooting Guide](./troubleshooting.md)
- [Security Overview](../security/overview.md)

