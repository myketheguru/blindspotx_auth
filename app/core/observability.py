"""
Observability Module
-------------------
This module provides observability features including Prometheus metrics,
enhanced health checks, and OpenTelemetry integration.
"""

import time
import logging
from contextlib import contextmanager
from typing import Dict, Any, List, Optional, Callable, Union, Generator
import functools
import os
from datetime import datetime

from fastapi import FastAPI, Request
from prometheus_client import Counter, Histogram, Gauge, Summary, Info
from starlette_exporter import PrometheusMiddleware, handle_metrics
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from app.core.config import settings
from app.models.drift import DriftReport

# Set up logging
logger = logging.getLogger(__name__)

# Prometheus metrics
DRIFT_SCAN_COUNTER = Counter(
    'blindspotx_drift_scans_total', 
    'Total number of drift detection scans'
)

DRIFT_CHANGE_COUNTER = Counter(
    'blindspotx_drift_changes_total', 
    'Total number of drift changes detected',
    ['category', 'severity', 'security_impact']
)

DRIFT_SCAN_DURATION = Histogram(
    'blindspotx_drift_scan_duration_seconds', 
    'Duration of drift detection scans in seconds',
    buckets=(1, 5, 10, 30, 60, 120, 300, 600)
)

AUTH_REQUEST_COUNTER = Counter(
    'blindspotx_auth_requests_total', 
    'Total number of authentication requests',
    ['method', 'provider', 'status']
)

API_REQUEST_DURATION = Histogram(
    'blindspotx_api_request_duration_seconds', 
    'Duration of API requests in seconds',
    ['endpoint', 'method', 'status_code']
)

ACTIVE_USERS_GAUGE = Gauge(
    'blindspotx_active_users', 
    'Number of currently active users'
)

TOKEN_REFRESH_COUNTER = Counter(
    'blindspotx_token_refreshes_total', 
    'Number of token refresh operations',
    ['status']
)

SYSTEM_INFO = Info(
    'blindspotx_system_info', 
    'Information about the BlindspotX system'
)

# Update system info
SYSTEM_INFO.info({
    'version': settings.VERSION,
    'environment': settings.ENVIRONMENT,
    'start_time': datetime.now().isoformat()
})

# OpenTelemetry setup
def setup_tracing() -> None:
    """Initialize OpenTelemetry tracing"""
    # Check if tracing is enabled
    if not getattr(settings, 'ENABLE_TRACING', False):
        logger.info("OpenTelemetry tracing is disabled")
        return
    
    # Set up tracer provider
    trace.set_tracer_provider(TracerProvider())
    tracer = trace.get_tracer(__name__)
    
    # Configure exporter
    otlp_endpoint = getattr(settings, 'OTLP_ENDPOINT', 'localhost:4317')
    
    # Set up the OTLP exporter
    otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
    span_processor = BatchSpanProcessor(otlp_exporter)
    trace.get_tracer_provider().add_span_processor(span_processor)
    
    logger.info(f"OpenTelemetry tracing initialized with endpoint {otlp_endpoint}")
    return tracer

# Context manager to measure function execution time
@contextmanager
def timed_execution(
    metric: Histogram, 
    labels: Dict[str, str] = None
) -> Generator[None, None, None]:
    """
    Context manager to measure function execution time
    
    Args:
        metric: Prometheus histogram to record duration
        labels: Labels to apply to the metric
        
    Yields:
        None
    """
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        if labels:
            metric.labels(**labels).observe(duration)
        else:
            metric.observe(duration)

# Decorator for drift detection functions to record metrics
def track_drift_detection(func: Callable) -> Callable:
    """
    Decorator to track drift detection metrics
    
    Args:
        func: Function to decorate
        
    Returns:
        Decorated function
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        DRIFT_SCAN_COUNTER.inc()
        
        # Create a new trace span
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("drift_detection"):
            with timed_execution(DRIFT_SCAN_DURATION):
                # Call the original function
                result = await func(*args, **kwargs)
                
                # Record changes if any were detected
                if isinstance(result, dict) and 'changes' in result:
                    for change in result['changes']:
                        DRIFT_CHANGE_COUNTER.labels(
                            category=change.get('category', 'unknown'),
                            severity=change.get('severity', 'unknown'),
                            security_impact=change.get('security_impact', 'unknown')
                        ).inc()
                
                return result
    
    return wrapper

def initialize_metrics(app: FastAPI) -> None:
    """
    Initialize metrics and expose a /metrics endpoint
    
    Args:
        app: FastAPI application instance
    """
    # Add PrometheusMiddleware to the application
    app.add_middleware(
        PrometheusMiddleware,
        app_name="blindspotx_auth",
        prefix="blindspotx",
        group_paths=True
    )
    
    # Add metrics endpoint
    app.add_route("/metrics", handle_metrics)
    
    logger.info("Prometheus metrics initialized")

async def get_component_health(db: AsyncSession) -> Dict[str, Any]:
    """
    Get health status of all components
    
    Args:
        db: Database session
        
    Returns:
        Dictionary with component health status
    """
    health = {
        "status": "ok",
        "components": {
            "api": {"status": "ok"},
            "database": {"status": "checking"},
            "oauth": {"status": "checking"},
            "drift_detection": {"status": "checking"}
        },
        "timestamp": datetime.now().isoformat()
    }
    
    # Check database health
    try:
        # Execute a simple query to check database connectivity
        await db.execute(select(1))
        health["components"]["database"] = {
            "status": "ok",
            "details": "Connected to database"
        }
    except Exception as e:
        health["components"]["database"] = {
            "status": "error",
            "details": f"Database error: {str(e)}"
        }
        health["status"] = "degraded"
    
    # Check OAuth provider connectivity
    try:
        from app.api.routes.auth import get_msal_app
        msal_app = get_msal_app()
        authority = msal_app.authority
        health["components"]["oauth"] = {
            "status": "ok",
            "details": f"MSAL configured with authority: {authority}"
        }
    except Exception as e:
        health["components"]["oauth"] = {
            "status": "error",
            "details": f"OAuth error: {str(e)}"
        }
        health["status"] = "degraded"
    
    # Check drift detection module
    try:
        from app.core.drift.scheduler import get_scheduler_health
        scheduler_health = get_scheduler_health()
        health["components"]["drift_detection"] = {
            "status": "ok" if scheduler_health.get("status") == "RUNNING" else "degraded",
            "details": scheduler_health
        }
    except Exception as e:
        health["components"]["drift_detection"] = {
            "status": "error",
            "details": f"Drift detection error: {str(e)}"
        }
        health["status"] = "degraded"
    
    # Get latest drift scan time
    try:
        result = await db.execute(
            select(DriftReport)
            .order_by(DriftReport.timestamp.desc())
            .limit(1)
        )
        latest_scan = result.scalar_one_or_none()
        if latest_scan:
            health["components"]["drift_detection"]["last_scan"] = latest_scan.timestamp.isoformat()
    except Exception:
        # Non-critical check, can proceed if fails
        pass
    
    # Overall health logic
    component_statuses = [c["status"] for c in health["components"].values()]
    if "error" in component_statuses:
        health["status"] = "degraded"
    
    # If any critical component is down, mark the system as down
    critical_components = ["database"]
    for comp in critical_components:
        if health["components"].get(comp, {}).get("status") == "error":
            health["status"] = "down"
            break
    
    return health

