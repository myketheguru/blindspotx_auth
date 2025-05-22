"""
Celery Configuration for Drift Detection
----------------------------------------
This module configures Celery for handling background drift detection tasks.
"""

import os
from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

# Create Celery instance
celery_app = Celery(
    "drift_detector",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.drift_tasks",
        "app.tasks.cleanup_tasks",
        "app.tasks.notification_tasks"
    ]
)

# Configure Celery
celery_app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Task routing
    task_routes={
        "app.tasks.drift_tasks.detect_drift": {"queue": "drift_detection"},
        "app.tasks.drift_tasks.compare_snapshots": {"queue": "drift_analysis"},
        "app.tasks.cleanup_tasks.cleanup_old_snapshots": {"queue": "maintenance"},
        "app.tasks.notification_tasks.send_drift_alert": {"queue": "notifications"},
    },
    
    # Worker settings
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    
    # Task execution settings
    task_soft_time_limit=300,  # 5 minutes
    task_time_limit=600,       # 10 minutes
    task_max_retries=3,
    task_default_retry_delay=60,
    
    # Result backend settings
    result_expires=3600,  # 1 hour
    result_persistent=True,
    
    # Beat schedule for periodic tasks
    beat_schedule={
        "drift-detection": {
            "task": "app.tasks.drift_tasks.detect_drift",
            "schedule": crontab(minute="*/30"),  # Every 30 minutes
            "options": {"queue": "drift_detection"}
        },
        "cleanup-old-snapshots": {
            "task": "app.tasks.cleanup_tasks.cleanup_old_snapshots",
            "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
            "options": {"queue": "maintenance"}
        },
        "generate-drift-analytics": {
            "task": "app.tasks.drift_tasks.generate_analytics_report",
            "schedule": crontab(hour=6, minute=0),  # Daily at 6 AM
            "options": {"queue": "drift_analysis"}
        },
    },
)

# Health check task
@celery_app.task(bind=True)
def health_check(self):
    """Health check task for monitoring."""
    return {
        "status": "healthy",
        "worker_id": self.request.id,
        "timestamp": self.request.utc
    }