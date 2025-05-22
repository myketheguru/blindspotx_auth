# app/tasks/cleanup_tasks.py
"""
Celery Tasks for Cleanup and Maintenance
---------------------------------------
Handle cleanup of old snapshots and maintenance tasks.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from app.core.celery_app import celery_app
from app.core.database import get_db
from app.core.config import settings
from app.models.drift import ConfigurationSnapshot, DriftReport
from sqlmodel import select, delete

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
async def cleanup_old_snapshots(self, retention_days: Optional[int] = None):
    """
    Clean up old configuration snapshots based on retention policy.
    """
    if retention_days is None:
        retention_days = getattr(settings, 'DRIFT_RETENTION_DAYS', 90)
    
    logger.info(f"Starting cleanup of snapshots older than {retention_days} days")
    
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        async for db in get_db():
            # Count snapshots to be deleted
            count_result = await db.execute(
                select(ConfigurationSnapshot)
                .where(ConfigurationSnapshot.timestamp < cutoff_date)
            )
            old_snapshots = count_result.scalars().all()
            snapshot_count = len(old_snapshots)
            
            if snapshot_count == 0:
                logger.info("No old snapshots to clean up")
                return {"deleted_snapshots": 0, "deleted_reports": 0}
            
            # Delete old snapshots
            await db.execute(
                delete(ConfigurationSnapshot)
                .where(ConfigurationSnapshot.timestamp < cutoff_date)
            )
            
            # Also clean up old drift reports
            report_count_result = await db.execute(
                select(DriftReport)
                .where(DriftReport.timestamp < cutoff_date)
                .where(DriftReport.status == "resolved")
            )
            old_reports = report_count_result.scalars().all()
            report_count = len(old_reports)
            
            await db.execute(
                delete(DriftReport)
                .where(DriftReport.timestamp < cutoff_date)
                .where(DriftReport.status == "resolved")
            )
            
            await db.commit()
            
            logger.info(f"Cleanup completed: deleted {snapshot_count} snapshots and {report_count} resolved reports")
            return {"deleted_snapshots": snapshot_count, "deleted_reports": report_count}
            
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        self.retry(countdown=3600)  # Retry in 1 hour


@celery_app.task(bind=True)
async def optimize_database(self):
    """
    Perform database optimization tasks.
    """
    logger.info("Starting database optimization")
    
    try:
        async for db in get_db():
            # Add any database optimization logic here
            # For example, updating statistics, rebuilding indexes, etc.
            
            # This is a placeholder - implement based on your database type
            logger.info("Database optimization completed")
            return {"status": "completed"}
            
    except Exception as e:
        logger.error(f"Error during database optimization: {str(e)}")
        self.retry(countdown=7200)  # Retry in 2 hours


@celery_app.task(bind=True)
async def generate_health_report(self):
    """
    Generate a health report for the drift detection system.
    """
    logger.info("Generating system health report")
    
    try:
        async for db in get_db():
            # Get various health metrics
            now = datetime.utcnow()
            last_24h = now - timedelta(hours=24)
            
            # Count recent snapshots
            recent_snapshots_result = await db.execute(
                select(ConfigurationSnapshot)
                .where(ConfigurationSnapshot.timestamp >= last_24h)
            )
            recent_snapshots = len(recent_snapshots_result.scalars().all())
            
            # Count recent reports
            recent_reports_result = await db.execute(
                select(DriftReport)
                .where(DriftReport.timestamp >= last_24h)
            )
            recent_reports = len(recent_reports_result.scalars().all())
            
            # Count unresolved critical reports
            critical_reports_result = await db.execute(
                select(DriftReport)
                .where(DriftReport.severity == "critical")
                .where(DriftReport.status != "resolved")
            )
            critical_reports = len(critical_reports_result.scalars().all())
            
            health_report = {
                "timestamp": now.isoformat(),
                "snapshots_last_24h": recent_snapshots,
                "reports_last_24h": recent_reports,
                "unresolved_critical": critical_reports,
                "system_status": "healthy" if recent_snapshots > 0 else "warning"
            }
            
            logger.info(f"Health report generated: {health_report}")
            return health_report
            
    except Exception as e:
        logger.error(f"Error generating health report: {str(e)}")
        self.retry(countdown=1800)  # Retry in 30 minutes