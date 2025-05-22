# app/api/routes/drift_celery.py
"""
FastAPI routes for Celery-based drift detection
----------------------------------------------
This module provides API endpoints to interact with Celery tasks
for drift detection, replacing the previous asyncio-based system.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.drift import DriftReport, ConfigurationSnapshot
from app.tasks.drift_tasks import (
    detect_drift, 
    generate_analytics_report, 
    save_snapshot_task,
    compare_with_previous_snapshots
)
from app.tasks.cleanup_tasks import cleanup_old_snapshots, generate_health_report
from app.tasks.notification_tasks import send_webhook_alert, send_email_alert
from app.core.celery_app import celery_app

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/trigger", response_model=Dict[str, Any])
async def trigger_drift_detection(
    current_user: User = Depends(get_current_user)
):
    """
    Manually trigger drift detection process.
    """
    try:
        # Trigger the Celery task
        task = detect_drift.delay()
        
        logger.info(f"Drift detection triggered by user {current_user.email}, task ID: {task.id}")
        
        return {
            "message": "Drift detection started",
            "task_id": task.id,
            "status": "pending",
            "triggered_by": current_user.email,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error triggering drift detection: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger drift detection: {str(e)}")


@router.get("/status/{task_id}")
async def get_task_status(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get the status of a drift detection task.
    """
    try:
        task_result = celery_app.AsyncResult(task_id)
        
        response = {
            "task_id": task_id,
            "status": task_result.status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if task_result.ready():
            if task_result.successful():
                response["result"] = task_result.result
            else:
                response["error"] = str(task_result.info)
        else:
            response["message"] = "Task is still running"
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting task status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get task status: {str(e)}")


@router.get("/reports", response_model=List[Dict[str, Any]])
async def get_drift_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    days: int = Query(default=30, le=365)
):
    """
    Get drift reports with filtering options.
    """
    try:
        # Build query
        query = select(DriftReport)
        
        # Add time filter
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = query.where(DriftReport.timestamp >= cutoff_date)
        
        # Add filters
        if severity:
            query = query.where(DriftReport.severity == severity)
        if category:
            query = query.where(DriftReport.category == category)
        if status:
            query = query.where(DriftReport.status == status)
        
        # Add ordering and pagination
        query = query.order_by(DriftReport.timestamp.desc())
        query = query.offset(offset).limit(limit)
        
        result = await db.execute(query)
        reports = result.scalars().all()
        
        # Convert to dict for JSON response
        reports_data = []
        for report in reports:
            report_dict = {
                "id": str(report.id),
                "batch_id": str(report.batch_id) if report.batch_id else None,
                "key": report.key,
                "category": report.category,
                "change_type": report.change_type,
                "severity": str(report.severity),
                "security_impact": str(report.security_impact),
                "affected_components": report.affected_components,
                "timestamp": report.timestamp.isoformat() if report.timestamp else None,
                "status": str(report.status),
                "alert_sent": report.alert_sent,
                "is_security_sensitive": getattr(report, 'is_security_sensitive', False),
                "is_unusual_pattern": getattr(report, 'is_unusual_pattern', False),
                "changed_fields": getattr(report, 'changed_fields', [])
            }
            reports_data.append(report_dict)
        
        return reports_data
        
    except Exception as e:
        logger.error(f"Error fetching drift reports: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch reports: {str(e)}")


@router.get("/analytics")
async def get_drift_analytics(
    current_user: User = Depends(get_current_user),
    days: int = Query(default=30, le=365, description="Number of days to analyze")
):
    """
    Get drift analytics or trigger analytics generation.
    """
    try:
        # Trigger analytics generation task
        task = generate_analytics_report.delay()
        
        return {
            "message": "Analytics generation started",
            "task_id": task.id,
            "status": "pending",
            "time_window_days": days,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating analytics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate analytics: {str(e)}")


@router.post("/reports/{report_id}/acknowledge")
async def acknowledge_drift_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Acknowledge a drift report (mark as reviewed).
    """
    try:
        # Find the report
        result = await db.execute(
            select(DriftReport).where(DriftReport.id == report_id)
        )
        report = result.scalars().first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Drift report not found")
        
        # Update the report status
        report.status = "acknowledged"
        report.resolved_by = current_user.id
        report.resolution_timestamp = datetime.utcnow()
        report.resolution_notes = f"Acknowledged by {current_user.email}"
        
        await db.commit()
        
        logger.info(f"Drift report {report_id} acknowledged by {current_user.email}")
        
        return {
            "message": "Drift report acknowledged",
            "report_id": str(report_id),
            "acknowledged_by": current_user.email,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging drift report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to acknowledge report: {str(e)}")


@router.post("/reports/{report_id}/resolve")
async def resolve_drift_report(
    report_id: UUID,
    resolution_notes: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Resolve a drift report with notes.
    """
    try:
        # Find the report
        result = await db.execute(
            select(DriftReport).where(DriftReport.id == report_id)
        )
        report = result.scalars().first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Drift report not found")
        
        # Update the report
        report.status = "resolved"
        report.resolved_by = current_user.id
        report.resolution_timestamp = datetime.utcnow()
        report.resolution_notes = resolution_notes
        
        await db.commit()
        
        logger.info(f"Drift report {report_id} resolved by {current_user.email}")
        
        return {
            "message": "Drift report resolved",
            "report_id": str(report_id),
            "resolved_by": current_user.email,
            "resolution_notes": resolution_notes,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving drift report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to resolve report: {str(e)}")


@router.post("/cleanup")
async def trigger_cleanup(
    current_user: User = Depends(get_current_user),
    retention_days: int = Query(default=90, description="Days to retain data")
):
    """
    Manually trigger cleanup of old snapshots and reports.
    """
    try:
        task = cleanup_old_snapshots.delay(retention_days)
        
        logger.info(f"Cleanup triggered by user {current_user.email}, task ID: {task.id}")
        
        return {
            "message": "Cleanup started",
            "task_id": task.id,
            "retention_days": retention_days,
            "triggered_by": current_user.email,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error triggering cleanup: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger cleanup: {str(e)}")


@router.get("/health")
async def get_system_health(
    current_user: User = Depends(get_current_user)
):
    """
    Get system health information including Celery worker status.
    """
    try:
        # Get Celery worker stats
        celery_inspect = celery_app.control.inspect()
        
        # Get active tasks
        active_tasks = celery_inspect.active()
        
        # Get worker stats
        worker_stats = celery_inspect.stats()
        
        # Get scheduled tasks
        scheduled_tasks = celery_inspect.scheduled()
        
        # Get reserved tasks
        reserved_tasks = celery_inspect.reserved()
        
        # Trigger health report generation
        health_task = generate_health_report.delay()
        
        health_info = {
            "timestamp": datetime.utcnow().isoformat(),
            "celery": {
                "workers": {
                    "active": len(worker_stats) if worker_stats else 0,
                    "stats": worker_stats,
                },
                "tasks": {
                    "active": sum(len(tasks) for tasks in active_tasks.values()) if active_tasks else 0,
                    "scheduled": sum(len(tasks) for tasks in scheduled_tasks.values()) if scheduled_tasks else 0,
                    "reserved": sum(len(tasks) for tasks in reserved_tasks.values()) if reserved_tasks else 0,
                },
                "queues": {
                    "drift_detection": "active" if worker_stats else "inactive",
                    "drift_analysis": "active" if worker_stats else "inactive",
                    "maintenance": "active" if worker_stats else "inactive",
                    "notifications": "active" if worker_stats else "inactive",
                }
            },
            "health_report_task_id": health_task.id,
            "status": "healthy" if worker_stats else "degraded"
        }
        
        return health_info
        
    except Exception as e:
        logger.error(f"Error getting system health: {str(e)}")
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "status": "error",
            "error": str(e),
            "celery": {
                "workers": {"active": 0},
                "tasks": {"active": 0, "scheduled": 0, "reserved": 0}
            }
        }


@router.post("/test-alert")
async def test_alert_system(
    current_user: User = Depends(get_current_user)
):
    """
    Test the alert system by sending a test notification.
    """
    try:
        test_reports = [
            {
                "id": "test-report-1",
                "category": "user",
                "severity": "high",
                "change_type": "modified",
                "timestamp": datetime.utcnow().isoformat(),
                "security_impact": "high",
                "summary": "Test drift detection alert"
            }
        ]
        
        tasks = []
        
        # Send webhook alert if configured
        if hasattr(settings, 'DRIFT_ALERT_WEBHOOK') and settings.DRIFT_ALERT_WEBHOOK:
            webhook_task = send_webhook_alert.delay(test_reports)
            tasks.append({"type": "webhook", "task_id": webhook_task.id})
        
        # Send email alert if configured
        if hasattr(settings, 'DRIFT_ALERT_EMAIL') and settings.DRIFT_ALERT_EMAIL:
            email_task = send_email_alert.delay(test_reports)
            tasks.append({"type": "email", "task_id": email_task.id})
        
        if not tasks:
            return {
                "message": "No alert methods configured",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        logger.info(f"Test alerts triggered by user {current_user.email}")
        
        return {
            "message": "Test alerts sent",
            "tasks": tasks,
            "triggered_by": current_user.email,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error sending test alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to send test alerts: {str(e)}")


@router.get("/snapshots")
async def get_snapshots(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    category: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0)
):
    """
    Get configuration snapshots with filtering.
    """
    try:
        query = select(ConfigurationSnapshot)
        
        if category:
            query = query.where(ConfigurationSnapshot.category == category)
        
        query = query.order_by(ConfigurationSnapshot.timestamp.desc())
        query = query.offset(offset).limit(limit)
        
        result = await db.execute(query)
        snapshots = result.scalars().all()
        
        snapshots_data = []
        for snapshot in snapshots:
            snapshot_dict = {
                "id": str(snapshot.id),
                "category": snapshot.category,
                "key": snapshot.key,
                "batch_id": str(snapshot.batch_id) if snapshot.batch_id else None,
                "timestamp": snapshot.timestamp.isoformat() if snapshot.timestamp else None,
                "validation_status": str(snapshot.validation_status),
                "retention_policy": str(snapshot.retention_policy),
                "hash": snapshot.hash,
                "created_by": snapshot.created_by,
                "config_metadata": snapshot.config_metadata
            }
            snapshots_data.append(snapshot_dict)
        
        return snapshots_data
        
    except Exception as e:
        logger.error(f"Error fetching snapshots: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch snapshots: {str(e)}")


@router.delete("/snapshots/{snapshot_id}")
async def delete_snapshot(
    snapshot_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete a specific configuration snapshot.
    """
    try:
        result = await db.execute(
            select(ConfigurationSnapshot).where(ConfigurationSnapshot.id == snapshot_id)
        )
        snapshot = result.scalars().first()
        
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        
        await db.delete(snapshot)
        await db.commit()
        
        logger.info(f"Snapshot {snapshot_id} deleted by user {current_user.email}")
        
        return {
            "message": "Snapshot deleted",
            "snapshot_id": str(snapshot_id),
            "deleted_by": current_user.email,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting snapshot: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete snapshot: {str(e)}")


@router.post("/snapshots/manual")
async def create_manual_snapshot(
    category: str,
    current_user: User = Depends(get_current_user)
):
    """
    Manually trigger creation of a configuration snapshot for a specific category.
    """
    try:
        if category not in ["role", "user"]:
            raise HTTPException(status_code=400, detail="Invalid category. Must be 'role' or 'user'")
        
        # This would need to fetch current data and save it
        # For now, we'll trigger the main detection which includes snapshot creation
        task = detect_drift.delay()
        
        logger.info(f"Manual snapshot creation triggered by user {current_user.email} for category {category}")
        
        return {
            "message": f"Manual snapshot creation started for category {category}",
            "task_id": task.id,
            "category": category,
            "triggered_by": current_user.email,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating manual snapshot: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create manual snapshot: {str(e)}")