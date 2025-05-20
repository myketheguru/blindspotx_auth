# app/api/routes/drift_router.py
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from typing import Dict, Any, List, Optional
from uuid import UUID
from pydantic import BaseModel
from datetime import datetime, timedelta

from app.models.drift import DriftReport, ConfigurationSnapshot
from app.core.database import get_db
from app.services.drift_service import detect_drift
from app.core.drift.scheduler import get_scheduler_health, start_scheduler, schedule_drift_detection
from app.core.drift.types import SecurityImpact
from app.core.drift.detector import calculate_drift_analytics


class DriftStatusResponse(BaseModel):
    """Response model for drift status endpoint"""
    last_scan: Optional[datetime] = None
    total_reports: int = 0
    high_severity_count: int = 0
    active_scan: bool = False


class DriftHistoryResponse(BaseModel):
    """Response model for drift history endpoint"""
    snapshot_date: datetime
    category: str
    key: str
    has_changes: bool


class SchedulerHealthResponse(BaseModel):
    """Response model for scheduler health endpoint"""
    status: str
    start_time: Optional[datetime] = None
    uptime: Optional[float] = None
    last_successful_scan: Optional[datetime] = None
    stats: Dict[str, Any] = {}


router = APIRouter(prefix="/drift", tags=["Drift Detection"])


@router.get("/reports", response_model=List[DriftReport])
async def get_drift_reports(db: AsyncSession = Depends(get_db)):
    """Get list of detected drift reports"""
    result = await db.execute(select(DriftReport).order_by(desc(DriftReport.timestamp)))
    reports = result.scalars().all()
    return reports


@router.get("/reports/{report_id}", response_model=DriftReport)
async def get_drift_report_by_id(report_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get a specific drift report by ID"""
    result = await db.execute(select(DriftReport).where(DriftReport.id == report_id))
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Drift report with ID {report_id} not found"
        )
    
    return report


@router.get("/status", response_model=DriftStatusResponse)
async def get_drift_status(db: AsyncSession = Depends(get_db)):
    """Get current status of drift detection"""
    # Get last scan time
    last_scan_result = await db.execute(
        select(DriftReport)
        .order_by(desc(DriftReport.timestamp))
        .limit(1)
    )
    last_scan = last_scan_result.scalar_one_or_none()
    
    # Get total reports count
    total_reports_result = await db.execute(select(DriftReport))
    total_reports = len(total_reports_result.scalars().all())
    
    # Get high severity count using proper query
    high_severity_result = await db.execute(
        select(DriftReport)
        .where(DriftReport.severity.in_(["high", "critical"]))
    )
    high_severity_count = len(high_severity_result.scalars().all())
    
    # Check if scan is active
    scheduler_health = get_scheduler_health()
    active_scan = scheduler_health["status"] == "RUNNING"
    
    return DriftStatusResponse(
        last_scan=last_scan.timestamp if last_scan else None,
        total_reports=total_reports,
        high_severity_count=high_severity_count,
        active_scan=active_scan
    )


@router.get("/history", response_model=List[DriftHistoryResponse])
async def get_drift_history(db: AsyncSession = Depends(get_db)):
    """Get history of configuration snapshots with change indicators"""
    # Get snapshots with change indicators
    result = await db.execute(
        select(ConfigurationSnapshot)
        .order_by(desc(ConfigurationSnapshot.timestamp))
    )
    snapshots = result.scalars().all()
    
    # For each snapshot, determine if changes were detected
    history_items = []
    for snapshot in snapshots:
        # Check if there are any reports associated with this snapshot
        reports_result = await db.execute(
            select(DriftReport)
            .where(DriftReport.timestamp >= snapshot.timestamp)
            .where(DriftReport.timestamp <= snapshot.timestamp + timedelta(minutes=5))
            .where(DriftReport.category == snapshot.category)
            .where(DriftReport.key == snapshot.key)
        )
        reports = reports_result.scalars().all()
        
        history_items.append(DriftHistoryResponse(
            snapshot_date=snapshot.timestamp,
            category=snapshot.category,
            key=snapshot.key,
            has_changes=len(reports) > 0
        ))
    
    return history_items


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED)
async def trigger_drift_scan(background_tasks: BackgroundTasks):
    """Manually trigger a drift detection scan"""
    # Add the drift detection task to run in the background
    background_tasks.add_task(detect_drift)
    
    return {"status": "Drift detection scan started"}


@router.get("/health", response_model=SchedulerHealthResponse)
async def get_drift_health():
    """Get health status of the drift detection scheduler"""
    health_info = get_scheduler_health()
    
    return SchedulerHealthResponse(
        status=health_info["status"],
        start_time=health_info.get("start_time"),
        uptime=health_info.get("uptime"),
        last_successful_scan=health_info.get("last_successful_scan"),
        stats=health_info.get("jobs", {}).get("stats", {})
    )
