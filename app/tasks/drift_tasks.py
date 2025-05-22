# app/tasks/drift_tasks.py
"""
Celery Tasks for Drift Detection
-------------------------------
This module contains all the Celery tasks for drift detection, replacing
the previous asyncio-based scheduling system.
"""

import asyncio
import logging
import json
import hashlib
import time
from datetime import datetime, timezone, timedelta
from uuid import uuid4, UUID
from typing import List, Dict, Optional, Any, Tuple
from celery import Task
from celery.exceptions import Retry
import httpx

from app.core.celery_app import celery_app
from app.core.database import get_db
from app.core.config import settings
from app.models.drift import (
    ConfigurationSnapshot, 
    DriftReport, 
    ValidationStatus, 
    RetentionPolicy, 
    Severity, 
    DriftStatus
)
from app.core.drift.types import (
    DriftCategory,
    DriftType,
    DriftChange,
    SecurityImpact,
    DriftResult
)
from app.core.drift.detector import compare_objects, safe_category_convert
from app.api.routes.auth import get_msal_app
from sqlmodel import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Constants
MAX_RETRIES = 3
RETRY_DELAY = 2


class AsyncTask(Task):
    """Base class for async Celery tasks."""
    
    def __call__(self, *args, **kwargs):
        """Execute the task in an asyncio event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.run_async(*args, **kwargs))
        finally:
            loop.close()
    
    async def run_async(self, *args, **kwargs):
        """Override this method in subclasses."""
        raise NotImplementedError("Subclasses must implement run_async")


@celery_app.task(bind=True, base=AsyncTask, max_retries=3)
async def detect_drift(self):
    """
    Main Celery task for detecting drift in Azure AD roles/users.
    This replaces the previous detect_drift function.
    """
    logger.info("Starting drift detection task")
    
    try:
        # Get authentication token
        access_token = await get_graph_access_token()
        if not access_token:
            logger.error("Failed to acquire access token for drift detection")
            self.retry(countdown=300)  # Retry in 5 minutes
            return
        
        # Process each category
        results = {}
        for category in ["role", "user"]:
            try:
                # Fetch current data from Microsoft Graph
                current_data = await fetch_graph_data(access_token, category)
                
                if not current_data:
                    logger.warning(f"No data retrieved for category {category}")
                    continue
                
                # Save current snapshot
                batch_id = await save_snapshot_task.delay(category, current_data)
                
                # Detect drift by comparing with previous snapshots
                drift_reports = await compare_with_previous_snapshots.delay(
                    category, current_data, batch_id
                )
                
                results[category] = {
                    "items_processed": len(current_data),
                    "drift_reports": len(drift_reports) if drift_reports else 0
                }
                
            except Exception as e:
                logger.error(f"Error processing category {category}: {str(e)}")
                results[category] = {"error": str(e)}
        
        # Send alerts for high-severity changes
        await send_drift_alerts.delay(results)
        
        logger.info(f"Drift detection completed: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Error during drift detection: {str(e)}")
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying drift detection (attempt {self.request.retries + 1})")
            self.retry(countdown=60 * (self.request.retries + 1))
        raise


@celery_app.task(bind=True, base=AsyncTask)
async def save_snapshot_task(self, category: str, items: List[Dict], 
                           retention: str = "MEDIUM_TERM", creator: str = "system"):
    """
    Celery task to save configuration snapshots.
    """
    logger.info(f"Saving snapshot for category {category} with {len(items)} items")
    
    try:
        batch_id = uuid4()
        
        async for db in get_db():
            for item in items:
                # Calculate hash for quick comparison
                item_hash = hashlib.sha256(
                    json.dumps(item, sort_keys=True).encode()
                ).hexdigest()
                
                # Save additional metadata
                metadata = {
                    "snapshot_time": datetime.now(timezone.utc).isoformat(),
                    "item_count": len(items),
                    "source": f"graph_api/{category}",
                    "version": "1.0",
                }
                
                # Add specific metadata based on item type
                if category == "user":
                    metadata["user_type"] = item.get("userType", "unknown")
                    if "assignedLicenses" in item:
                        metadata["license_count"] = len(item.get("assignedLicenses", []))
                        
                elif category == "role":
                    metadata["role_template_id"] = item.get("roleTemplateId", "unknown")
                    metadata["is_builtin"] = bool(item.get("isBuiltIn", False))
                
                snapshot = ConfigurationSnapshot(
                    category=category,
                    key=item["id"],
                    value=json.dumps(item),
                    batch_id=batch_id,
                    config_metadata=metadata,
                    retention_policy=RetentionPolicy[retention],
                    validation_status=ValidationStatus.VALID,
                    hash=item_hash,
                    created_by=creator
                )
                db.add(snapshot)
            
            await db.commit()
            logger.info(f"Saved {len(items)} {category} snapshots with batch ID {batch_id}")
            return str(batch_id)
            
    except Exception as e:
        logger.error(f"Error saving snapshots: {str(e)}")
        self.retry(countdown=60)
        

@celery_app.task(bind=True, base=AsyncTask)
async def compare_with_previous_snapshots(self, category: str, current_data: List[Dict], 
                                        batch_id: Optional[str] = None):
    """
    Compare current data with previous snapshots to detect drift.
    """
    logger.info(f"Comparing snapshots for category {category}")
    
    try:
        async for db in get_db():
            # Get the two most recent snapshots for this category
            result = await db.execute(
                select(ConfigurationSnapshot)
                .where(ConfigurationSnapshot.category == category)
                .order_by(ConfigurationSnapshot.timestamp.desc())
            )
            snapshots = result.scalars().all()
            
            if len(snapshots) < 2:
                logger.info(f"Not enough snapshots for comparison in category {category}")
                return []
            
            # Get previous snapshot items (second most recent batch)
            previous_timestamp = snapshots[1].timestamp
            previous_result = await db.execute(
                select(ConfigurationSnapshot)
                .where(ConfigurationSnapshot.category == category)
                .where(ConfigurationSnapshot.timestamp == previous_timestamp)
            )
            previous_snapshots = previous_result.scalars().all()
            
            # Compare snapshots and generate drift reports
            reports = await compare_snapshots(previous_snapshots, current_data, batch_id)
            
            # Save drift reports to database
            for report in reports:
                db.add(report)
            await db.commit()
            
            logger.info(f"Generated {len(reports)} drift reports for {category}")
            return [str(report.id) for report in reports]
            
    except Exception as e:
        logger.error(f"Error comparing snapshots: {str(e)}")
        self.retry(countdown=60)


@celery_app.task(bind=True, base=AsyncTask)
async def generate_analytics_report(self):
    """
    Generate comprehensive analytics report for drift detection.
    """
    logger.info("Generating drift analytics report")
    
    try:
        from app.core.drift.detector import calculate_drift_analytics
        
        async for db in get_db():
            analytics = await calculate_drift_analytics(db, time_window_days=30)
            
            # Store analytics results (you might want to save to a separate table)
            logger.info(f"Analytics generated: {analytics['total_reports']} reports analyzed")
            
            # Send analytics report if configured
            if settings.DRIFT_ALERT_EMAIL:
                await send_analytics_email.delay(analytics)
            
            return analytics
            
    except Exception as e:
        logger.error(f"Error generating analytics: {str(e)}")
        self.retry(countdown=300)


@celery_app.task(bind=True, base=AsyncTask, max_retries=2)
async def send_drift_alerts(self, detection_results: Dict[str, Any]):
    """
    Send alerts for detected drift changes.
    """
    logger.info("Processing drift alerts")
    
    try:
        # Check if there were any significant changes
        total_reports = sum(
            result.get("drift_reports", 0) 
            for result in detection_results.values() 
            if isinstance(result, dict) and "drift_reports" in result
        )
        
        if total_reports == 0:
            logger.info("No drift reports to alert on")
            return
        
        # Get high-severity reports from the last hour
        async for db in get_db():
            one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            
            result = await db.execute(
                select(DriftReport)
                .where(DriftReport.timestamp >= one_hour_ago)
                .where(DriftReport.severity.in_(["high", "critical"]))
                .where(DriftReport.alert_sent == False)
            )
            high_severity_reports = result.scalars().all()
            
            if not high_severity_reports:
                logger.info("No high-severity reports to alert on")
                return
            
            # Send webhook alert
            if settings.DRIFT_ALERT_WEBHOOK:
                await send_webhook_alert.delay([
                    {
                        "id": str(report.id),
                        "category": report.category,
                        "severity": str(report.severity),
                        "change_type": report.change_type,
                        "timestamp": report.timestamp.isoformat(),
                        "security_impact": str(report.security_impact)
                    }
                    for report in high_severity_reports
                ])
            
            # Send email alert
            if settings.DRIFT_ALERT_EMAIL:
                await send_email_alert.delay([
                    {
                        "id": str(report.id),
                        "category": report.category,
                        "severity": str(report.severity),
                        "change_type": report.change_type,
                        "timestamp": report.timestamp.isoformat(),
                        "summary": f"{report.change_type} in {report.category}"
                    }
                    for report in high_severity_reports
                ])
            
            # Mark alerts as sent
            for report in high_severity_reports:
                report.alert_sent = True
            await db.commit()
            
            logger.info(f"Sent alerts for {len(high_severity_reports)} high-severity reports")
            
    except Exception as e:
        logger.error(f"Error sending drift alerts: {str(e)}")
        self.retry(countdown=300)


async def get_graph_access_token() -> Optional[str]:
    """Get Microsoft Graph access token."""
    try:
        msal_app = get_msal_app()
        result = msal_app.acquire_token_silent(scopes=settings.PARSED_MS_SCOPES, account=None)

        if not result:
            logger.info("No cached token found, using client credentials flow")
            client_scopes = ["https://graph.microsoft.com/.default"]
            result = msal_app.acquire_token_for_client(scopes=client_scopes)
            
        if result and "access_token" in result:
            return result["access_token"]
        
        logger.error("Failed to acquire access token")
        return None
        
    except Exception as e:
        logger.error(f"Error acquiring access token: {str(e)}")
        return None


async def fetch_graph_data(access_token: str, category: str, retries: int = MAX_RETRIES) -> List[Dict]:
    """Fetch data from Microsoft Graph API with retry mechanism."""
    endpoint_map = {
        "role": "directoryRoles",
        "user": "users"
    }
    
    endpoint = endpoint_map.get(category)
    if not endpoint:
        logger.warning(f"Unknown category: {category}")
        return []
    
    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://graph.microsoft.com/v1.0/{endpoint}",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                
                if response.status_code == 200:
                    return response.json().get("value", [])
                elif response.status_code == 429 or response.status_code >= 500:
                    retry_after = int(response.headers.get('Retry-After', RETRY_DELAY))
                    logger.warning(f"Rate limited or server error. Retrying after {retry_after}s...")
                    await asyncio.sleep(retry_after)
                else:
                    logger.warning(f"Failed to fetch from Graph API: {response.text}")
                    if attempt < retries - 1:
                        await asyncio.sleep(RETRY_DELAY * (2 ** attempt))
                    else:
                        return []
        except Exception as e:
            logger.error(f"Exception fetching Graph data: {str(e)}")
            if attempt < retries - 1:
                await asyncio.sleep(RETRY_DELAY * (2 ** attempt))
            else:
                return []
    
    return []


async def compare_snapshots(
    old_snapshots: List[ConfigurationSnapshot],
    new_snapshots: List[Dict],
    batch_id: Optional[str] = None
) -> List[DriftReport]:
    """
    Compare old and new snapshots to detect drift.
    This is adapted from your original implementation.
    """
    if not old_snapshots or not new_snapshots:
        return []
    
    batch_uuid = UUID(batch_id) if batch_id else uuid4()
    category = old_snapshots[0].category if old_snapshots else "unknown"
    
    # Create maps for faster lookup
    old_snapshots_map = {snapshot.key: snapshot for snapshot in old_snapshots}
    new_snapshots_map = {item["id"]: item for item in new_snapshots}
    
    old_ids = set(old_snapshots_map.keys())
    new_ids = set(new_snapshots_map.keys())
    
    # Find changes
    created_ids = new_ids - old_ids
    deleted_ids = old_ids - new_ids
    potentially_modified_ids = old_ids.intersection(new_ids)
    
    reports = []
    
    # Handle created items
    for item_id in created_ids:
        new_item = new_snapshots_map[item_id]
        severity, security_impact, affected_components = await determine_severity(
            category, "created", new_value=new_item
        )
        
        report = DriftReport(
            batch_id=batch_uuid,
            key=item_id,
            category=category,
            change_type="created",
            severity=severity,
            security_impact=security_impact,
            affected_components=affected_components,
            old_value=None,
            new_value=json.dumps(new_item),
            timestamp=datetime.now(timezone.utc),
            status=DriftStatus.DETECTED,
            alert_sent=False
        )
        reports.append(report)
    
    # Handle deleted items
    for item_id in deleted_ids:
        old_snapshot = old_snapshots_map[item_id]
        old_item = json.loads(old_snapshot.value)
        
        severity, security_impact, affected_components = await determine_severity(
            category, "deleted", old_value=old_item
        )
        
        report = DriftReport(
            batch_id=batch_uuid,
            key=item_id,
            category=category,
            change_type="deleted",
            severity=severity,
            security_impact=security_impact,
            affected_components=affected_components,
            old_value=old_snapshot.value,
            new_value=None,
            timestamp=datetime.now(timezone.utc),
            status=DriftStatus.DETECTED,
            alert_sent=False
        )
        reports.append(report)
    
    # Handle modified items
    for item_id in potentially_modified_ids:
        old_snapshot = old_snapshots_map[item_id]
        old_item = json.loads(old_snapshot.value)
        new_item = new_snapshots_map[item_id]
        
        # Perform deep comparison
        result = compare_objects(old_item, new_item)
        
        if result.changed:
            severity, security_impact, affected_components = await determine_severity(
                category, "modified", old_value=old_item, new_value=new_item
            )
            
            report = DriftReport(
                batch_id=batch_uuid,
                key=item_id,
                category=category,
                change_type="modified",
                severity=severity,
                security_impact=security_impact,
                affected_components=affected_components,
                old_value=old_snapshot.value,
                new_value=json.dumps(new_item),
                changed_fields=result.changed_paths,
                timestamp=datetime.now(timezone.utc),
                status=DriftStatus.DETECTED,
                alert_sent=False
            )
            reports.append(report)
    
    return reports


async def determine_severity(
    category: str, 
    change_type: str, 
    old_value: Optional[Dict] = None, 
    new_value: Optional[Dict] = None
) -> Tuple[Severity, SecurityImpact, List[str]]:
    """
    Determine severity and security impact of a change.
    Adapted from your original implementation.
    """
    severity = Severity.MEDIUM
    security_impact = SecurityImpact.UNKNOWN
    affected_components = []
    
    # Maintain existing severity determination logic here
    # (keeping it similar to original implementation)
    
    critical_categories = {"AUTH_SETTINGS", "PASSWORD_POLICY", "MFA_SETTINGS", "FIREWALL"}
    security_categories = {"ROLE", "PERMISSION", "USER"}
    
    if category.upper() in critical_categories:
        severity = Severity.HIGH
        security_impact = SecurityImpact.HIGH
        affected_components = ["security", "authentication"]
        if change_type == "deleted":
            severity = Severity.CRITICAL
            security_impact = SecurityImpact.CRITICAL_SECURITY_REMOVED
    
    elif category.upper() in security_categories:
        if change_type == "created":
            severity = Severity.MEDIUM
            security_impact = SecurityImpact.MEDIUM
            affected_components = ["identity", "access"]
        elif change_type == "deleted":
            severity = Severity.HIGH
            security_impact = SecurityImpact.HIGH
            affected_components = ["identity", "access", "security"]
        else:
            severity = Severity.MEDIUM
            security_impact = SecurityImpact.MEDIUM
            affected_components = ["identity", "access", "configuration"]
    
    return severity, security_impact, affected_components