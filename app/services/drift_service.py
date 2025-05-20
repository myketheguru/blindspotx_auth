# app/services/drift_service.py
import asyncio
import logging
import json
import hashlib
import time
from datetime import datetime, timezone
from uuid import uuid4, UUID
from typing import List, Dict, Optional, Any, Tuple, Set, Union
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.drift import (
    ConfigurationSnapshot, 
    DriftReport, 
    ValidationStatus, 
    RetentionPolicy, 
    Severity, 
    DriftStatus
)
from app.core.database import get_db
from app.api.routes.auth import get_msal_app
import httpx
from sqlmodel import select, delete, update
from app.core.config import settings
from app.core.drift.types import (
    DriftCategory,
    DriftType,
    DriftChange,
    SecurityImpact,
    DriftResult
)
from app.core.drift.detector import compare_objects, safe_category_convert

logger = logging.getLogger(__name__)

# Constants for retry mechanism
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

async def fetch_graph_data(access_token: str, endpoint: str, retries: int = MAX_RETRIES) -> List[Dict]:
    """
    Fetch data from Microsoft Graph API with retry mechanism
    
    Args:
        access_token: Bearer token for Graph API
        endpoint: API endpoint path
        retries: Number of retries for failed requests
        
    Returns:
        List of JSON objects from the API response
    """
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
                    # Rate limiting or server error - retry after delay
                    retry_after = int(response.headers.get('Retry-After', RETRY_DELAY))
                    logger.warning(f"Rate limited or server error from Graph API ({endpoint}). Retrying after {retry_after}s...")
                    await asyncio.sleep(retry_after)
                else:
                    logger.warning(f"Failed to fetch from Graph API ({endpoint}): {response.text}")
                    if attempt < retries - 1:
                        await asyncio.sleep(RETRY_DELAY * (2 ** attempt))  # Exponential backoff
                    else:
                        return []
        except Exception as e:
            logger.error(f"Exception fetching Graph data: {str(e)}")
            if attempt < retries - 1:
                await asyncio.sleep(RETRY_DELAY * (2 ** attempt))
            else:
                return []
    
    return []

async def calculate_hash(data: Dict) -> str:
    """
    Calculate a stable hash for configuration data
    
    Args:
        data: Configuration data dictionary
        
    Returns:
        Hash string for the data
    """
    # Sort dict keys for stable hash
    serialized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()

async def create_batch_id() -> UUID:
    """
    Create a batch ID for grouping related snapshots
    
    Returns:
        UUID for the batch
    """
    return uuid4()

async def save_snapshot(
    session: AsyncSession, 
    category: str, 
    items: List[Dict], 
    batch_id: Optional[UUID] = None,
    retention: RetentionPolicy = RetentionPolicy.MEDIUM_TERM,
    creator: Optional[str] = "system"
):
    """
    Save current state of a category (roles, users, etc.)
    
    Args:
        session: Database session
        category: Category name (role, user, etc.)
        items: List of configuration items to save
        batch_id: Optional batch ID for grouping snapshots
        retention: Retention policy for these snapshots
        creator: User or system that created the snapshot
    """
    # Create batch ID if not provided
    if not batch_id:
        batch_id = await create_batch_id()
        
    for item in items:
        # Calculate hash for quick comparison
        item_hash = await calculate_hash(item)
        
        # Save additional metadata about the item
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
            metadata["is_builtin"] = True if item.get("isBuiltIn", False) else False
            
        snapshot = ConfigurationSnapshot(
            category=category,
            key=item["id"],
            value=json.dumps(item),
            batch_id=batch_id,
            config_metadata=metadata,
            retention_policy=retention,
            validation_status=ValidationStatus.VALID,
            hash=item_hash,
            created_by=creator
        )
        session.add(snapshot)
    
    try:
        await session.commit()
        logger.info(f"Saved {len(items)} {category} snapshots with batch ID {batch_id}")
    except Exception as e:
        await session.rollback()
        logger.error(f"Error saving snapshots: {str(e)}")
        raise

async def determine_severity(
    category: str, 
    change_type: str, 
    old_value: Optional[Dict] = None, 
    new_value: Optional[Dict] = None
) -> Tuple[Severity, str, List[str]]:
    """
    Determine severity, security impact, and affected components of a change
    
    Args:
        category: Category of the configuration item
        change_type: Type of change detected
        old_value: Previous configuration state (if available)
        new_value: New configuration state (if available)
        
    Returns:
        Tuple of (severity, security_impact, affected_components)
    """
    severity = Severity.MEDIUM  # Default severity
    security_impact = "Unknown"
    affected_components = []
    
    # Critical categories with high security impact
    critical_categories = {"AUTH_SETTINGS", "PASSWORD_POLICY", "MFA_SETTINGS", "FIREWALL"}
    security_categories = {"ROLE", "PERMISSION", "USER"}
    
    # Determine severity based on category and change type
    if category.upper() in critical_categories:
        severity = Severity.HIGH
        if change_type == "deleted":
            severity = Severity.CRITICAL
            security_impact = "Critical security configuration removed"
            affected_components = ["security", "authentication"]
        else:
            security_impact = "Security configuration modified"
            affected_components = ["security", "authentication", "configuration"]
    
    elif category.upper() in security_categories:
        if change_type == "created":
            severity = Severity.MEDIUM
            security_impact = f"New {category} created"
            affected_components = ["identity", "access"]
        elif change_type == "deleted":
            severity = Severity.HIGH
            security_impact = f"Existing {category} deleted"
            affected_components = ["identity", "access", "security"]
        else:  # modified
            severity = Severity.MEDIUM
            security_impact = f"{category} configuration changed"
            affected_components = ["identity", "access", "configuration"]
            
            # Check for permission changes if we have old and new values
            if old_value and new_value:
                # For users, check if admin role was added
                if category == "user" and "roles" in new_value:
                    old_roles = set(old_value.get("roles", []))
                    new_roles = set(new_value.get("roles", []))
                    admin_roles = {"Admin", "Administrator", "GlobalAdmin"}
                    
                    added_roles = new_roles - old_roles
                    if any(role for role in added_roles if role in admin_roles):
                        severity = Severity.CRITICAL
                        security_impact = "Administrative privileges granted"
                        affected_components.append("admin")
                
                # For roles, check if permissions were expanded
                if category == "role" and "permissions" in new_value:
                    old_perms = set(old_value.get("permissions", []))
                    new_perms = set(new_value.get("permissions", []))
                    
                    if new_perms - old_perms:
                        severity = Severity.HIGH
                        security_impact = "Role permissions expanded"
                        affected_components.append("permissions")
    
    # Default for other categories
    else:
        if change_type == "created":
            severity = Severity.LOW
            security_impact = "New configuration item created"
        elif change_type == "deleted":
            severity = Severity.MEDIUM
            security_impact = "Configuration item deleted"
        else:
            severity = Severity.LOW
            security_impact = "Configuration modified"
        
        affected_components = ["configuration"]
    
    return severity, security_impact, affected_components

async def compare_snapshots(
    old_snapshots: List[ConfigurationSnapshot],
    new_snapshots: List[Dict],
    batch_id: Optional[UUID] = None
) -> List[DriftReport]:
    """
    Compare old and new snapshots to detect drift with enhanced security analysis
    
    Args:
        old_snapshots: Previous configuration snapshots
        new_snapshots: Current configuration items
        batch_id: Optional batch ID for grouping related reports
        
    Returns:
        List of drift reports for detected changes
    """
    if not old_snapshots:
        logger.info("No previous snapshots available for comparison")
        return []
        
    if not new_snapshots:
        logger.info("No new snapshots provided for comparison")
        return []
    
    # Create batch ID if not provided
    if not batch_id:
        batch_id = await create_batch_id()
    
    # Create maps of old snapshots for faster lookup
    old_snapshots_map = {snapshot.key: snapshot for snapshot in old_snapshots}
    category = old_snapshots[0].category if old_snapshots else "unknown"
    
    # Create maps of new snapshots for faster lookup
    new_snapshots_map = {item["id"]: item for item in new_snapshots}
    
    # Lists to track IDs in each set
    old_ids = set(old_snapshots_map.keys())
    new_ids = set(new_snapshots_map.keys())
    
    # Find created, deleted, and potentially modified items
    created_ids = new_ids - old_ids
    deleted_ids = old_ids - new_ids
    potentially_modified_ids = old_ids.intersection(new_ids)
    
    reports = []
    
    # Handle created items
    for item_id in created_ids:
        new_item = new_snapshots_map[item_id]
        severity, security_impact, affected_components = await determine_severity(
            category, 
            "created", 
            new_value=new_item
        )
        
        change = DriftChange(
            category=safe_category_convert(category),
            change_type=DriftType.CREATED,
            key=item_id,
            old_value=None,
            new_value=new_item,
            path="*"  # All fields are new
        )
        
        report = DriftReport(
            batch_id=batch_id,
            key=item_id,
            category=category,
            change_type="created",
            severity=severity,
            security_impact=SecurityImpact[security_impact.upper().replace(" ", "_")] if security_impact.upper().replace(" ", "_") in SecurityImpact.__members__ else SecurityImpact.UNKNOWN,
            affected_components=affected_components,
            old_value=None,
            new_value=json.dumps(new_item),
            timestamp=datetime.now(timezone.utc),
            status=DriftStatus.DETECTED,
            resolution_notes=None,
            resolved_by=None,
            resolution_timestamp=None,
            alert_sent=False
        )
        reports.append(report)
    
    # Handle deleted items
    for item_id in deleted_ids:
        old_snapshot = old_snapshots_map[item_id]
        old_item = json.loads(old_snapshot.value)
        
        severity, security_impact, affected_components = await determine_severity(
            category, 
            "deleted", 
            old_value=old_item
        )
        
        change = DriftChange(
            category=safe_category_convert(category),
            change_type=DriftType.DELETED,
            key=item_id,
            old_value=old_item,
            new_value=None,
            path="*"  # All fields are removed
        )
        
        report = DriftReport(
            batch_id=batch_id,
            key=item_id,
            category=category,
            change_type="deleted",
            severity=severity,
            security_impact=SecurityImpact[security_impact.upper().replace(" ", "_")] if security_impact.upper().replace(" ", "_") in SecurityImpact.__members__ else SecurityImpact.UNKNOWN,
            affected_components=affected_components,
            old_value=old_snapshot.value,
            new_value=None,
            timestamp=datetime.now(timezone.utc),
            status=DriftStatus.DETECTED,
            resolution_notes=None,
            resolved_by=None,
            resolution_timestamp=None,
            alert_sent=False
        )
        reports.append(report)
    
    # Handle modified items
    for item_id in potentially_modified_ids:
        old_snapshot = old_snapshots_map[item_id]
        old_item = json.loads(old_snapshot.value)
        new_item = new_snapshots_map[item_id]
        
        # Perform deep comparison to detect changes
        result = compare_objects(old_item, new_item)
        
        if result.changed:
            severity, security_impact, affected_components = await determine_severity(
                category, 
                "modified", 
                old_value=old_item,
                new_value=new_item
            )
            
            change = DriftChange(
                category=safe_category_convert(category),
                change_type=DriftType.MODIFIED,
                key=item_id,
                old_value=old_item,
                new_value=new_item,
                path=",".join(result.changed_paths) if result.changed_paths else "*"
            )
            
            # Determine if this is a critical or security-sensitive change
            is_security_sensitive = any(
                component in ["security", "authentication", "permissions", "admin"] 
                for component in affected_components
            )
            
            is_unusual_pattern = False
            # Check for unusual patterns (e.g., multiple changes in short timeframe)
            # This would typically involve checking recent history, which would require additional queries
            
            report = DriftReport(
                batch_id=batch_id,
                key=item_id,
                category=category,
                change_type="modified",
                severity=severity,
                security_impact=SecurityImpact[security_impact.upper().replace(" ", "_")] if security_impact.upper().replace(" ", "_") in SecurityImpact.__members__ else SecurityImpact.UNKNOWN,
                affected_components=affected_components,
                old_value=old_snapshot.value,
                new_value=json.dumps(new_item),
                changed_fields=result.changed_paths,
                timestamp=datetime.now(timezone.utc),
                status=DriftStatus.DETECTED,
                resolution_notes=None,
                resolved_by=None,
                resolution_timestamp=None,
                is_security_sensitive=is_security_sensitive,
                is_unusual_pattern=is_unusual_pattern,
                alert_sent=False
            )
            reports.append(report)
    
    if reports:
        logger.info(f"Detected {len(reports)} changes in {category} configuration")
    else:
        logger.info(f"No changes detected in {category} configuration")
        
    return reports

async def detect_drift():
    """Main function to detect drift in Azure AD roles/users"""
    logger.info("Starting drift detection job")

    try:
        # Get token silently first
        msal_app = get_msal_app()
        result = msal_app.acquire_token_silent(scopes=settings.PARSED_MS_SCOPES, account=None)

        if not result:
            logger.info("No cached token found, falling back to client credentials flow")
            # For client credentials flow, we need to use .default scope
            client_scopes = ["https://graph.microsoft.com/.default"]
            result = msal_app.acquire_token_for_client(scopes=client_scopes)
            
        if not result:
            logger.error("Failed to acquire token through both silent auth and client credentials")
            return

        access_token = result.get("access_token")
        if not access_token:
            logger.error("Could not retrieve access token for drift detection")
            return

        async for db in get_db():
            # Fetch current state from Microsoft Graph
            roles = await fetch_graph_data(access_token, "directoryRoles")
            users = await fetch_graph_data(access_token, "users")

            # Save current state
            await save_snapshot(db, "role", roles)
            await save_snapshot(db, "user", users)

            # Clean up old snapshots (keep last 2 per category)
            for category in ["role", "user"]:
                result = await db.execute(
                    select(ConfigurationSnapshot).where(ConfigurationSnapshot.category == category)
                )
                snapshots = result.scalars().all()
                if len(snapshots) > 2:
                    oldest = sorted(snapshots, key=lambda x: x.timestamp)[0]
                    await db.delete(oldest)
                    await db.commit()

            # Detect drift between last two snapshots
            reports = []
            for category in ["role", "user"]:
                result = await db.execute(
                    select(ConfigurationSnapshot)
                    .where(ConfigurationSnapshot.category == category)
                    .order_by(ConfigurationSnapshot.timestamp.desc())
                )
                snapshots = result.scalars().all()
                if len(snapshots) >= 2:
                    latest = snapshots[0]  # Most recent snapshot
                    previous = snapshots[1]  # Second most recent snapshot
                    
                    # Get previous snapshot items
                    previous_result = await db.execute(
                        select(ConfigurationSnapshot)
                        .where(ConfigurationSnapshot.timestamp == previous.timestamp)
                        .where(ConfigurationSnapshot.category == category)
                    )
                    previous_snapshots = previous_result.scalars().all()
                    
                    # Get latest items
                    latest_result = await db.execute(
                        select(ConfigurationSnapshot)
                        .where(ConfigurationSnapshot.timestamp == latest.timestamp)
                        .where(ConfigurationSnapshot.category == category)
                    )
                    latest_snapshots = latest_result.scalars().all()
                    
                    # Convert latest snapshots to expected format for comparison
                    latest_items = []
                    for snapshot in latest_snapshots:
                        item_data = json.loads(snapshot.value)
                        latest_items.append(item_data)
                    
                    # Compare snapshots
                    # FIX: Added the await keyword here to properly await the coroutine
                    category_reports = await compare_snapshots(previous_snapshots, latest_items)
                    reports.extend(category_reports)

            # Save drift reports
            for report in reports:
                db.add(report)
            await db.commit()

            logger.info(f"Drift detection completed. Found {len(reports)} changes.")

    except Exception as e:
        logger.error(f"Error during drift detection: {str(e)}")