# app/services/drift_service.py
import asyncio
import logging
import json
from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.drift import ConfigurationSnapshot, DriftReport
from app.core.database import get_db
from app.api.routes.auth import get_msal_app
import httpx
from sqlmodel import select, delete
from app.core.config import settings

logger = logging.getLogger(__name__)

async def fetch_graph_data(access_token: str, endpoint: str) -> List[Dict]:
    """Fetch data from Microsoft Graph API"""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://graph.microsoft.com/v1.0/ {endpoint}",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if response.status_code == 200:
            return response.json().get("value", [])
        else:
            logger.warning(f"Failed to fetch from Graph API ({endpoint}): {response.text}")
            return []

async def save_snapshot(session: AsyncSession, category: str, items: List[Dict]):
    """Save current state of a category (roles, users)"""
    for item in items:
        snapshot = ConfigurationSnapshot(
            category=category,
            key=item["id"],
            value=json.dumps(item)
        )
        session.add(snapshot)
    await session.commit()

def compare_snapshots(
    old_snapshots: List[ConfigurationSnapshot],
    new_snapshots: List[Dict]
) -> List[DriftReport]:
    """Compare old and new snapshots to detect drift"""
    old_dict = {s.key: json.loads(s.value) for s in old_snapshots}
    new_dict = {item["id"]: item for item in new_snapshots}

    reports = []

    # Check for created/deleted/updated
    for key in new_dict:
        if key not in old_dict:
            reports.append(DriftReport(
                change_type="created",
                category=new_dict[key]["category"],
                key=key,
                new_value=json.dumps(new_dict[key])
            ))

    for key in old_dict:
        if key not in new_dict:
            reports.append(DriftReport(
                change_type="deleted",
                category=old_dict[key].get("category"),
                key=key,
                old_value=json.dumps(old_dict[key])
            ))
        else:
            old_val = old_dict[key]
            new_val = new_dict[key]
            if old_val != new_val:
                reports.append(DriftReport(
                    change_type="modified",
                    category=old_val.get("category"),
                    key=key,
                    old_value=json.dumps(old_val),
                    new_value=json.dumps(new_val)
                ))

    return reports

async def detect_drift():
    """Main function to detect drift in Azure AD roles/users"""
    logger.info("Starting drift detection job")

    try:
        # Get token silently
        msal_app = get_msal_app()
        result = msal_app.acquire_token_silent(scopes=settings.MS_SCOPES, account=None)

        if not result:
            logger.warning("No cached token found for silent auth")
            # Optionally fallback to client credentials flow or alert
            return 

        access_token = result.get("access_token")
        if not access_token:
            logger.warning("Could not retrieve access token for drift detection")
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
                    select(ConfigurationSnapshot).where(ConfigurationSnapshot.category == category)
                )
                snapshots = result.scalars().all()
                if len(snapshots) >= 2:
                    latest = snapshots[-1]
                    previous = snapshots[-2]
                    new_items = [json.loads(x.value) for x in snapshots if x.id == latest.id]
                    old_items = [json.loads(x.value) for x in snapshots if x.id == previous.id]
                    reports.extend(compare_snapshots(old_items, new_items))

            # Save drift reports
            for report in reports:
                db.add(report)
            await db.commit()

            logger.info(f"Drift detection completed. Found {len(reports)} changes.")

    except Exception as e:
        logger.error(f"Error during drift detection: {str(e)}")