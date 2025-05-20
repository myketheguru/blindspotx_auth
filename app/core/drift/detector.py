"""
Drift Detection Core Logic
-------------------------
This module contains the core logic for detecting drift in configuration
and security settings, including nested object comparison.
"""

import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional, Set, Union
import copy
from collections import defaultdict

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, delete

from app.core.database import get_db
from app.models.drift import ConfigurationSnapshot, DriftReport
from app.core.drift.types import (
    DriftCategory, DriftType, DriftChange, SecurityImpact, 
    DriftResult
)
from app.core.drift.severity import calculate_severity, determine_security_impact
from app.core.config import settings
from app.api.routes.auth import get_msal_app

logger = logging.getLogger(__name__)

def safe_category_convert(category_str: str) -> DriftCategory:
    """
    Safely convert a string category to a DriftCategory enum.
    
    Args:
        category_str: String representation of the category
        
    Returns:
        DriftCategory enum value
    """
    try:
        if not category_str:
            return DriftCategory.CUSTOM
            
        # Try to convert to uppercase and lookup in enum
        if category_str.upper() in DriftCategory.__members__:
            return DriftCategory[category_str.upper()]
        
        # If we have a string that's already a DriftCategory enum value
        if isinstance(category_str, DriftCategory):
            return category_str
            
        return DriftCategory.CUSTOM
    except Exception as e:
        logger.warning(f"Error converting category '{category_str}': {e}")
        return DriftCategory.CUSTOM


def compare_objects(
    old_obj: Dict[str, Any], 
    new_obj: Dict[str, Any], 
    path: str = "", 
    category: str = "",
    key: str = ""
) -> DriftResult:
    """
    Compare two dictionary objects recursively and identify all differences.
    
    Args:
        old_obj: The original object state
        new_obj: The new object state
        path: Current path in the object (for nested objects)
        category: Category of the object (e.g., 'user', 'role')
        key: Identifier for the object
        
    Returns:
        DriftResult containing all changes detected
    """
    changes = []
    changed_paths = []
    
    # Handle non-dictionary and non-list types
    if not isinstance(old_obj, (dict, list)) or not isinstance(new_obj, (dict, list)):
        # Direct comparison for scalar values
        if old_obj != new_obj:
            current_path = path if path else "root"
            changes.append(DriftChange(
                change_type=DriftType.MODIFIED,
                category=safe_category_convert(category),
                key=key,
                path=current_path,
                old_value=old_obj,
                new_value=new_obj,
                security_impact=determine_security_impact(category, current_path, old_obj, new_obj)
            ))
            changed_paths.append(current_path)
        
        return DriftResult(
            changed=len(changes) > 0,
            changes=changes,
            changed_paths=changed_paths
        )
    
    # Special handling for arrays/lists
    if isinstance(old_obj, list) and isinstance(new_obj, list):
        # If lists are of different lengths, consider it a change
        if len(old_obj) != len(new_obj):
            current_path = path if path else "root"
            changes.append(DriftChange(
                change_type=DriftType.MODIFIED,
                category=safe_category_convert(category),
                key=key,
                path=current_path,
                old_value=f"List with {len(old_obj)} items",
                new_value=f"List with {len(new_obj)} items",
                security_impact=SecurityImpact.UNKNOWN
            ))
            changed_paths.append(current_path)
        
        # For lists of dictionaries with IDs, do smart comparison
        if all(isinstance(x, dict) and 'id' in x for x in old_obj + new_obj if isinstance(x, dict)):
            old_dict = {item.get('id'): item for item in old_obj if isinstance(item, dict) and 'id' in item}
            new_dict = {item.get('id'): item for item in new_obj if isinstance(item, dict) and 'id' in item}
            
            # Check for added items
            for item_key in new_dict:
                if item_key not in old_dict:
                    change_path = f"{path}[{item_key}]" if path else f"[{item_key}]"
                    changes.append(DriftChange(
                        change_type=DriftType.CREATED,
                        category=safe_category_convert(category),
                        key=key,
                        path=change_path,
                        old_value=None,
                        new_value=new_dict[item_key],
                        security_impact=determine_security_impact(
                            category, change_path, None, new_dict[item_key]
                        )
                    ))
                    changed_paths.append(change_path)
                else:
                    # Recursively compare items with the same ID
                    item_path = f"{path}[{item_key}]" if path else f"[{item_key}]"
                    nested_result = compare_objects(
                        old_dict[item_key],
                        new_dict[item_key],
                        item_path,
                        category,
                        key
                    )
                    
                    if nested_result.changed:
                        changes.extend(nested_result.changes)
                        changed_paths.extend(nested_result.changed_paths)
            
            # Check for removed items
            for item_key in old_dict:
                if item_key not in new_dict:
                    change_path = f"{path}[{item_key}]" if path else f"[{item_key}]"
                    changes.append(DriftChange(
                        change_type=DriftType.DELETED,
                        category=safe_category_convert(category),
                        key=key,
                        path=change_path,
                        old_value=old_dict[item_key],
                        new_value=None,
                        security_impact=determine_security_impact(
                            category, change_path, old_dict[item_key], None
                        )
                    ))
                    changed_paths.append(change_path)
                    
        # For simple lists or lists without ID fields, do index-based comparison
        else:
            max_index = max(len(old_obj), len(new_obj))
            for i in range(max_index):
                if i < len(old_obj) and i < len(new_obj):
                    # Both arrays have this index, compare values
                    item_path = f"{path}[{i}]" if path else f"[{i}]"
                    
                    if isinstance(old_obj[i], (dict, list)) and isinstance(new_obj[i], (dict, list)):
                        # Recursive comparison for nested objects/arrays
                        nested_result = compare_objects(
                            old_obj[i],
                            new_obj[i],
                            item_path,
                            category,
                            key
                        )
                        
                        if nested_result.changed:
                            changes.extend(nested_result.changes)
                            changed_paths.extend(nested_result.changed_paths)
                    elif old_obj[i] != new_obj[i]:
                        # Direct comparison for scalar values
                        changes.append(DriftChange(
                            change_type=DriftType.MODIFIED,
                            category=safe_category_convert(category),
                            key=key,
                            path=item_path,
                            old_value=old_obj[i],
                            new_value=new_obj[i],
                            security_impact=determine_security_impact(
                                category, item_path, old_obj[i], new_obj[i]
                            )
                        ))
                        changed_paths.append(item_path)
                
                elif i < len(old_obj):
                    # Item exists in old array but not in new (deleted)
                    item_path = f"{path}[{i}]" if path else f"[{i}]"
                    changes.append(DriftChange(
                        change_type=DriftType.DELETED,
                        category=safe_category_convert(category),
                        key=key,
                        path=item_path,
                        old_value=old_obj[i],
                        new_value=None,
                        security_impact=determine_security_impact(
                            category, item_path, old_obj[i], None
                        )
                    ))
                    changed_paths.append(item_path)
                
                elif i < len(new_obj):
                    # Item exists in new array but not in old (created)
                    item_path = f"{path}[{i}]" if path else f"[{i}]"
                    changes.append(DriftChange(
                        change_type=DriftType.CREATED,
                        category=safe_category_convert(category),
                        key=key,
                        path=item_path,
                        old_value=None,
                        new_value=new_obj[i],
                        security_impact=determine_security_impact(
                            category, item_path, None, new_obj[i]
                        )
                    ))
                    changed_paths.append(item_path)
        
        return DriftResult(
            changed=len(changes) > 0,
            changes=changes,
            changed_paths=changed_paths
        )
    
    # Handle dictionary objects
    if isinstance(old_obj, dict) and isinstance(new_obj, dict):
        # Get all keys from both objects
        all_keys = set(old_obj.keys()) | set(new_obj.keys())
        
        # Check each key for differences
        for k in all_keys:
            key_path = f"{path}.{k}" if path else k
            
            if k in old_obj and k in new_obj:
                # Key exists in both objects, compare values
                if isinstance(old_obj[k], (dict, list)) and isinstance(new_obj[k], (dict, list)):
                    # Recursive comparison for nested objects
                    nested_result = compare_objects(
                        old_obj[k],
                        new_obj[k],
                        key_path,
                        category,
                        key
                    )
                    
                    if nested_result.changed:
                        changes.extend(nested_result.changes)
                        changed_paths.extend(nested_result.changed_paths)
                
                elif old_obj[k] != new_obj[k]:
                    # Direct comparison for scalar values
                    changes.append(DriftChange(
                        change_type=DriftType.MODIFIED,
                        category=safe_category_convert(category),
                        key=key,
                        path=key_path,
                        old_value=old_obj[k],
                        new_value=new_obj[k],
                        security_impact=determine_security_impact(
                            category, key_path, old_obj[k], new_obj[k]
                        )
                    ))
                    changed_paths.append(key_path)
            
            elif k in old_obj:
                # Key exists in old object but not in new (deleted)
                changes.append(DriftChange(
                    change_type=DriftType.DELETED,
                    category=safe_category_convert(category),
                    key=key,
                    path=key_path,
                    old_value=old_obj[k],
                    new_value=None,
                    security_impact=determine_security_impact(
                        category, key_path, old_obj[k], None
                    )
                ))
                changed_paths.append(key_path)
            
            elif k in new_obj:
                # Key exists in new object but not in old (created)
                changes.append(DriftChange(
                    change_type=DriftType.CREATED,
                    category=safe_category_convert(category),
                    key=key,
                    path=key_path,
                    old_value=None,
                    new_value=new_obj[k],
                    security_impact=determine_security_impact(
                        category, key_path, None, new_obj[k]
                    )
                ))
                changed_paths.append(key_path)
    
    return DriftResult(
        changed=len(changes) > 0,
        changes=changes,
        changed_paths=changed_paths
    )


async def analyze_drift_changes(changes: List[DriftChange]) -> Dict[str, Any]:
    """
    Analyze drift changes to extract useful metrics and patterns
    
    Args:
        changes: List of detected drift changes
        
    Returns:
        Dictionary of analysis results
    """
    if not changes:
        return {
            "total_changes": 0,
            "has_critical_changes": False,
            "security_impact_counts": {},
            "change_type_counts": {},
            "affected_paths": [],
            "categories_affected": [],
            "most_changed_category": None,
            "critical_changes": [],
            "patterns_detected": []
        }
    
    # Initialize counters and collections
    security_impact_counts = defaultdict(int)
    change_type_counts = defaultdict(int)
    categories_affected = set()
    category_counts = defaultdict(int)
    affected_paths = []
    critical_changes = []
    patterns = []
    
    # Analyze each change
    for change in changes:
        # Count by security impact
        impact = change.security_impact
        security_impact_counts[impact] += 1
        
        # Count by change type
        change_type = change.change_type
        change_type_counts[change_type] += 1
        
        # Track categories affected
        category = change.category
        categories_affected.add(category)
        category_counts[category] += 1
        
        # Track affected paths
        affected_paths.append(change.path)
        
        # Identify critical changes
        if impact in [
            SecurityImpact.CRITICAL_SECURITY_REMOVED,
            SecurityImpact.ADMIN_RIGHTS_GRANTED,
            SecurityImpact.PERMISSION_ESCALATION
        ]:
            critical_changes.append({
                "path": change.path,
                "category": category,
                "impact": impact,
                "type": change_type
            })
    
    # Detect patterns
    if len(changes) > 3:
        # Pattern: Many changes in a short time
        patterns.append({
            "pattern": "high_volume_changes",
            "description": f"High volume of changes detected ({len(changes)} changes)",
            "severity": "medium"
        })
        
    # Pattern: Multiple security-related changes
    security_changes = security_impact_counts.get(SecurityImpact.SECURITY_WEAKENED, 0)
    if security_changes > 1:
        patterns.append({
            "pattern": "multiple_security_weakening",
            "description": f"Multiple security weakening changes detected ({security_changes})",
            "severity": "high"
        })
        
    # Pattern: Admin right changes
    admin_changes = security_impact_counts.get(SecurityImpact.ADMIN_RIGHTS_GRANTED, 0)
    if admin_changes > 0:
        patterns.append({
            "pattern": "admin_rights_changes",
            "description": "Administrative privilege changes detected",
            "severity": "critical"
        })
        
    # Pattern: Critical category changes
    critical_categories = [
        c for c in categories_affected 
        if c in [
            DriftCategory.AUTH_SETTINGS, 
            DriftCategory.MFA_SETTINGS, 
            DriftCategory.PASSWORD_POLICY
        ]
    ]
    if critical_categories:
        patterns.append({
            "pattern": "critical_category_changes",
            "description": f"Changes to critical security categories: {', '.join(critical_categories)}",
            "severity": "high"
        })
    
    # Find most changed category
    most_changed_category = max(category_counts.items(), key=lambda x: x[1])[0] if category_counts else None
    
    # Compile results
    return {
        "total_changes": len(changes),
        "has_critical_changes": len(critical_changes) > 0,
        "security_impact_counts": dict(security_impact_counts),
        "change_type_counts": dict(change_type_counts),
        "affected_paths": affected_paths,
        "categories_affected": list(categories_affected),
        "most_changed_category": most_changed_category,
        "critical_changes": critical_changes,
        "patterns_detected": patterns
    }


async def detect_unusual_patterns(
    changes: List[DriftChange],
    recent_reports: List[DriftReport] = None
) -> List[Dict[str, Any]]:
    """
    Detect unusual patterns in drift changes that might indicate security issues
    
    Args:
        changes: Current list of detected drift changes
        recent_reports: Recent drift reports for historical comparison
        
    Returns:
        List of detected patterns with descriptions and severity
    """
    patterns = []
    
    if not changes:
        return patterns
    
    # Check for patterns within current changes
    
    # 1. Large number of simultaneous changes
    if len(changes) > 10:
        patterns.append({
            "pattern": "high_volume_changes",
            "description": f"Unusually high number of changes ({len(changes)}) detected at once",
            "severity": "medium",
            "recommendation": "Review all changes carefully as this could indicate a bulk modification"
        })
    
    # 2. Multiple security-weakening changes
    security_weakening = [c for c in changes if c.security_impact == SecurityImpact.SECURITY_WEAKENED]
    if len(security_weakening) > 2:
        patterns.append({
            "pattern": "multiple_security_weakening",
            "description": f"Multiple security-weakening changes ({len(security_weakening)}) detected",
            "severity": "high",
            "recommendation": "Investigate why multiple security controls are being weakened simultaneously"
        })
    
    # 3. Changes across multiple critical categories
    categories = {c.category for c in changes}
    critical_categories = {
        DriftCategory.AUTH_SETTINGS, 
        DriftCategory.PASSWORD_POLICY,
        DriftCategory.MFA_SETTINGS,
        DriftCategory.FIREWALL
    }
    overlapping = categories.intersection(critical_categories)
    if len(overlapping) > 1:
        patterns.append({
            "pattern": "multiple_critical_categories",
            "description": f"Changes across multiple critical categories: {', '.join(overlapping)}",
            "severity": "critical",
            "recommendation": "Review changes immediately as they affect multiple security domains"
        })
    
    # 4. Admin rights granted
    admin_changes = [c for c in changes if c.security_impact == SecurityImpact.ADMIN_RIGHTS_GRANTED]
    if admin_changes:
        patterns.append({
            "pattern": "admin_rights_granted",
            "description": f"Administrative privileges granted ({len(admin_changes)} changes)",
            "severity": "critical",
            "recommendation": "Verify these privilege escalations are authorized"
        })
    
    # 5. Sequential pattern detection if historical data provided
    if recent_reports:
        # Look for stepwise weakening (multiple small changes over time)
        recent_paths = {r.path for r in recent_reports if r.security_impact == SecurityImpact.SECURITY_WEAKENED}
        current_paths = {c.path for c in security_weakening}
        
        if recent_paths and current_paths and recent_paths != current_paths:
            patterns.append({
                "pattern": "sequential_weakening",
                "description": "Sequential security weakening detected across multiple reports",
                "severity": "high",
                "recommendation": "Review recent security changes for potential coordinated weakening"
            })
    
    return patterns


async def calculate_drift_analytics(
    session: AsyncSession,
    time_window_days: int = 30
) -> Dict[str, Any]:
    """
    Calculate comprehensive analytics for drift detection
    
    Args:
        session: Database session
        time_window_days: Time window for analytics in days
        
    Returns:
        Dictionary with analytics data
    """
    from sqlalchemy import func
    from datetime import datetime, timedelta
    
    # Calculate time window
    end_time = datetime.now()
    start_time = end_time - timedelta(days=time_window_days)
    
    # Initialize results
    results = {
        "total_reports": 0,
        "reports_by_severity": {},
        "reports_by_category": {},
        "reports_by_change_type": {},
        "security_impact_distribution": {},
        "trend_data": [],
        "critical_findings": [],
        "unresolved_critical_count": 0,
    }
    
    try:
        # Get total reports in time window
        count_result = await session.execute(
            select(func.count(DriftReport.id))
            .where(DriftReport.timestamp >= start_time)
        )
        results["total_reports"] = count_result.scalar_one() or 0
        
        # Reports by severity
        severity_result = await session.execute(
            select(DriftReport.severity, func.count(DriftReport.id))
            .where(DriftReport.timestamp >= start_time)
            .group_by(DriftReport.severity)
        )
        results["reports_by_severity"] = {str(s): c for s, c in severity_result.all()}
        
        # Reports by category
        category_result = await session.execute(
            select(DriftReport.category, func.count(DriftReport.id))
            .where(DriftReport.timestamp >= start_time)
            .group_by(DriftReport.category)
        )
        results["reports_by_category"] = {c: count for c, count in category_result.all()}
        
        # Reports by change type
        change_type_result = await session.execute(
            select(DriftReport.change_type, func.count(DriftReport.id))
            .where(DriftReport.timestamp >= start_time)
            .group_by(DriftReport.change_type)
        )
        results["reports_by_change_type"] = {ct: count for ct, count in change_type_result.all()}
        
        # Security impact distribution
        security_impact_result = await session.execute(
            select(DriftReport.security_impact, func.count(DriftReport.id))
            .where(DriftReport.timestamp >= start_time)
            .group_by(DriftReport.security_impact)
        )
        results["security_impact_distribution"] = {
            str(si): count for si, count in security_impact_result.all()
        }
        
        # Trend data: Generate daily counts for the time period
        # Create a list of dates in the time window
        dates = []
        current_date = start_time.date()
        end_date = end_time.date()
        
        while current_date <= end_date:
            dates.append(current_date)
            current_date += timedelta(days=1)
        
        # Collect trend data for each date
        trend_data = []
        
        for date in dates:
            date_start = datetime.combine(date, datetime.min.time())
            date_end = datetime.combine(date, datetime.max.time())
            
            # Get total count for the day
            day_count_result = await session.execute(
                select(func.count(DriftReport.id))
                .where(DriftReport.timestamp >= date_start)
                .where(DriftReport.timestamp <= date_end)
            )
            total_count = day_count_result.scalar_one() or 0
            
            # Skip days with no activity to reduce noise
            if total_count == 0:
                continue
                
            # Get severity distribution for this day
            severity_result = await session.execute(
                select(DriftReport.severity, func.count(DriftReport.id))
                .where(DriftReport.timestamp >= date_start)
                .where(DriftReport.timestamp <= date_end)
                .group_by(DriftReport.severity)
            )
            severity_counts = {str(s): c for s, c in severity_result.all()}
            
            # Get security impact distribution for this day
            security_result = await session.execute(
                select(DriftReport.security_impact, func.count(DriftReport.id))
                .where(DriftReport.timestamp >= date_start)
                .where(DriftReport.timestamp <= date_end)
                .group_by(DriftReport.security_impact)
            )
            security_impact_counts = {str(si): c for si, c in security_result.all()}
            
            # Get categories affected on this day
            category_result = await session.execute(
                select(DriftReport.category, func.count(DriftReport.id))
                .where(DriftReport.timestamp >= date_start)
                .where(DriftReport.timestamp <= date_end)
                .group_by(DriftReport.category)
            )
            category_counts = {c: count for c, count in category_result.all()}
            
            # Compile trend data for this day
            trend_data.append({
                "date": date.isoformat(),
                "total_count": total_count,
                "severity_counts": severity_counts,
                "security_impact_counts": security_impact_counts,
                "category_counts": category_counts
            })
        
        # Add trend data to results
        results["trend_data"] = trend_data
        
        # Critical findings tracking: Get details of critical and high severity reports
        critical_findings_result = await session.execute(
            select(DriftReport)
            .where(DriftReport.timestamp >= start_time)
            .where(DriftReport.severity.in_(["critical", "high"]))
            .order_by(DriftReport.timestamp.desc())
            .limit(20)  # Limit to most recent 20 critical/high findings
        )
        critical_reports = critical_findings_result.scalars().all()
        
        # Format critical findings for easier consumption
        critical_findings = []
        for report in critical_reports:
            # Parse old and new values if available
            old_value_dict = {}
            new_value_dict = {}
            
            if report.old_value:
                try:
                    old_value_dict = json.loads(report.old_value)
                except (json.JSONDecodeError, TypeError):
                    old_value_dict = {"value": str(report.old_value)}
            
            if report.new_value:
                try:
                    new_value_dict = json.loads(report.new_value)
                except (json.JSONDecodeError, TypeError):
                    new_value_dict = {"value": str(report.new_value)}
            
            # Create a summary of the change
            change_summary = f"{report.change_type.capitalize()} in {report.category}"
            if hasattr(report, "changed_fields") and report.changed_fields:
                fields_list = report.changed_fields[:3]  # Take first 3 fields
                fields_str = ", ".join(fields_list)
                if len(report.changed_fields) > 3:
                    fields_str += f" and {len(report.changed_fields) - 3} more"
                change_summary += f" - Fields: {fields_str}"
            
            # Add to critical findings list
            critical_findings.append({
                "id": str(report.id),
                "timestamp": report.timestamp.isoformat() if report.timestamp else None,
                "category": report.category,
                "change_type": report.change_type,
                "severity": str(report.severity),
                "security_impact": str(report.security_impact),
                "status": str(report.status),
                "summary": change_summary,
                "is_resolved": report.status in ["resolved", "acknowledged"],
                "affected_components": report.affected_components if hasattr(report, "affected_components") else []
            })
        
        results["critical_findings"] = critical_findings
        
        # Count of unresolved critical issues
        unresolved_critical_result = await session.execute(
            select(func.count(DriftReport.id))
            .where(DriftReport.timestamp >= start_time)
            .where(DriftReport.severity.in_(["critical", "high"]))
            .where(DriftReport.status.not_in(["resolved", "acknowledged"]))
        )
        results["unresolved_critical_count"] = unresolved_critical_result.scalar_one() or 0
        
        # Historical pattern analysis
        # 1. Calculate average daily change rate
        if trend_data:
            daily_counts = [day["total_count"] for day in trend_data]
            avg_daily_changes = sum(daily_counts) / len(daily_counts)
            
            # Identify days with unusually high activity (3x average)
            high_activity_days = [
                day["date"] for day in trend_data
                if day["total_count"] > avg_daily_changes * 3 and day["total_count"] > 5
            ]
            
            results["high_activity_days"] = high_activity_days
            results["avg_daily_changes"] = avg_daily_changes
        else:
            results["high_activity_days"] = []
            results["avg_daily_changes"] = 0
        
        # 2. Most frequently changed categories
        if results["reports_by_category"]:
            sorted_categories = sorted(
                results["reports_by_category"].items(), 
                key=lambda x: x[1], 
                reverse=True
            )
            results["most_changed_categories"] = [
                {"category": category, "count": count} 
                for category, count in sorted_categories[:3]
            ]
        else:
            results["most_changed_categories"] = []
        
        # 3. Security-focused analysis
        security_related_changes = 0
        for impact, count in results["security_impact_distribution"].items():
            if impact.lower() in ["security_weakened", "permission_escalation", "admin_rights_granted", "critical_security_removed"]:
                security_related_changes += count
        
        results["security_related_changes"] = security_related_changes
        results["security_related_percentage"] = (
            (security_related_changes / results["total_reports"]) * 100 
            if results["total_reports"] > 0 else 0
        )
        
        # Generate insights based on the analytics
        insights = []
        
        # Insight 1: Security posture changes
        if security_related_changes > 0:
            insights.append({
                "type": "security_posture",
                "severity": "high" if security_related_changes > 3 else "medium",
                "message": f"Detected {security_related_changes} security-related changes in the last {time_window_days} days",
                "recommendation": "Review security-related changes to ensure they are authorized"
            })
        
        # Insight 2: Unusual activity volume
        if results["high_activity_days"]:
            insights.append({
                "type": "unusual_activity",
                "severity": "medium",
                "message": f"Detected {len(results['high_activity_days'])} days with unusually high change volume",
                "recommendation": "Investigate these days for potential unauthorized batch changes"
            })
        
        # Insight 3: Unresolved critical issues
        if results["unresolved_critical_count"] > 0:
            insights.append({
                "type": "unresolved_issues",
                "severity": "high",
                "message": f"{results['unresolved_critical_count']} critical or high severity issues remain unresolved",
                "recommendation": "Prioritize review and resolution of these issues"
            })
        
        # Add insights to results
        results["insights"] = insights
        
        logger.info(f"Drift analytics calculated for {time_window_days}-day period with {results['total_reports']} reports")
        
    except Exception as e:
        logger.error(f"Error calculating drift analytics: {str(e)}")
        # Return partial results if available, or empty structure on complete failure
        
    return results
