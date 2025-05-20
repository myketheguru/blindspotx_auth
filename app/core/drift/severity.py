"""
Drift Severity


Drift Severity Classification
----------------------------
This module provides functionality to classify the severity of detected
drift based on the type of change, the affected resource, and security impact.

The severity classification helps prioritize responses to detected changes.
"""

from enum import Enum, auto
from typing import Dict, Any, List, Optional
import re

from app.core.drift.types import DriftChange, DriftCategory, DriftType, SecurityImpact


class SeverityLevel(str, Enum):
    """Severity levels for drift detection."""
    
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Security-sensitive fields that should trigger higher severity
SECURITY_SENSITIVE_FIELDS = [
    "password", "secret", "key", "token", "auth", "permission", "admin", "role",
    "access", "mfa", "2fa", "firewall", "security", "encrypt", "certificate",
    "crypt", "ssl", "tls", "private", "sudo", "root", "privilege"
]

# Regular expressions for detecting sensitive patterns
SENSITIVE_PATTERNS = [
    re.compile(r"passw(or)?d", re.IGNORECASE),
    re.compile(r"secur(e|ity)", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"admin", re.IGNORECASE),
    re.compile(r"root", re.IGNORECASE),
    re.compile(r"key", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"cert(ificate)?", re.IGNORECASE),
    re.compile(r"access", re.IGNORECASE),
]

# Mapping of categories to their base security impact
CATEGORY_SECURITY_IMPACT = {
    DriftCategory.ROLE: SecurityImpact.MEDIUM,
    DriftCategory.USER: SecurityImpact.LOW,
    DriftCategory.PERMISSION: SecurityImpact.HIGH,
    DriftCategory.AUTH_SETTINGS: SecurityImpact.HIGH,
    DriftCategory.PASSWORD_POLICY: SecurityImpact.HIGH,
    DriftCategory.MFA_SETTINGS: SecurityImpact.HIGH,
    DriftCategory.APP_SETTINGS: SecurityImpact.LOW,
    DriftCategory.API_SETTINGS: SecurityImpact.MEDIUM,
    DriftCategory.NETWORK: SecurityImpact.MEDIUM,
    DriftCategory.FIREWALL: SecurityImpact.HIGH,
    DriftCategory.CUSTOM: SecurityImpact.LOW,
}

# Mapping of change types to their severity adjustment
CHANGE_TYPE_SEVERITY_MODIFIER = {
    DriftType.CREATED: 0,  # No adjustment
    DriftType.DELETED: 1,   # Increase by 1 level
    DriftType.MODIFIED: 0,  # No adjustment
    DriftType.PERMISSION_ADDED: 1,  # Increase by 1 level
    DriftType.PERMISSION_REMOVED: 0,  # No adjustment
    DriftType.SECURITY_DOWNGRADE: 2,  # Increase by 2 levels
    DriftType.UNUSUAL_ACTIVITY: 1,  # Increase by 1 level
}


def is_sensitive_field(field_name: str) -> bool:
    """
    Determine if a field name is security-sensitive.
    
    Args:
        field_name: The name of the field to check
        
    Returns:
        True if the field is considered security-sensitive
    """
    # Direct match with known sensitive fields
    if any(sensitive in field_name.lower() for sensitive in SECURITY_SENSITIVE_FIELDS):
        return True
    
    # Regex pattern match
    return any(pattern.search(field_name) for pattern in SENSITIVE_PATTERNS)


def determine_security_impact(
    change: DriftChange, 
    field_path: Optional[str] = None
) -> SecurityImpact:
    """
    Determine the security impact of a change.
    
    Args:
        change: The drift change to evaluate
        field_path: Optional dot-notation path to the specific field
        
    Returns:
        SecurityImpact level
    """
    # Start with the base impact for the category
    base_impact = CATEGORY_SECURITY_IMPACT.get(
        change.category, SecurityImpact.LOW
    )
    
    # Convert string-based impact to numeric for easier calculation
    impact_map = {
        SecurityImpact.NONE: 0,
        SecurityImpact.LOW: 1, 
        SecurityImpact.MEDIUM: 2,
        SecurityImpact.HIGH: 3,
        SecurityImpact.CRITICAL: 4
    }
    impact_level = impact_map[base_impact]
    
    # Adjust based on the change type
    impact_level += CHANGE_TYPE_SEVERITY_MODIFIER.get(change.change_type, 0)
    
    # Check field sensitivity if we have a path
    if field_path:
        field_parts = field_path.split('.')
        # Check the last part which is the actual field name
        if field_parts and is_sensitive_field(field_parts[-1]):
            impact_level += 1
    
    # Specific checks for security downgrades
    if (change.change_type == DriftType.MODIFIED and 
        change.category in (DriftCategory.AUTH_SETTINGS, DriftCategory.PASSWORD_POLICY, 
                           DriftCategory.MFA_SETTINGS, DriftCategory.FIREWALL)):
        # Security settings were modified, check if it's a downgrade
        # This would need application-specific logic but here's a simplified version
        if isinstance(change.old_value, dict) and isinstance(change.new_value, dict):
            # Example: detect if password complexity was reduced
            if (change.old_value.get('requiresUppercase', True) is True and 
                change.new_value.get('requiresUppercase', True) is False):
                impact_level += 1
            
            # Example: detect if MFA was disabled
            if (change.old_value.get('mfaEnabled', True) is True and 
                change.new_value.get('mfaEnabled', True) is False):
                impact_level += 2  # Major security downgrade
    
    # Cap at the maximum level
    impact_level = min(impact_level, 4)
    
    # Convert back to enum
    reverse_map = {v: k for k, v in impact_map.items()}
    return reverse_map[impact_level]


def calculate_severity(change: DriftChange) -> SeverityLevel:
    """
    Calculate the severity level of a detected drift change.
    
    Args:
        change: The drift change to evaluate
        
    Returns:
        SeverityLevel indicating how severe the change is
    """
    # Map security impact to severity level
    impact_to_severity = {
        SecurityImpact.NONE: SeverityLevel.INFO,
        SecurityImpact.LOW: SeverityLevel.LOW,
        SecurityImpact.MEDIUM: SeverityLevel.MEDIUM,
        SecurityImpact.HIGH: SeverityLevel.HIGH,
        SecurityImpact.CRITICAL: SeverityLevel.CRITICAL
    }
    
    # Get the security impact
    security_impact = determine_security_impact(change, change.path)
    
    # Further adjust severity based on additional rules if needed
    # Example: elevate severity for admin role changes
    if (change.category == DriftCategory.ROLE and 
        "admin" in change.key.lower() and 
        security_impact != SecurityImpact.CRITICAL):
        # Bump up one level for admin role changes
        impact_index = list(impact_to_severity.keys()).index(security_impact)
        security_impact = list(impact_to_severity.keys())[min(impact_index + 1, 4)]
    
    # Map to severity level
    return impact_to_severity[security_impact]

