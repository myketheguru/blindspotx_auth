"""
Drift Detection Types
--------------------
This module defines the type system used for drift detection, including
categories, change types, and other related enumerations.
"""

from enum import Enum, auto
from typing import Dict, Any, Optional, List, Union
from pydantic import BaseModel
from datetime import datetime
from uuid import UUID, uuid4


class DriftCategory(str, Enum):
    """Categories of configuration items that can drift."""
    
    # Identity & Access Management
    ROLE = "role"
    USER = "user"
    PERMISSION = "permission"
    
    # Security Configuration
    AUTH_SETTINGS = "auth_settings"
    PASSWORD_POLICY = "password_policy"
    MFA_SETTINGS = "mfa_settings"
    
    # Application Configuration
    APP_SETTINGS = "app_settings"
    API_SETTINGS = "api_settings"
    
    # Infrastructure
    NETWORK = "network"
    FIREWALL = "firewall"
    
    # Other
    CUSTOM = "custom"


class DriftType(str, Enum):
    """Types of drift changes that can occur."""
    
    CREATED = "created"
    DELETED = "deleted"
    MODIFIED = "modified"
    PERMISSION_ADDED = "permission_added"
    PERMISSION_REMOVED = "permission_removed"
    SECURITY_DOWNGRADE = "security_downgrade"
    UNUSUAL_ACTIVITY = "unusual_activity"


class SecurityImpact(str, Enum):
    """Potential security impact of a drift change."""
    
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DriftChange(BaseModel):
    """
    Represents a single detected change in configuration.
    More detailed than the database model, used during processing.
    """
    
    id: UUID = uuid4()
    change_type: DriftType
    category: DriftCategory
    key: str
    path: Optional[str] = None  # For nested changes, the dot-notation path to the changed value
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    security_impact: SecurityImpact = SecurityImpact.NONE
    timestamp: datetime = datetime.utcnow()
    metadata: Dict[str, Any] = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        result = self.dict()
        # Convert non-serializable items to strings
        if self.old_value is not None and not isinstance(self.old_value, (str, int, float, bool, type(None))):
            result["old_value"] = str(self.old_value)
        if self.new_value is not None and not isinstance(self.new_value, (str, int, float, bool, type(None))):
            result["new_value"] = str(self.new_value)
        return result


class DriftResult(BaseModel):
    """Collection of drift changes from a detection run."""
    
    changes: List[DriftChange] = []
    timestamp: datetime = datetime.utcnow()
    total_count: int = 0
    security_changes_count: int = 0
    
    @property
    def changed(self) -> bool:
        """Check if there are any changes detected."""
        return len(self.changes) > 0
    
    @property
    def has_security_changes(self) -> bool:
        """Check if there are any security-related changes."""
        return any(c.security_impact != SecurityImpact.NONE for c in self.changes)
    
    @property
    def high_severity_changes(self) -> List[DriftChange]:
        """Get only high or critical severity changes."""
        return [c for c in self.changes if c.security_impact in 
                (SecurityImpact.HIGH, SecurityImpact.CRITICAL)]

