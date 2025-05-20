from typing import List, Optional, Dict, Any, TYPE_CHECKING
from sqlmodel import SQLModel, Field
from sqlalchemy import JSON
from uuid import UUID, uuid4
from datetime import datetime
from enum import Enum, auto

class ValidationStatus(str, Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"

class RetentionPolicy(str, Enum):
    SHORT_TERM = "short_term"  # e.g., 30 days
    MEDIUM_TERM = "medium_term"  # e.g., 90 days
    LONG_TERM = "long_term"  # e.g., 1 year
    PERMANENT = "permanent"  # never delete

class ConfigurationSnapshot(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    category: str = Field(index=True)  # e.g., "role", "user"
    key: str = Field(index=True)       # unique identifier (role.id, user.email)
    value: str                          # JSON string of config
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # New fields
    batch_id: Optional[UUID] = Field(default=None, index=True)  # For grouping related snapshots
    config_metadata: Optional[Dict[str, Any]] = Field(default=None, sa_type=JSON)  # Additional context as JSON
    retention_policy: RetentionPolicy = Field(default=RetentionPolicy.MEDIUM_TERM)
    validation_status: ValidationStatus = Field(default=ValidationStatus.PENDING)
    hash: Optional[str] = Field(default=None)  # Hash of configuration for quick comparison
    created_by: Optional[str] = Field(default=None)  # User or system that created the snapshot

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DriftStatus(str, Enum):
    DETECTED = "detected"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    IGNORED = "ignored"

class DriftReport(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    change_type: str  # "created", "updated", "deleted"
    category: str     # "role", "user", etc.
    key: str          # role ID or user email
    old_value: Optional[str]
    new_value: Optional[str]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # New fields
    severity: Severity = Field(default=Severity.MEDIUM)
    status: DriftStatus = Field(default=DriftStatus.DETECTED)
    description: Optional[str] = Field(default=None)
    security_impact: Optional[str] = Field(default=None)
    affected_components: Optional[List[str]] = Field(default=None, sa_type=JSON)
    batch_id: Optional[UUID] = Field(default=None, index=True)
    resolution_notes: Optional[str] = Field(default=None)
    resolved_by: Optional[str] = Field(default=None)
    resolved_at: Optional[datetime] = Field(default=None)
    created_by: Optional[str] = Field(default=None)  # User or system that detected the drift
