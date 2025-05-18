from typing import List, Optional
from sqlmodel import SQLModel, Field
from uuid import UUID, uuid4
from datetime import datetime

class ConfigurationSnapshot(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    category: str = Field(index=True)  # e.g., "role", "user"
    key: str = Field(index=True)       # unique identifier (role.id, user.email)
    value: str                          # JSON string of config
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class DriftReport(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    change_type: str  # "created", "updated", "deleted"
    category: str     # "role", "user", etc.
    key: str          # role ID or user email
    old_value: Optional[str]
    new_value: Optional[str]
    timestamp: datetime = Field(default_factory=datetime.utcnow)