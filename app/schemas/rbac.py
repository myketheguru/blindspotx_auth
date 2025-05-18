from pydantic import BaseModel
from uuid import UUID
from typing import Optional

class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None


class RoleUpdate(BaseModel):
    name: Optional[str]
    description: Optional[str]


class PermissionCreate(BaseModel):
    name: str
    description: Optional[str]