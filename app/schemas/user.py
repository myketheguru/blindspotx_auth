from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

class PermissionBase(BaseModel):
    name: str
    description: Optional[str] = None

class PermissionCreate(PermissionBase):
    pass

class Permission(PermissionBase):
    id: UUID
    
    class Config:
        from_attributes = True

class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None

class RoleCreate(RoleBase):
    permissions: List[str] = []

class Role(RoleBase):
    id: UUID
    permissions: List[Permission] = []
    
    class Config:
        from_attributes = True

class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool = True
    azure_object_id: Optional[str] = None

class UserCreate(UserBase):
    roles: List[str] = []

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    roles: Optional[List[str]] = None

class User(UserBase):
    id: UUID
    is_superuser: bool = False
    roles: List[Role] = []
    
    class Config:
        from_attributes = True

class UserInDB(User):
    pass