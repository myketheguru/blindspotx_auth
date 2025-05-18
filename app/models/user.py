from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import EmailStr
from sqlmodel import Field, Relationship, SQLModel, select
from sqlalchemy.ext.asyncio import AsyncSession

class Permission(SQLModel, table=True):
    """Permission model for fine-grained access control"""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(index=True)
    description: Optional[str] = None
    
    # Relationships
    roles: List["RolePermission"] = Relationship(back_populates="permission")

class Role(SQLModel, table=True):
    """Role model for role-based access control"""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(index=True)
    description: Optional[str] = None
    
    # Relationships
    users: List["UserRole"] = Relationship(back_populates="role")
    permissions: List["RolePermission"] = Relationship(back_populates="role")

class RolePermission(SQLModel, table=True):
    """Many-to-many relationship between roles and permissions"""
    role_id: UUID = Field(foreign_key="role.id", primary_key=True)
    permission_id: UUID = Field(foreign_key="permission.id", primary_key=True)
    
    # Relationships
    role: Role = Relationship(back_populates="permissions")
    permission: Permission = Relationship(back_populates="roles")

class UserRole(SQLModel, table=True):
    """Many-to-many relationship between users and roles"""
    user_id: UUID = Field(foreign_key="user.id", primary_key=True)
    role_id: UUID = Field(foreign_key="role.id", primary_key=True)
    
    # Relationships
    user: "User" = Relationship(back_populates="roles")
    role: Role = Relationship(back_populates="users")

class User(SQLModel, table=True):
    """User model for authentication and authorization"""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: EmailStr = Field(unique=True, index=True)
    full_name: Optional[str] = None
    azure_object_id: Optional[str] = Field(unique=True, index=True)
    is_active: bool = True
    is_superuser: bool = False
    
    # Relationships
    roles: List[UserRole] = Relationship(back_populates="user")

# Async functions for user operations
async def get_user_by_email(email: str, db: AsyncSession = None) -> Optional[User]:
    """Get user by email"""
    from app.core.database import async_session
    
    if db is None:
        async with async_session() as db:
            result = await db.execute(select(User).where(User.email == email))
            return result.scalars().first()
    else:
        result = await db.execute(select(User).where(User.email == email))
        return result.scalars().first()

async def get_user_by_azure_id(azure_id: str, db: AsyncSession = None) -> Optional[User]:
    """Get user by Azure Object ID"""
    from app.core.database import async_session
    
    if db is None:
        async with async_session() as db:
            result = await db.execute(select(User).where(User.azure_object_id == azure_id))
            return result.scalars().first()
    else:
        result = await db.execute(select(User).where(User.azure_object_id == azure_id))
        return result.scalars().first()

async def create_user(user_data: dict, db: AsyncSession = None) -> User:
    """Create a new user"""
    from app.core.database import async_session
    
    user = User(**user_data)
    
    if db is None:
        async with async_session() as db:
            db.add(user)
            await db.commit()
            await db.refresh(user)
    else:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    
    return user

async def get_user_permissions(user_id: UUID, db: AsyncSession = None) -> List[str]:
    """Get permissions for a user"""
    from app.core.database import async_session
    
    query = """
    SELECT DISTINCT p.name FROM permission p
    JOIN role_permission rp ON p.id = rp.permission_id
    JOIN role r ON rp.role_id = r.id
    JOIN user_role ur ON r.id = ur.role_id
    WHERE ur.user_id = :user_id
    """
    
    if db is None:
        async with async_session() as db:
            result = await db.execute(query, {"user_id": user_id})
            return [row[0] for row in result.fetchall()]
    else:
        result = await db.execute(query, {"user_id": user_id})
        return [row[0] for row in result.fetchall()]