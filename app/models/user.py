from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import EmailStr
from sqlmodel import Field, Relationship, SQLModel, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, and_, func


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


# --- Async functions for user operations ---

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
    """Get permissions for a user using ORM-style query"""
    from app.core.database import async_session

    stmt = (
        select(Permission.name)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .join(Role, RolePermission.role_id == Role.id)
        .join(UserRole, Role.id == UserRole.role_id)
        .where(UserRole.user_id == user_id)
        .distinct()
    )

    if db is None:
        async with async_session() as session:
            result = await session.execute(stmt)
    else:
        result = await db.execute(stmt)

    return [row[0] for row in result]