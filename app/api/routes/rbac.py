from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, delete
from typing import List
from uuid import UUID

from app.core.database import get_db
from app.core.security import get_current_user, verify_permission
from app.models.user import User, Permission, Role, RolePermission, UserRole
from app.schemas.rbac import RoleCreate, RoleUpdate, PermissionCreate


router = APIRouter()


# ================== #
# 🧑‍💼 ROLE MANAGEMENT
# ================== #

@router.post("/roles", response_model=Role, dependencies=[Depends(verify_permission("create:roles"))])
async def create_role(
    role: RoleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new role"""
    db_role = Role(**role.dict())
    db.add(db_role)
    await db.commit()
    await db.refresh(db_role)
    return db_role


@router.get("/roles", response_model=List[Role], dependencies=[Depends(verify_permission("read:roles"))])
async def list_roles(db: AsyncSession = Depends(get_db)):
    """Get all roles"""
    result = await db.execute(select(Role))
    return result.scalars().all()


@router.put("/roles/{role_id}", response_model=Role, dependencies=[Depends(verify_permission("update:roles"))])
async def update_role(
    role_id: UUID,
    role_update: RoleUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update an existing role"""
    result = await db.execute(select(Role).where(Role.id == role_id))
    db_role = result.scalars().first()
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")

    for key, value in role_update.dict(exclude_unset=True).items():
        setattr(db_role, key, value)

    await db.commit()
    await db.refresh(db_role)
    return db_role


@router.delete("/roles/{role_id}", dependencies=[Depends(verify_permission("delete:roles"))])
async def delete_role(
    role_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Delete a role by ID"""
    result = await db.execute(select(Role).where(Role.id == role_id))
    db_role = result.scalars().first()
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")

    await db.delete(db_role)
    await db.commit()
    return {"message": f"Role {db_role.name} deleted successfully"}


# ======================= #
# 🔐 PERMISSION MANAGEMENT
# ======================= #

@router.post("/permissions", response_model=Permission, dependencies=[Depends(verify_permission("create:permissions"))])
async def create_permission(
    permission: PermissionCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new permission"""
    db_perm = Permission(**permission.dict())
    db.add(db_perm)
    await db.commit()
    await db.refresh(db_perm)
    return db_perm


@router.get("/permissions", response_model=List[Permission], dependencies=[Depends(verify_permission("read:permissions"))])
async def list_permissions(db: AsyncSession = Depends(get_db)):
    """Get all permissions"""
    result = await db.execute(select(Permission))
    return result.scalars().all()


# ==================================== #
# 🔗 ASSIGN PERMISSIONS TO ROLES
# ==================================== #

@router.post("/roles/{role_id}/permissions/{permission_id}", dependencies=[Depends(verify_permission("assign:permissions"))])
async def assign_permission_to_role(
    role_id: UUID,
    permission_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Assign a permission to a role"""
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalars().first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    result = await db.execute(select(Permission).where(Permission.id == permission_id))
    perm = result.scalars().first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Check if already assigned
    result = await db.execute(
        select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id
        )
    )
    existing = result.scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail="Permission already assigned to role")

    role_perm = RolePermission(role_id=role_id, permission_id=permission_id)
    db.add(role_perm)
    await db.commit()
    return {"message": "Permission assigned to role"}


@router.delete("/roles/{role_id}/permissions/{permission_id}", dependencies=[Depends(verify_permission("assign:permissions"))])
async def remove_permission_from_role(
    role_id: UUID,
    permission_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Remove a permission from a role"""
    result = await db.execute(
        select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id
        )
    )
    role_perm = result.scalars().first()
    if not role_perm:
        raise HTTPException(status_code=404, detail="Permission not assigned to role")

    await db.delete(role_perm)
    await db.commit()
    return {"message": "Permission removed from role"}


# ============================= #
# 👥 ASSIGN ROLES TO USERS
# ============================= #

@router.post("/users/{user_id}/roles/{role_id}", dependencies=[Depends(verify_permission("assign:roles"))])
async def assign_role_to_user(
    user_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Assign a role to a user"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalars().first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    # Check if already assigned
    result = await db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id
        )
    )
    existing = result.scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail="Role already assigned to user")

    user_role = UserRole(user_id=user_id, role_id=role_id)
    db.add(user_role)
    await db.commit()
    return {"message": "Role assigned to user"}


@router.delete("/users/{user_id}/roles/{role_id}", dependencies=[Depends(verify_permission("assign:roles"))])
async def remove_role_from_user(
    user_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Remove a role from a user"""
    result = await db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id
        )
    )
    user_role = result.scalars().first()
    if not user_role:
        raise HTTPException(status_code=404, detail="Role not assigned to user")

    await db.delete(user_role)
    await db.commit()
    return {"message": "Role removed from user"}