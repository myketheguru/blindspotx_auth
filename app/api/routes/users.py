import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.core.database import get_db
from app.core.security import get_current_user, verify_permission
from app.models.user import User, get_user_permissions
from app.schemas.user import User as UserSchema, UserCreate, UserUpdate

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/me", response_model=UserSchema)
async def read_users_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user profile information
    """
    # Get user permissions
    permissions = await get_user_permissions(current_user.id, db)
    
    # Create user response
    user_data = current_user.dict()
    user_data["permissions"] = permissions
    
    return user_data

@router.get("/", response_model=List[UserSchema], dependencies=[Depends(verify_permission("read:users"))])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get list of users (admin only)
    """
    query = select(User).offset(skip).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()
    return users

@router.post("/", response_model=UserSchema, dependencies=[Depends(verify_permission("create:users"))])
async def create_new_user(
    user: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new user (admin only)
    """
    # Check if user already exists
    existing_user = await get_user_by_email(user.email, db)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User with email {user.email} already exists"
        )
    
    # Create user
    user_data = user.dict(exclude={"roles"})
    new_user = User(**user_data)
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    # Assign roles if provided
    if user.roles:
        # Add role assignment logic here
        pass
    
    logger.info(f"User created: {new_user.email}")
    return new_user

@router.put("/{user_id}", response_model=UserSchema, dependencies=[Depends(verify_permission("update:users"))])
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update user information (admin only)
    """
    # Get user from database
    result = await db.execute(select(User).where(User.id == user_id))
    db_user = result.scalars().first()
    
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Update user fields
    user_data = user_update.dict(exclude_unset=True)
    for key, value in user_data.items():
        if key != "roles" and value is not None:
            setattr(db_user, key, value)
    
    # Update roles if provided
    if user_update.roles is not None:
        # Add role update logic here
        pass
    
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    
    logger.info(f"User updated: {db_user.email}")
    return db_user

@router.delete("/{user_id}", dependencies=[Depends(verify_permission("delete:users"))])
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete a user (admin only)
    """
    # Get user from database
    result = await db.execute(select(User).where(User.id == user_id))
    db_user = result.scalars().first()
    
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Prevent deletion of own account
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete own account"
        )
    
    # Delete user
    await db.delete(db_user)
    await db.commit()
    
    logger.info(f"User deleted: {db_user.email}")
    return {"message": f"User {db_user.email} deleted successfully"}