"""
Test Fixtures and Configuration
------------------------------
This module contains fixtures and configuration for pytest testing.
"""

import os
import pytest
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, AsyncGenerator

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token
from app.models.user import User, Role, Permission, RolePermission, UserRole
from app.main import app as main_app

# Use an in-memory SQLite database for testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# Override the database URL for testing
settings.DATABASE_URL = TEST_DATABASE_URL

# Create async engine for testing
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    future=True
)

# Create test session
TestingSessionLocal = sessionmaker(
    test_engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

# Dependency override
async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    """Override database dependency for tests"""
    async with TestingSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

# Apply dependency override to the app
main_app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for each test session"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def setup_test_db():
    """Create test database and tables"""
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)

@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session for tests"""
    async with TestingSessionLocal() as session:
        yield session
        # Clean up after test
        await session.rollback()

@pytest.fixture
def app(setup_test_db) -> FastAPI:
    """Get FastAPI app for testing"""
    return main_app

@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Get TestClient for making requests"""
    return TestClient(app)

@pytest.fixture
async def create_test_user(db_session: AsyncSession) -> User:
    """Create a test user in the database"""
    test_user = User(
        email="test@example.com",
        full_name="Test User",
        hashed_password="hashed_password",  # Not actually hashed for test
        azure_object_id="testazureid123",
        is_active=True
    )
    db_session.add(test_user)
    await db_session.commit()
    await db_session.refresh(test_user)
    return test_user

@pytest.fixture
async def create_admin_user(db_session: AsyncSession) -> User:
    """Create an admin user in the database"""
    admin_user = User(
        email="admin@example.com",
        full_name="Admin User",
        hashed_password="hashed_password",  # Not actually hashed for test
        azure_object_id="adminazureid123",
        is_active=True,
        is_admin=True
    )
    db_session.add(admin_user)
    await db_session.commit()
    await db_session.refresh(admin_user)
    return admin_user

@pytest.fixture
async def test_permissions(db_session: AsyncSession) -> List[Permission]:
    """Create test permissions in the database"""
    permissions = [
        Permission(name="read:users", description="Read user information"),
        Permission(name="create:users", description="Create new users"),
        Permission(name="read:roles", description="View roles"),
        Permission(name="create:roles", description="Create new roles"),
    ]
    
    for permission in permissions:
        db_session.add(permission)
    
    await db_session.commit()
    for permission in permissions:
        await db_session.refresh(permission)
    
    return permissions

@pytest.fixture
async def test_role(db_session: AsyncSession, test_permissions: List[Permission]) -> Role:
    """Create a test role with permissions"""
    test_role = Role(
        name="Test Role",
        description="Role for testing purposes"
    )
    db_session.add(test_role)
    await db_session.commit()
    await db_session.refresh(test_role)
    
    # Assign first two permissions to the role
    for permission in test_permissions[:2]:
        role_permission = RolePermission(
            role_id=test_role.id,
            permission_id=permission.id
        )
        db_session.add(role_permission)
    
    await db_session.commit()
    return test_role

@pytest.fixture
async def admin_role(db_session: AsyncSession, test_permissions: List[Permission]) -> Role:
    """Create an admin role with all permissions"""
    admin_role = Role(
        name="Admin Role",
        description="Role with admin permissions"
    )
    db_session.add(admin_role)
    await db_session.commit()
    await db_session.refresh(admin_role)
    
    # Assign all permissions to the role
    for permission in test_permissions:
        role_permission = RolePermission(
            role_id=admin_role.id,
            permission_id=permission.id
        )
        db_session.add(role_permission)
    
    await db_session.commit()
    return admin_role

@pytest.fixture
async def assign_role_to_user(
    db_session: AsyncSession, 
    create_test_user: User, 
    test_role: Role
) -> User:
    """Assign role to test user"""
    user_role = UserRole(
        user_id=create_test_user.id,
        role_id=test_role.id
    )
    db_session.add(user_role)
    await db_session.commit()
    return create_test_user

@pytest.fixture
async def assign_admin_role(
    db_session: AsyncSession, 
    create_admin_user: User, 
    admin_role: Role
) -> User:
    """Assign admin role to admin user"""
    user_role = UserRole(
        user_id=create_admin_user.id,
        role_id=admin_role.id
    )
    db_session.add(user_role)
    await db_session.commit()
    return create_admin_user

@pytest.fixture
def test_user_token(create_test_user: User) -> str:
    """Create a token for the test user"""
    return create_access_token(
        subject=create_test_user.email,
        permissions=["read:users", "create:users"],
        user_id=str(create_test_user.id)
    )

@pytest.fixture
def admin_token(create_admin_user: User) -> str:
    """Create a token for the admin user with all permissions"""
    return create_access_token(
        subject=create_admin_user.email,
        permissions=["read:users", "create:users", "read:roles", "create:roles"],
        user_id=str(create_admin_user.id)
    )

@pytest.fixture
def auth_headers(test_user_token: str) -> Dict[str, str]:
    """Get authorization headers for the test user"""
    return {"Authorization": f"Bearer {test_user_token}"}

@pytest.fixture
def admin_headers(admin_token: str) -> Dict[str, str]:
    """Get authorization headers for the admin user"""
    return {"Authorization": f"Bearer {admin_token}"}

@pytest.fixture
def expired_token() -> str:
    """Create an expired token for testing"""
    return create_access_token(
        subject="expired@example.com",
        permissions=["read:users"],
        expires_delta=timedelta(minutes=-1)  # Expired 1 minute ago
    )

@pytest.fixture
def mock_configuration_snapshot() -> Dict[str, Any]:
    """Create a mock configuration snapshot for drift detection tests"""
    return {
        "id": "mockid123",
        "type": "role",
        "name": "Test Role",
        "permissions": ["read:users", "create:users"],
        "members": ["user1", "user2"],
        "created_at": "2025-01-01T00:00:00Z",
        "modified_at": "2025-01-02T00:00:00Z"
    }

@pytest.fixture
def mock_modified_configuration() -> Dict[str, Any]:
    """Create a modified version of the configuration snapshot"""
    return {
        "id": "mockid123",
        "type": "role",
        "name": "Test Role Modified",
        "permissions": ["read:users", "create:users", "delete:users"],  # Added permission
        "members": ["user1"],  # Removed user2
        "created_at": "2025-01-01T00:00:00Z",
        "modified_at": "2025-01-03T00:00:00Z"  # Updated timestamp
    }

import os
import pytest
import asyncio
from typing import AsyncGenerator, Generator

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from sqlmodel import SQLModel

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User, Role, Permission, RolePermission, UserRole
from app.core.security import hash_password, create_access_token

# Use a separate test database
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# Override the get_db dependency during tests
engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=NullPool
)
async_session = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def create_db_and_tables():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def get_test_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


# Create a test app with the test database
@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_app() -> FastAPI:
    # Import the app here to avoid circular imports
    from app.main import app

    # Override dependencies
    app.dependency_overrides[get_db] = get_test_db

    # Set up the test database
    await create_db_and_tables()

    # Return the app
    return app


@pytest.fixture
async def client(test_app: FastAPI) -> AsyncGenerator[TestClient, None]:
    # Use TestClient which handles async context
    with TestClient(test_app) as client:
        yield client


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session
        # Clean up after each test
        for table in reversed(SQLModel.metadata.sorted_tables):
            await session.execute(f"DELETE FROM {table.name}")
        await session.commit()


# User fixtures
@pytest.fixture
async def test_permission(db_session: AsyncSession) -> Permission:
    # Create a test permission
    permission = Permission(name="test:permission", description="Test Permission")
    db_session.add(permission)
    await db_session.commit()
    await db_session.refresh(permission)
    return permission


@pytest.fixture
async def test_role(db_session: AsyncSession, test_permission: Permission) -> Role:
    # Create a test role
    role = Role(name="Test Role", description="Test Role Description")
    db_session.add(role)
    await db_session.commit()
    await db_session.refresh(role)
    
    # Assign permission to role
    role_permission = RolePermission(role_id=role.id, permission_id=test_permission.id)
    db_session.add(role_permission)
    await db_session.commit()
    
    return role


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    # Create a test user
    user = User(
        email="test@example.com",
        full_name="Test User",
        hashed_password=hash_password("password123"),
        is_active=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_admin(db_session: AsyncSession, test_role: Role) -> User:
    # Create an admin user
    admin = User(
        email="admin@example.com",
        full_name="Admin User",
        hashed_password=hash_password("adminpass"),
        is_active=True,
        is_superuser=True
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    
    # Assign role to admin
    user_role = UserRole(user_id=admin.id, role_id=test_role.id)
    db_session.add(user_role)
    await db_session.commit()
    
    return admin


@pytest.fixture
def user_token(test_user: User) -> str:
    # Create a token for the test user
    return create_access_token(
        subject=test_user.email,
        permissions=["test:permission"]
    )


@pytest.fixture
def admin_token(test_admin: User) -> str:
    # Create a token for the admin user with all permissions
    return create_access_token(
        subject=test_admin.email,
        permissions=["test:permission", "admin:all"]
    )


# Clean up after all tests
@pytest.fixture(autouse=True, scope="session")
async def cleanup():
    yield
    # Remove test database after all tests
    try:
        os.remove("./test.db")
    except:
        pass

