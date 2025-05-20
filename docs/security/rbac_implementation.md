# RBAC Implementation

## Overview

BlindspotX implements Role-Based Access Control (RBAC) to manage user permissions and access control throughout the system. This document details the RBAC implementation, including roles, permissions, and access control mechanisms.

## Core Components

### Base Models

1. **Permission Model**
```python
class Permission(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
```

2. **Role Model**
```python
class Role(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
```

3. **Association Models**
```python
class RolePermission(SQLModel, table=True):
    role_id: UUID = Field(foreign_key="role.id")
    permission_id: UUID = Field(foreign_key="permission.id")
    
class UserRole(SQLModel, table=True):
    user_id: UUID = Field(foreign_key="user.id")
    role_id: UUID = Field(foreign_key="role.id")
```

## Predefined Roles & Permissions

### Base Permissions
```python
BASE_PERMISSIONS = [
    {"name": "read:users", "description": "Read user information"},
    {"name": "create:users", "description": "Create new users"},
    {"name": "update:users", "description": "Update user information"},
    {"name": "delete:users", "description": "Delete users"},
    {"name": "read:roles", "description": "View roles"},
    {"name": "create:roles", "description": "Create new roles"},
    {"name": "update:roles", "description": "Update roles"},
    {"name": "delete:roles", "description": "Delete roles"},
    {"name": "assign:roles", "description": "Assign roles to users"},
    {"name": "assign:permissions", "description": "Assign permissions to roles"},
]
```

### Permission Categories
1. **User Management**
   - read:users
   - create:users
   - update:users
   - delete:users

2. **Role Management**
   - read:roles
   - create:roles
   - update:roles
   - delete:roles

3. **Permission Management**
   - assign:roles
   - assign:permissions

## Access Control Implementation

### Permission Verification
```python
def verify_permission(required_permission: str):
    """Dependency for checking if user has specific permission"""
    async def has_permission(token: str = Depends(oauth2_scheme)) -> bool:
        payload = await decode_token(token)
        permissions = payload.get("permissions", [])
        
        if required_permission not in permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required: {required_permission}"
            )
        return True
    return has_permission
```

### Route Protection
```python
@router.post("/roles", dependencies=[Depends(verify_permission("create:roles"))])
async def create_role(role: RoleCreate, db: Session = Depends(get_db)):
    """Create a new role"""
    ...

@router.get("/users", dependencies=[Depends(verify_permission("read:users"))])
async def list_users(db: Session = Depends(get_db)):
    """List all users"""
    ...
```

## Permission Management

### Assigning Permissions to Roles
```python
async def assign_permission_to_role(
    role_id: UUID,
    permission_id: UUID,
    db: Session
) -> None:
    # Check if already assigned
    existing = await db.execute(
        select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id
        )
    )
    if existing.first():
        raise HTTPException(400, "Permission already assigned to role")
    
    # Create new assignment
    role_perm = RolePermission(role_id=role_id, permission_id=permission_id)
    db.add(role_perm)
    await db.commit()
```

### Assigning Roles to Users
```python
async def assign_role_to_user(
    user_id: UUID,
    role_id: UUID,
    db: Session
) -> None:
    # Check if already assigned
    existing = await db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id
        )
    )
    if existing.first():
        raise HTTPException(400, "Role already assigned to user")
    
    # Create new assignment
    user_role = UserRole(user_id=user_id, role_id=role_id)
    db.add(user_role)
    await db.commit()
```

## Permission Caching

### Cache Implementation
```python
class PermissionCache:
    def __init__(self, ttl_seconds: int = 300):
        self.cache = {}
        self.ttl = ttl_seconds
        
    def get(self, key: str) -> Optional[List[str]]:
        if key in self.cache:
            timestamp, permissions = self.cache[key]
            if time.time() < timestamp + self.ttl:
                return permissions
            del self.cache[key]
        return None
        
    def set(self, key: str, permissions: List[str]):
        self.cache[key] = (time.time(), permissions)
```

## User Interface Integration

### Role Management UI
1. **Create Role Form**
   - Role name input
   - Description input
   - Permission selection

2. **Edit Role Form**
   - Update role details
   - Modify permissions
   - View assigned users

3. **Permission Assignment**
   - Multi-select interface
   - Permission categories
   - Search functionality

## Best Practices

### Implementation Guidelines
1. Always check permissions using dependencies
2. Cache permission checks when possible
3. Use explicit permission names
4. Maintain audit logs for changes
5. Implement least privilege principle

### Security Considerations
1. Regular permission reviews
2. Role-based security testing
3. Permission inheritance rules
4. Access control monitoring
5. Change documentation

## Related Documentation
- [Security Overview](./overview.md)
- [Authentication Flow](../architecture/authentication_flow.md)
- [Authorization Flow](../architecture/authorization_flow.md)
- [Audit Logging](./audit_logging.md)

