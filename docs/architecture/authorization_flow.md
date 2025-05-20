# Authorization Flow

## Overview

BlindspotX implements a comprehensive Role-Based Access Control (RBAC) system that manages user permissions and enforces access control at the API level. This document details the authorization flow and permission checks.

## Authorization Flow Diagram

```
┌──────────┐      1. API Request + Token     ┌──────────────┐
│          │─────────────────────────────────>│              │
│  Client  │                                  │  BlindspotX  │
│          │                                  │     Auth     │
│          │<─────────────────────────────────│              │
└──────────┘      4. Response                 └──────────────┘
                                                     │
                                                     │ 2. Token Validation
                                                     ▼
                                              ┌──────────────┐
                                              │              │
                                              │  Permission  │ 3. Permission Check
                                              │   System     │
                                              │              │
                                              └──────────────┘
```

## Authorization Process

### 1. Request with Access Token

When a client makes a request to a protected API endpoint:

1. The client includes the access token (JWT) in the request, typically as an HTTP-only cookie or Authorization header
2. The request is received by the BlindspotX API gateway

### 2. Token Validation

Before processing the request:

1. The system extracts and validates the access token
2. The token signature is verified to ensure authenticity
3. Token expiration time is checked
4. Token claims are extracted, including user identity and roles

### 3. Permission Check

After token validation:

1. The system identifies the required permissions for the requested endpoint
2. The user's roles are retrieved from the token or database
3. The roles are expanded to their associated permissions
4. The system checks if the user's permissions include those required for the endpoint
5. Additional contextual checks may be performed (e.g., resource ownership)

### 4. Authorization Decision

Based on the permission check:

1. If authorized, the request proceeds to the handler function
2. If unauthorized, a 403 Forbidden response is returned
3. If unauthenticated, a 401 Unauthorized response is returned
4. The authorization decision is logged for audit purposes

## RBAC Model

### Roles

Roles are named collections of permissions that can be assigned to users. Example roles:

- **Admin**: Full system access
- **Manager**: User and configuration management
- **Auditor**: Read-only access to logs and configurations
- **User**: Basic application functionality

### Permissions

Permissions are fine-grained access controls that define what actions can be performed. Permissions follow a format of `resource:action`, for example:

- `users:read` - Can view user information
- `users:write` - Can create or update users
- `roles:assign` - Can assign roles to users
- `config:update` - Can update system configuration
- `drift:view` - Can view drift detection reports

### Permission Inheritance

Roles can inherit permissions from other roles, creating a hierarchy. For example:

- **Admin** inherits all permissions from **Manager**
- **Manager** inherits all permissions from **User**

### Resource-Based Authorization

Some endpoints implement resource-based authorization, where access depends on the specific resource being accessed:

1. The system first checks if the user has the required permission (e.g., `documents:read`)
2. Then checks if the user has access to the specific resource (e.g., is the user an owner or member of the project)

## Implementation

### Dependency Injection

FastAPI's dependency injection system is used to enforce authorization:

```python
from fastapi import Depends, HTTPException
from app.core.security import get_current_user, require_permissions

@app.get("/api/users/", dependencies=[Depends(require_permissions(["users:read"]))])
async def list_users(current_user = Depends(get_current_user)):
    # Only users with 'users:read' permission can access this endpoint
    # ...
```

### Custom Decorators

Custom decorators are used for more complex authorization logic:

```python
@app.put("/api/documents/{document_id}")
@require_resource_permission("documents:write", "document_id")
async def update_document(document_id: str, current_user = Depends(get_current_user)):
    # This checks both the permission and resource ownership
    # ...
```

## Audit Logging

All authorization decisions are logged for audit purposes:

- Successful authorizations (user accessed a resource)
- Failed authorizations (access denied)
- Permission changes (role assignments, permission modifications)
- Administrative actions (role creation, permission updates)

## Security Considerations

- Principle of least privilege: Users are given the minimum permissions necessary
- Regular permission review: Admin interface allows review of user permissions
- Permission expiration: Temporary permissions can be set to expire
- Role separation: Critical operations require multiple roles (separation of duties)
- Fine-grained permissions: Granular control over system functionality

# Authorization Flow

This document describes the authorization flow within the BlindspotX Auth system, explaining how access control is enforced through role-based permissions.

## RBAC Authorization Process

BlindspotX Auth implements a comprehensive role-based access control (RBAC) system with the following flow:

1. **Request Validation**: When a client makes an API request with a token, the system first validates the token.
2. **Permission Extraction**: The system extracts the user's roles and permissions from the validated token.
3. **Permission Check**: The system checks if the user has the required permission for the requested resource/action.
4. **Access Decision**: Based on the permission check, the system either grants or denies access.
5. **Response**: The system returns the appropriate response to the client.

## Flow Diagram

The authorization flow is illustrated in the following diagram:

```
┌──────────┐      1. API Request + Token     ┌──────────────┐
│          │─────────────────────────────────>│              │
│  Client  │                                  │  BlindspotX  │
│          │                                  │     Auth     │
│          │<─────────────────────────────────│              │
└──────────┘      4. Response                 └──────────────┘
                                                     │
                                                     │ 2. Token Validation
                                                     ▼
                                              ┌──────────────┐
                                              │              │
                                              │  Permission  │ 3. Permission Check
                                              │   System     │
                                              │              │
                                              └──────────────┘
```

## RBAC Components

### Roles

Roles are named collections of permissions. Each user can be assigned multiple roles, and each role can have multiple permissions. Example roles include:

- Administrator
- Security Analyst
- User Manager
- Auditor
- Read-Only User

### Permissions

Permissions define what actions can be performed on which resources. Permissions follow a structured format:

```
{resource}:{action}
```

Examples:
- `users:read` - Can read user information
- `roles:write` - Can create/update roles
- `drift:admin` - Has full access to drift detection features
- `system:settings` - Can modify system settings

### Permission Inheritance

The system supports permission inheritance and wildcards:

- `resource:*` grants all actions on a specific resource
- `*:read` grants read access to all resources
- `*:*` grants full access to all resources (admin level)

## Implementation Details

### Role and Permission Storage

Roles and permissions are stored in the database with relationships to users:

- User → Roles (many-to-many)
- Role → Permissions (many-to-many)

### Authorization Enforcement

Authorization is enforced using a decorator pattern:

```python
@router.get("/users/", response_model=List[UserSchema])
@requires_permission("users:read")
async def get_users(current_user: User = Depends(get_current_user)):
    # Implementation
    pass
```

### Permission Checking Logic

The system implements a hierarchical permission checking algorithm:

1. Check for explicit permission match
2. Check for wildcard permissions
3. Check for inherited permissions through roles
4. Default to deny if no matches

## Resource-Specific Authorization

Certain resources implement additional object-level permissions beyond the basic RBAC:

- **Resource Ownership**: Users can access resources they own regardless of role-based permissions
- **Hierarchical Resources**: Access to a parent resource grants access to child resources
- **Context-Based Permissions**: Permissions can be contextual based on resource state or attributes

## Related Documentation

- [Authentication Flow](./authentication_flow.md)
- [RBAC Management API](../api/rbac_management.md)
- [Security Best Practices](../security/best_practices.md)

