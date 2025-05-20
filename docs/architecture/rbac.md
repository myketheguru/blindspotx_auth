# Role-Based Access Control (RBAC)

## Overview

The BlindspotX Authentication System implements a comprehensive Role-Based Access Control (RBAC) mechanism to ensure appropriate access levels for different users based on their roles within the organization. This document details the RBAC structure, permission models, and implementation details.

## RBAC Components

### 1. Users

Users are the individuals accessing the system. Each user can:
- Be assigned one or more roles
- Have custom permissions assigned directly (optional)
- Inherit permissions from their assigned roles

### 2. Roles

Roles are collections of permissions representing job functions. The system includes:
- **Built-in roles**: Predefined roles (Admin, User, Auditor, etc.)
- **Custom roles**: Organization-specific roles
- **Role hierarchy**: Roles can inherit from parent roles (optional)

### 3. Permissions

Permissions are fine-grained access controls that define what actions a user can perform:
- **Action-based permissions**: Create, Read, Update, Delete
- **Resource-based permissions**: Users, Roles, Settings, Reports
- **Environment-based permissions**: Dev, Staging, Production

### 4. Permission Scopes

Permissions can be scoped to specific resource contexts:
- **Global scope**: Applies to all resources of a type
- **Limited scope**: Applies to specific resource instances
- **Attribute-based scope**: Applies based on resource attributes

## Permission Model

### Permission Structure

Permissions are structured as strings with the format:
```
[action]:[resource][:qualifier]
```

Examples:
- `read:users`: Can view all users
- `create:roles`: Can create new roles
- `update:settings:security`: Can update security settings
- `delete:reports:own`: Can delete own reports

### Built-in Permissions

The system includes a comprehensive set of built-in permissions:

| Permission | Description |
|------------|-------------|
| `read:users` | View user information |
| `create:users` | Create new users |
| `update:users` | Modify user information |
| `delete:users` | Remove users from the system |
| `read:roles` | View role information |
| `create:roles` | Create new roles |
| `update:roles` | Modify role information |
| `delete:roles` | Remove roles from the system |
| `assign:roles` | Assign roles to users |
| `read:permissions` | View permission information |
| `create:permissions` | Create new permissions |
| `update:permissions` | Modify permission information |
| `delete:permissions` | Remove permissions from the system |
| `assign:permissions` | Assign permissions to roles |
| `read:settings` | View system settings |
| `update:settings` | Modify system settings |
| `read:drift` | View drift detection reports |
| `execute:drift` | Run drift detection manually |
| `read:logs` | View system logs |

### Built-in Roles

The system comes with the following built-in roles:

| Role | Description | Key Permissions |
|------|-------------|----------------|
| `Administrator` | Full system access | All permissions |
| `User Manager` | Manages users | `*:users`, `read:roles` |
| `Role Manager` | Manages roles | `*:roles`, `*:permissions` |
| `Auditor` | Views logs and reports | `read:*`, `read:logs`, `read:drift` |
| `Operator` | Day-to-day operations | `read:*`, `update:settings:basic` |
| `Basic User` | Standard usage | `read:users:self`, `read:settings` |

## Implementation Details

### Permission Enforcement

The system enforces permissions at multiple levels:

1. **API Layer**: Decorators on endpoints verify permissions before processing requests
2. **Service Layer**: Service methods check permissions before performing operations
3. **Data Layer**: Query filters ensure users only access authorized resources

Example endpoint protection:
```python
@router.get("/users/", response_model=List[UserResponse])
@requires_permissions(["read:users"])
async def get_users(current_user: User = Depends(get_current_user)):
    # Implementation
```

### Permission Evaluation

The permission evaluation system supports:

1. **Direct matching**: Exact permission string matches
2. **Wildcard matching**: Using `*` for multi-character wildcards
   - Example: `read:*` matches any read permission
3. **Hierarchical matching**: Parent permissions imply child permissions
   - Example: `manage:users` implies `read:users`, `create:users`, etc.
4. **Scope evaluation**: Checks if user's permission scope includes the target resource

### Dynamic Permission Loading

Permissions are:
- Loaded at authentication time
- Cached for performance
- Refreshed on role/permission changes
- Included in JWT claims (essential permissions only)

### Role Assignment

Roles can be assigned:
- Manually by administrators
- Via group synchronization from Microsoft Entra ID
- Through automated provisioning based on user attributes

## Security Considerations

### Principle of Least Privilege

The system implements least privilege by:
- Assigning minimal permissions by default
- Requiring explicit privilege escalation
- Time-limited elevated permissions (optional)

### Separation of Duties

The RBAC system supports separation of duties through:
- Mutually exclusive roles
- Approval workflows for sensitive operations
- Audit logging of permission changes

### Permission Boundaries

The system implements permission boundaries that:
- Prevent privilege escalation beyond maximum allowed permissions
- Apply regardless of role assignments
- Can be defined at organizational or user level

## Audit and Compliance

All RBAC-related operations are logged:
- Role assignments and removals
- Permission changes
- Access attempts (successful and failed)
-

