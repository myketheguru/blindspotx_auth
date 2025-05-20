# System Overview

## BlindspotX Authentication System

The BlindspotX Authentication System provides secure authentication and authorization for the BlindspotX Cloud Security Posture Management platform. The system is designed to integrate with Microsoft Entra ID (formerly Azure AD) and provide robust role-based access control (RBAC).

## Key Components

### Authentication Module

The authentication module handles user authentication through OAuth2 integration with Microsoft Entra ID. It manages the authentication flow, token validation, and secure storage of tokens.

Key features:
- OAuth2 authorization code flow with PKCE
- JWT validation and parsing
- Secure token storage and management
- Refresh token handling

### RBAC Module

The Role-Based Access Control (RBAC) module manages permissions and roles within the system. It enforces access control at the API level based on user roles and specific permissions.

Key features:
- Role definition and management
- Permission assignment to roles
- User-role association
- Permission-based endpoint protection

### Drift Detection Module

The Drift Detection module monitors for changes in configurations, permissions, and security settings to identify potentially unauthorized or security-impacting modifications.

Key features:
- Configuration snapshots at regular intervals
- Differential analysis between snapshots
- Severity classification of changes
- Security-focused categorization
- Alerting based on severity

### User Management Module

The User Management module handles user profiles, preferences, and account information. It provides APIs for creating, updating, and retrieving user information.

Key features:
- User profile management
- User creation and management
- User search and filtering
- User-role assignment

## Integration Points

The system integrates with several external systems:

1. **Microsoft Entra ID**: For authentication and user identity
2. **Logging and Monitoring Systems**: For operational visibility
3. **Notification Systems**: For alerting on critical events
4. **Database**: For persistent storage of user data, roles, and configurations

## Technology Stack

- **Framework**: FastAPI
- **Database**: SQLite (development) / PostgreSQL (production)
- **Authentication**: OAuth2 with MSAL (Microsoft Authentication Library)
- **Encryption**: AES-256-GCM for sensitive data
- **Token Handling**: JWT with RS256 signing
- **Background Processing**: asyncio-based scheduler

