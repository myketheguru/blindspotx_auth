# BlindspotX System Architecture Overview

## Introduction

The BlindspotX Authentication System provides secure authentication and authorization for the BlindspotX Cloud Security Posture Management platform. The system integrates with Microsoft Entra ID (formerly Azure AD) and provides robust role-based access control (RBAC) with drift detection capabilities.

## Architectural Layers

The system follows a layered architecture pattern with clear separation of concerns:

1. **API Layer**: FastAPI-based endpoints for authentication, authorization, and user management
2. **Service Layer**: Business logic for handling authentication, authorization, and drift detection
3. **Data Layer**: Database models and persistence using SQLModel and SQLite
4. **Security Layer**: Cross-cutting concerns such as encryption, JWT handling, and audit logging

## Core Components

### Authentication Module
- OAuth2 authorization code flow with PKCE
- JWT validation and parsing
- Secure token storage and management
- Refresh token handling
- Integration with Microsoft Entra ID

### RBAC Module
- Role definition and management
- Permission assignment to roles
- User-role association
- Permission-based endpoint protection
- Dynamic permission validation

### Drift Detection Module
- Configuration snapshots at regular intervals
- Differential analysis between snapshots
- Severity classification of changes
- Security-focused categorization
- Alerting based on severity

### User Management Module
- User profile management
- User creation and monitoring
- User search and filtering
- User-role assignment
- Account status management

## Technology Stack

- **API Framework**: FastAPI
- **Database**: SQLite (development) / PostgreSQL (production)
- **Authentication**: OAuth2 with MSAL (Microsoft Authentication Library)
- **ORM**: SQLModel
- **Background Jobs**: Python asyncio-based scheduler
- **Containerization**: Docker
- **CI/CD**: GitHub Actions
- **Encryption**: AES-256-GCM for sensitive data
- **Token Handling**: JWT with RS256 signing

## Integration Points

The system integrates with several external systems:

1. **Microsoft Entra ID**: For authentication and user identity
2. **Logging and Monitoring Systems**: For operational visibility
3. **Notification Systems**: For alerting on critical events
4. **Database**: For persistent storage of user data, roles, and configurations

## Architectural Principles

1. **Separation of Concerns**: Each component has a specific responsibility
2. **Dependency Injection**: Services and repositories are injected where needed
3. **Security by Default**: Security mechanisms are baked into the design
4. **Observability**: Comprehensive logging, monitoring, and health checks
5. **Testability**: Components are designed to be easily testable

## Related Documentation

- [Authentication Flow](./authentication_flow.md)
- [Authorization Flow](./authorization_flow.md)
- [Drift Detection](./drift_detection.md)
- [Data Flow](./data_flow.md)
- [Security Overview](../security/overview.md)

## Best Practices

- All authentication flows use secure protocols (OAuth2, PKCE)
- Sensitive data is always encrypted at rest
- All API endpoints are protected with appropriate permissions
- Regular security audits through drift detection
- Comprehensive logging for security events

