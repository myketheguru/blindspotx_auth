# System Architecture

## Overview

The BlindspotX Authentication System follows a layered architecture pattern with clear separation of concerns to ensure security, maintainability, and scalability. This document provides detailed information about the system's architecture, components, and interactions.

## Architectural Layers

### 1. API Layer

The API layer is responsible for handling HTTP requests and responses. It is implemented using FastAPI, which provides automatic validation, serialization, and documentation.

Key components:
- **Endpoint routers**: Organized by functional area (auth, users, RBAC, drift)
- **Middleware**: Request processing, logging, error handling
- **Request validation**: Schema-based validation of incoming data
- **Response formatting**: Standardized response structure

### 2. Service Layer

The service layer contains the core business logic of the application, implementing the various features and enforcing business rules.

Key components:
- **Authentication service**: Handles user authentication flows
- **OAuth integration**: Microsoft Entra ID integration with MSAL
- **RBAC service**: Manages roles, permissions, and access control
- **Drift detection service**: Implements the drift detection algorithms

### 3. Data Layer

The data layer manages data persistence and retrieval operations.

Key components:
- **Database models**: SQLModel-based ORM models
- **Data access objects**: Encapsulated database operations
- **Query builders**: Efficient and secure query construction
- **Connection management**: Database connection pooling and lifecycle

### 4. Security Layer

The security layer is a cross-cutting concern that impacts all other layers, ensuring the system's security.

Key components:
- **Encryption services**: Data encryption/decryption operations
- **JWT handling**: Token generation, validation, and management
- **Audit logging**: Security event recording and management
- **Permission enforcement**: Runtime permission checking

## Component Interaction

The components interact through a dependency injection pattern, with each layer depending only on interfaces of the layers below it. This ensures:

1. **Testability**: Components can be tested in isolation
2. **Maintainability**: Changes to one component don't cascade to others
3. **Extensibility**: New implementations can be provided without changing clients

### Request Flow

A typical request flows through the system as follows:

1. **Request reception**: FastAPI receives an HTTP request
2. **Middleware processing**: Authentication middleware validates token
3. **Endpoint handler**: Route function processes the request
4. **Service invocation**: Business logic is executed via service layer
5. **Data access**: Data is retrieved or updated via data layer
6. **Response creation**: Result is packaged into an HTTP response
7. **Middleware post-processing**: Logging, error handling, etc.
8. **Response delivery**: HTTP response is sent back to the client

## Data Models

### Core Entity Relationships

```
User <---> Role <---> Permission
  |
  v
UserSession
  |
  v
RefreshToken
```

### Drift Detection Models

```
ConfigSnapshot <---> DriftReport
                        |
                        v
                    DriftChange
```

## Communication Patterns

### Synchronous Communication

Most communication within the system is synchronous, using direct method calls between components.

### Asynchronous Communication

The system uses asynchronous patterns for:

1. **Background jobs**: Drift detection runs, scheduled using an asyncio-based scheduler
2. **Webhook notifications**: External system notifications for critical events
3. **Logging and monitoring**: Non-blocking logging and metric recording

## Integration Points

The system integrates with external systems through the following interfaces:

1. **Microsoft Entra ID**: OAuth2 authentication provider
2. **Logging infrastructure**: Structured logging output for SIEM integration
3. **Monitoring systems**: Prometheus metrics for dashboard integration

## Scalability Considerations

The architecture supports horizontal scaling through:

1. **Stateless API layer**: Requests can be routed to any instance
2. **Database connection pooling**: Efficient database resource usage
3. **Caching strategies**: Reduces database load for frequent operations
4. **Background job coordination**: Prevents duplicate drift detection runs

