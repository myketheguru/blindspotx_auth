# Data Flow Diagram

## Overview

This document describes the data flow within the BlindspotX Authentication System, showing how data moves between different components and external systems.

## High-Level Data Flow

```
                        ┌───────────────────────────────────────────────────┐
                        │                 BlindspotX Auth                   │
                        │                                                   │
           ┌────────────┤  ┌─────────────┐        ┌─────────────────────┐  │
           │            │  │             │        │                     │  │
User ──────┤ Web UI     │  │ Auth Service│───────▶│ RBAC Enforcement    │  │
           │            │  │             │        │                     │  │
           └────────────┤  └─────────────┘        └─────────────────────┘  │
                        │         │                         │               │
                        │         ▼                         ▼               │
           ┌────────────┤  ┌─────────────┐        ┌─────────────────────┐  │
           │            │  │             │        │                     │  │
Admin ─────┤ Admin UI   │  │ User/Role   │◀──────▶│ Drift Detection     │  │
           │            │  │ Management  │        │                     │  │
           └────────────┤  └─────────────┘        └─────────────────────┘  │
                        │         │                         │               │
                        │         ▼                         ▼               │
                        │  ┌─────────────┐        ┌─────────────────────┐  │
                        │  │             │        │                     │  │
                        │  │ Encrypted   │        │ Audit Logging       │  │
                        │  │ Storage     │        │                     │  │
                        │  └─────────────┘        └─────────────────────┘  │
                        │                                                   │
                        └───────────────────────────────────────────────────┘
```

## Detailed Data Flow

### Authentication Flow

1. User initiates login through the Web UI
2. Web UI redirects to Auth Service
3. Auth Service redirects to Microsoft Entra ID
4. Microsoft Entra ID returns authorization code to Auth Service
5. Auth Service exchanges code for tokens with Microsoft Entra ID
6. Auth Service validates tokens and extracts user information
7. User information is stored in Encrypted Storage
8. Access token is returned to Web UI
9. User accesses protected resources through the Web UI

### User and Role Management Flow

1. Admin accesses Admin UI
2. Admin UI sends user/role management requests to User/Role Management service
3. User/Role Management service validates requests through RBAC Enforcement
4. Changes are stored in Encrypted Storage
5. Configuration changes trigger Drift

