# BlindspotX Architecture Documentation

This directory contains detailed documentation about the BlindspotX Authentication System architecture.

## Contents

- [System Overview](system_overview.md)
- [Authentication Flow](authentication_flow.md)
- [Authorization Flow](authorization_flow.md)
- [Data Flow](data_flow.md)

## System Architecture

The BlindspotX Authentication System follows a layered architecture pattern with clear separation of concerns:

1. **API Layer**: FastAPI-based endpoints for authentication, authorization, and user management
2. **Service Layer**: Business logic for handling authentication, authorization, and drift detection
3. **Data Layer**: Database models and persistence using SQLModel and SQLite
4. **Security Layer**: Cross-cutting concerns such as encryption, JWT handling, and audit logging

See individual documents for detailed information about each component.

