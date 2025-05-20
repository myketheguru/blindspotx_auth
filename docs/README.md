# BlindspotX Authentication System Documentation

## Overview

This documentation provides comprehensive information about the BlindspotX Authentication System, a secure authentication and authorization platform for the BlindspotX Cloud Security Posture Management system.

## Quick Start
- [Getting Started Guide](../README.md#getting-started)
- [Environment Setup](../README.md#configuration)
- [Running the Application](../README.md#running-the-application)

## Core Documentation

### Architecture
- [System Architecture Overview](./architecture/overview.md)
- [Authentication Flow](./architecture/authentication_flow.md)
- [Authorization & RBAC](./architecture/authorization_flow.md)
- [Data Flow](./architecture/data_flow.md)
- [Drift Detection System](./architecture/drift_detection.md)

### Security
- [Security Overview](./security/overview.md)
- [Encryption Mechanisms](./security/encryption.md)
- [Token Management](./security/token_management.md)
- [Audit Logging](./security/audit_logging.md)
- [RBAC Implementation](./security/rbac_implementation.md)

### API Reference
- [Authentication APIs](../README.md#authentication)
- [User Management APIs](../README.md#user-management)
- [Role Management APIs](../README.md#role-management)
- [Permission Management APIs](../README.md#permission-management)
- [Drift Detection APIs](../README.md#drift-detection)

### Operations
- [Deployment Guide](./operations/deployment.md)
- [Configuration](./operations/configuration.md)
- [Monitoring & Logging](./operations/monitoring.md)
- [Troubleshooting](./operations/troubleshooting.md)

## Access Patterns

### Web Interface
- Dashboard: `http://your-domain/dashboard`
- User Management: `http://your-domain/users`
- Role Management: `http://your-domain/roles`
- Permission Management: `http://your-domain/permissions`
- Drift Detection: `http://your-domain/drift`

### API Documentation
- Swagger UI: `http://your-domain/api/docs`
- ReDoc: `http://your-domain/api/redoc`

### Authentication Endpoints
- Login: `http://your-domain/api/auth/login`
- OAuth2 Callback: `http://your-domain/api/auth/callback`
- Logout: `http://your-domain/api/auth/logout`

## Contributing
- [Development Setup](./development/setup.md)
- [Coding Standards](./development/coding_standards.md)
- [Testing Guide](./development/testing.md)
- [Security Guidelines](./development/security_guidelines.md)

## Support
For issues and support:
- GitHub Issues: [Project Issues](https://github.com/yourusername/blindspotx-auth/issues)
- Security Reports: Send to security@yourdomain.com

