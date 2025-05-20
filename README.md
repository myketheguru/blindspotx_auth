# BlindspotX Authentication System

This project implements a secure authentication and authorization system for the BlindspotX Cloud Security Posture Management platform. The system is built using FastAPI and SQLite, with a focus on security, scalability, and integration with Microsoft identity services.

## Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
  - [Authentication Flow](#authentication-flow)
  - [Authorization Flow](#authorization-flow)
  - [Data Flow Diagram](#data-flow-diagram)
- [Security Features](#security-features)
  - [Encryption Mechanisms](#encryption-mechanisms)
  - [Audit Logging](#audit-logging)
  - [Secure Token Management](#secure-token-management)
- [Drift Detection](#drift-detection)
  - [How Drift Detection Works](#how-drift-detection-works)
  - [Drift Severity Classification](#drift-severity-classification)
  - [Security-Focused Categories](#security-focused-categories)
  - [Nested Object Comparison](#nested-object-comparison)
  - [Scheduling Mechanism](#scheduling-mechanism)
- [Testing](#testing)
  - [Test Suite](#test-suite)
  - [Coverage Reporting](#coverage-reporting)
- [Deployment](#deployment)
  - [Environment Configuration](#environment-configuration)
  - [Docker Deployment](#docker-deployment)
  - [CI/CD Pipeline](#cicd-pipeline)
- [Observability](#observability)
  - [Logging Strategy](#logging-strategy)
  - [Health Checks](#health-checks)
  - [Monitoring](#monitoring)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)

## Features

- **OAuth2 Authentication**: Secure integration with Microsoft Entra ID (formerly Azure AD) using MSAL
- **Role-Based Access Control (RBAC)**: Granular permission system for different user types
- **Secure Storage**: Encrypted handling of sensitive data and tokens
- **Permission-Based Access**: Endpoint protection based on user roles and permissions
- **Token Management**: Secure handling of authentication and refresh tokens
- **Audit Logging**: Comprehensive logging of authentication events
- **Drift Detection**: Automated detection of configuration and security policy changes
- **Security Prioritization**: Security-focused categorization and severity classification

## System Architecture

The BlindspotX Authentication System follows a layered architecture pattern with clear separation of concerns:

1. **API Layer**: FastAPI-based endpoints for authentication, authorization, and user management
2. **Service Layer**: Business logic for handling authentication, authorization, and drift detection
3. **Data Layer**: Database models and persistence using SQLModel and SQLite
4. **Security Layer**: Cross-cutting concerns such as encryption, JWT handling, and audit logging

### Authentication Flow

```
┌──────────┐      1. Login Request      ┌──────────────┐      2. Redirect      ┌────────────────┐
│          │─────────────────────────-->│              │─────────────────────> │                │
│  Client  │                            │  BlindspotX  │                       │ Microsoft Entra │
│ Browser  │                            │     Auth     │                       │       ID       │
│          │<───────────────────────────│              │ <────────────────────│                │
└──────────┘      5. Token & Cookie     └──────────────┘      3. Auth Code     └────────────────┘
                                               │
                                               │ 4. Token Exchange
                                               ▼
                                        ┌──────────────┐
                                        │              │
                                        │   Secure     │
                                        │   Storage    │
                                        │              │
                                        └──────────────┘
```

### Authorization Flow

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

### Data Flow Diagram

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

## Security Features

### Encryption Mechanisms

BlindspotX Auth implements a multi-layered encryption approach:

1. **Data at Rest**: Sensitive data stored in the database is encrypted using AES-256-GCM with the following properties:
   - **Key Management**: Application keys are stored in a secure environment-specific key vault
   - **Encryption Scope**: All sensitive fields including tokens, secrets, and personal information
   - **Key Rotation**: Keys are rotated on a 90-day schedule

2. **Data in Transit**: All API communication is secured using:
   - TLS 1.3 for all external communications
   - HTTP-only secure cookies with strict same-site policy
   - HTTPS enforcement through HSTS headers

3. **Token Security**:
   - JWTs are signed using RS256 (asymmetric) for production environments
   - Token lifetimes are configurable with reasonable defaults (60 minutes)
   - Refresh tokens are securely stored with one-way hashing

### Audit Logging

The system implements comprehensive audit logging with the following characteristics:

1. **Log Content**:
   - Authentication events (login, logout, token refresh)
   - Authorization decisions (access granted/denied)
   - User and role management operations
   - Drift detection events

2. **Log Storage and Retention**:
   - Logs are stored in a tamper-evident format
   - Default 90-day retention period for standard logs
   - Extended 1-year retention for security-critical events
   - Logs are backed up daily to secure storage

3. **Log Protection**:
   - Log integrity is ensured through cryptographic hashing
   - Access to logs is restricted and audited
   - Logs are formatted for easy integration with SIEM systems

### Secure Token Management

The application implements the following token security measures:

1. **Token Types**:
   - Short-lived access tokens (default: 60 minutes)
   - Longer-lived refresh tokens (default: 7 days)
   - Cryptographically signed state tokens for OAuth flows

2. **Storage Security**:
   - Access tokens are stored in HTTP-only cookies or secure client storage
   - Refresh tokens are stored in the encrypted database with reference tokens used for clients
   - Token revocation is supported through a blocklist mechanism

## Drift Detection

Drift detection monitors changes in configurations, permissions, and security settings to identify potentially unauthorized or security-impacting modifications.

### How Drift Detection Works

The system employs a multi-stage process for drift detection:

1. **Snapshot Collection**: Configuration snapshots are taken at regular intervals
2. **Differential Analysis**: Current state is compared with previous snapshots
3. **Classification**: Changes are categorized and assigned severity levels
4. **Alerting**: Significant changes trigger notifications based on severity
5. **Reporting**: Comprehensive drift reports are available through the API and UI

### Drift Severity Classification

Changes are classified into severity levels based on several factors:

| Severity | Description | Examples | Response Time |
|----------|-------------|----------|---------------|
| **CRITICAL** | Changes with immediate security impact | MFA disabled, admin rights granted, password policy disabled | Immediate |
| **HIGH** | Significant security changes | Permission escalation, firewall rule changes | Within hours |
| **MEDIUM** | Notable changes with potential security implications | Role modifications, new user accounts | Within 24 hours |
| **LOW** | Minor security-related changes | User profile updates, non-critical setting changes | Within 72 hours |
| **INFO** | Informational changes with no security impact | Cosmetic changes, documentation updates | Routine review |

Severity classification is determined by multiple factors:

- **Category of the change**: Security settings have higher base severity than general settings
- **Type of change**: Deletions often have higher severity than creations or modifications
- **Field sensitivity**: Changes to fields like "password", "admin", or "security" increase severity
- **Security impact**: Changes that weaken security posture are automatically elevated

### Security-Focused Categories

The drift detection system prioritizes certain categories of configuration items based on their security implications:

| Category | Priority | Description | Examples |
|----------|----------|-------------|----------|
| **AUTH_SETTINGS** | Critical | Authentication configuration | Sign-in methods, session timeouts |
| **PASSWORD_POLICY** | Critical | Password complexity and management | Minimum length, complexity requirements |
| **MFA_SETTINGS** | Critical | Multi-factor authentication settings | MFA enforcement, trusted devices |
| **FIREWALL** | High | Network access controls | IP restrictions, API access rules |
| **PERMISSION** | High | User and role permissions | Admin rights, sensitive operation access |
| **ROLE** | Medium | Role definitions and assignments | Role creation, permission assignments |
| **USER** | Medium | User account management | Account creation, status changes |
| **API_SETTINGS** | Medium | API configuration | Rate limits, authentication requirements |
| **NETWORK** | Medium | Network configuration | Allowed origins, network paths |
| **APP_SETTINGS** | Low | Application configuration | UI settings, preferences |

### Nested Object Comparison

The drift detection system implements deep recursive comparison of configuration objects to detect changes at any level of nesting:

1. **Path Tracking**: Each field change is tracked with dot-notation path (e.g., `user.permissions.admin`)
2. **Deep Comparison**: Nested objects are recursively compared, not just shallow top-level properties
3. **Array Handling**: Special handling for arrays, including item-by-item comparison when possible
4. **Type-Aware**: Different comparison strategies based on the data type (scalar, object, array)

Example of nested comparison output:

```json
{
  "change_type": "modified",
  "category": "role",
  "key": "admin_role",
  "path": "permissions.resources.critical_systems.access_level",
  "old_value": "read",
  "new_value": "write",
  "severity": "high"
}
```

### Scheduling Mechanism

Drift detection runs as a scheduled background task with the following characteristics:

1. **Frequency**: Default interval of 30 minutes, configurable in settings
2. **Implementation**: Asynchronous job scheduler using asyncio
3. **Retry Logic**: Failed detection attempts use exponential backoff with jitter
4. **Health Monitoring**: Job execution is monitored with timestamps and status tracking
5. **Manual Triggering**: On-demand runs can be initiated through the admin API

The scheduler also provides:

- Graceful shutdown handling
- Job history with execution statistics
- Customizable intervals per environment
- Failure alerting for missed detection runs

## Testing

BlindspotX Auth includes a comprehensive test suite to ensure functionality, security, and reliability.

### Test Suite

The test suite includes:

1. **Unit Tests**: Testing individual components in isolation
   - Core security functions (JWT, encryption)
   - Data models and schemas
   - Utility functions

2. **Integration Tests**: Testing interaction between components
   - API endpoints with database interaction
   - Authentication flows
   - Permission enforcement

3. **Security Tests**: Specific tests for security functionality
   - Token validation and expiration
   - Permission boundary enforcement
   - Encryption correctness
   - Drift detection accuracy

4. **End-to-End Tests**: Testing complete workflows
   - Full authentication flows
   - User management operations
   - Role-based access scenarios

### Coverage Reporting

Test coverage is measured using pytest-cov with the following targets:

- **Minimum coverage requirement**: 80% overall code coverage
- **Critical paths coverage**: 95% coverage for authentication and permission code
- **Coverage reporting**: Generated as part of the CI/CD pipeline
- **Coverage visualization**: Available in HTML format and as GitHub status checks

To run tests with coverage reporting:

```bash
# Run tests with coverage
pytest --cov=app tests/ --cov-report=term --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Deployment

BlindspotX Auth supports multiple deployment environments with environment-specific configurations.

### Environment Configuration

The system supports the following environments:

1. **Local**: Development environment
   - SQLite database
   - Disabled encryption for easier debugging
   - Mock OAuth provider option
   - Debug logging

2. **Development**: Shared development environment
   - SQLite or PostgreSQL database
   - Basic encryption with development keys
   - Integration with test OAuth tenants
   - Verbose logging

3. **Staging**: Pre-production environment
   - PostgreSQL database
   - Full encryption with key vault integration
   - Integration with production OAuth configured for test users
   - Production-level logging with enhanced verbosity

4. **Production**: Production environment
   - PostgreSQL database with replication
   - Full encryption with production key vault
   - Integration with production OAuth
   - Production logging with security-focused events

Environment configuration is managed through:

- Environment variables
- Environment-specific `.env` files
- Azure Key Vault for secrets in non-local environments

### Docker Deployment

The application includes Docker support for containerized deployment:

```bash
# Build the Docker image
docker build -t blindspotx-auth:latest .

# Run the container
docker run -p 8000:8000 -e ENVIRONMENT=production blindspotx-auth:latest

# Using docker-compose
docker-compose up -d
```

The Dockerfile implements:

- Multi-stage builds for smaller images
- Non-root user for security
- Health checks for container orchestration
- Volume mounts for persistent data

### CI/CD Pipeline

The project includes a GitHub Actions CI/CD pipeline with the following stages:

1. **Build**: Builds and verifies the application
   - Dependency installation
   - Static type checking with mypy
   - Linting with flake8

2. **Test**: Runs the test suite
   - Unit and integration tests
   - Security tests
   - Coverage reporting

3. **Security Scan**: Performs security analysis
   - Dependency vulnerability scanning
   - Code security analysis with Bandit
   - Container image scanning

4. **Deploy**: Deploys to the appropriate environment
   - Automatic deployment to development on main branch changes
   - Manual approval workflow for staging and production
   - Environment-specific configuration

The CI/CD pipeline can be triggered:
- On push to main branch (dev deployment)
- On pull requests (build and test)
- Manually through GitHub Actions workflow_dispatch (any environment)

## Observability

The application implements comprehensive observability features to monitor health, performance, and security.

### Logging Strategy

The logging system follows a structured approach:

1. **Log Levels**:
   - `ERROR`: Application errors requiring attention
   - `WARNING`: Potential issues or security concerns
   - `INFO`: Standard operational events
   - `DEBUG`: Detailed information for troubleshooting

2. **Log Format**:
   - JSON-structured logs for machine parsing
   - Context enrichment with request IDs, user IDs, and correlation IDs
   - Timestamps in ISO 8601 format with timezone

3. **Log Categories**:
   - `auth`: Authentication events
   - `access`: Authorization decisions
   - `drift`: Drift detection events
   - `admin`: Administrative operations
   - `security`: Security-related events

Example log configuration:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(levelname)s %(name)s %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'app.log',
            'maxBytes': 10485760,  # 10 MB
            'backupCount': 10,
            'formatter': 'json',
        },
    },
    'loggers': {
        'app': {
            'handlers': ['console', 'file'],
            'level': os.getenv('LOG_LEVEL', 'INFO'),
        },
    },
}
```

### Health Checks

The application provides the following health check endpoints:

1. **Basic Health**: `/api/health` - Simple availability check
2. **Detailed Health**: `/api/health/details` - Component-level health status
3. **Readiness Probe**: `/api/health/ready` - Indicates if the application is ready to serve requests
4. **Liveness Probe**: `/api/health/live` - Indicates if the application is running properly

Health checks verify:
- Database connectivity
- OAuth provider availability
- Drift detection scheduler status
- Encryption service functionality

### Monitoring

The system exposes metrics and monitoring data through:

1. **Prometheus Metrics**: `/metrics` endpoint with:
   - Request counts and latencies
   - Error rates
   - Authentication success/failure counts
   - Drift detection statistics

2. **Application Performance Monitoring**:
   - Integration with OpenTelemetry for distributed tracing
   - Performance bottleneck identification
   - Error tracking and alerting

3. **Custom Dashboard**:
   - Admin UI with key metrics dashboard
   - Security events timeline
   - Drift detection visualization

## Getting Started

### Prerequisites

- Python 3.9+
- Virtual environment (recommended)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/myketheguru/blindspotx-auth.git
cd blindspotx_auth
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

### Configuration

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Edit `.env` with your specific configuration:

```
# Core settings
SECRET_KEY=your-secret-key
ENVIRONMENT=local

# Database
DATABASE_URL=sqlite:///./blindspotx.db

# OAuth settings
MS_CLIENT_ID=your-client-id
MS_CLIENT_SECRET=your-client-secret
MS_TENANT_ID=your-tenant-id

# Security settings
ACCESS_TOKEN_EXPIRE_MINUTES=240
REFRESH_TOKEN_EXPIRE_DAYS=7
```

### Running the Application

Start the application:

```bash
python run.py
```

Or using Uvicorn directly:

```bash
uvicorn app.main:app --reload
```

The application will be available at http://localhost:8000

## API Endpoints

### Authentication

- `GET /api/auth/login`: Initiates OAuth2 login flow with Microsoft Entra ID
- `GET /api/auth/callback`: OAuth2 callback handler
- `POST /api/auth/refresh`: Refreshes access token using refresh token
- `POST /api/auth/logout`: Logs out user and invalidates tokens

### User Management

- `GET /api/users/me`: Gets current user profile
- `GET /api/users/`: Lists all users
- `POST /api/users/`: Creates a new user
- `GET /api/users/{id}`: Gets a specific user
- `PUT /api/users/{id}`: Updates a specific user

### Role Management

- `GET /api/rbac/roles/`: Lists all roles
- `POST /api/rbac/roles/`: Creates a new role
- `GET /api/rbac/roles/{id}`: Gets a specific role
- `PUT /api/rbac/roles/{id}`: Updates a specific role
- `DELETE /api/rbac/roles/{id}`: Deletes a role
- `POST /api/rbac/roles/{id}/permissions`: Assigns permissions to a role
- `DELETE /api/rbac/roles/{id}/permissions/{permission_id}`: Removes a permission from a role

### Permission Management

- `GET /api/rbac/permissions/`: Lists all permissions
- `POST /api/rbac/permissions/`: Creates a new permission
- `GET /api/rbac/permissions/{id}`: Gets a specific permission
- `PUT /api/rbac/permissions/{id}`: Updates a permission
- `DELETE /api/rbac/permissions/{id}`: Deletes a permission

### Drift Detection

- `GET /api/drift/status`: Gets current drift detection status
- `GET /api/drift/history`: Gets drift detection history
- `POST /api/drift/scan`: Triggers manual drift detection
- `GET /api/drift/reports`: Lists all drift reports
- `GET /api/drift/reports/{id}`: Gets a specific drift report
- `GET /api/drift/analytics`: Gets drift detection analytics and statistics

## Project Structure

The project follows a modular architecture to separate concerns and facilitate testing:

```
blindspotx_auth/
├── app/
│   ├── __init__.py
│   ├── main.py             # FastAPI application entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py       # Configuration settings
│   │   ├── security.py     # Security utilities (JWT, permissions)
│   │   ├── database.py     # Database connection and secure storage
│   │   └── drift/          # Drift detection framework
│   │       ├── __init__.py
│   │       ├── detector.py  # Drift detection logic
│   │       ├── severity.py  # Severity classification
│   │       ├── types.py     # Drift detection types
│   │       └── scheduler.py # Background job scheduler
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py     # Authentication endpoints
│   │   │   ├── users.py    # User management endpoints
│   │   │   ├── rbac.py     # Role and permission endpoints
│   │   │   └── drift.py    # Drift detection endpoints
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py         # User model with role-based access
│   │   ├── role.py         # Role and permission models
│   │   └── drift.py        # Drift detection models
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── token.py        # Token schemas
│   │   ├── user.py         # User schemas
│   │   └── drift.py        # Drift detection schemas
│   └── services/
│       ├── __init__.py
│       ├── auth.py         # Authentication service
│       ├── oauth.py        # OAuth integration with Microsoft
│       └── drift_service.py # Drift detection service
├── tests/                  # Comprehensive test suite
│   ├── __init__.py
│   ├── conftest.py         # Test fixtures and configuration
│   ├── test_auth.py        # Authentication tests
│   ├── test_rbac.py        # Role and permission tests
│   └── test_drift.py       # Drift detection tests
├── .github/                # GitHub configuration
│   └── workflows/          # CI/CD workflows
│       └── ci.yml          # CI/CD pipeline configuration
├── .env.example            # Example environment variables
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose configuration
├── README.md               # Project documentation
└── run.py                  # Script to run the application
```
