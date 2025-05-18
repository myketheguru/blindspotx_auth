BlindspotX Authentication System
This project implements a secure authentication and authorization system for the BlindspotX Cloud Security Posture Management platform. The system is built using FastAPI and SQLite, with a focus on security, scalability, and integration with Microsoft identity services.
Features

OAuth2 Authentication: Secure integration with Microsoft Entra ID (formerly Azure AD) using MSAL
Role-Based Access Control (RBAC): Granular permission system for different user types
Secure Storage: Encrypted handling of sensitive data and tokens
Permission-Based Access: Endpoint protection based on user roles and permissions
Token Management: Secure handling of authentication and refresh tokens
Audit Logging: Comprehensive logging of authentication events

Getting Started
Prerequisites

Python 3.9+
Virtual environment (recommended)

Installation

Clone the repository:

bashgit clone https://github.com/yourusername/blindspotx-auth.git
cd blindspotx-auth

Create and activate a virtual environment:

bashpython -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

Install dependencies:

bashpip install -r requirements.txt

Configure environment variables:

bashcp .env.example .env
# Edit .env with your specific configuration

Run the application:

bashpython run.py
Project Structure
The project follows a modular architecture to separate concerns and facilitate testing:
blindspotx_auth/
├── app/
│   ├── __init__.py
│   ├── main.py             # FastAPI application entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py       # Configuration settings
│   │   ├── security.py     # Security utilities (JWT, permissions)
│   │   └── database.py     # Database connection and secure storage
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py     # Authentication endpoints
│   │   │   └── users.py    # User management endpoints
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py         # User model with role-based access
│   │   └── role.py         # Role and permission models
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── token.py        # Token schemas
│   │   └── user.py         # User schemas
│   └── services/
│       ├── __init__.py
│       ├── auth.py         # Authentication service
│       └── oauth.py        # OAuth integration with Microsoft
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   └── test_users.py
├── .env.example
├── requirements.txt
├── README.md
└── run.py                  # Script to run the application
API Endpoints
Authentication

GET /api/auth/login: Initiates OAuth2 login flow with Microsoft Entra ID
GET /api/auth/callback: OAuth2 callback handler
POST /api/auth/refresh: Refreshes access token using refresh token
POST /api/auth/logout: Logs out user and invalidates tokens

Users Management

GET /api/users/me: Gets current user profile
GET /api/users/: Lists all users# BlindspotX Authentication System

This project implements a secure authentication and authorization system for the BlindspotX Cloud Security Posture Management platform. The system is built using FastAPI and SQLite, with a focus on security, scalability, and integration with Microsoft identity services.
Features

OAuth2 Authentication: Secure integration with Microsoft Entra ID (formerly Azure AD) using MSAL
Role-Based Access Control (RBAC): Granular permission system for different user types
Secure Storage: Encrypted handling of sensitive data and tokens
Permission-Based Access: Endpoint protection based on user roles and permissions
Token Management: Secure handling of authentication and refresh tokens
Audit Logging: Comprehensive logging of authentication events

Getting Started
Prerequisites

Python 3.9+
Virtual environment (recommended)

Installation

Clone the repository:

bashgit clone https://github.com/yourusername/blindspotx-auth.git
cd blindspotx_auth

Create and activate a virtual environment:

python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Configure environment variables:

bashcp .env.example .env
# Edit .env with your specific configuration

Run the application:

python run.py
Project Structure
The project follows a modular architecture to separate concerns and facilitate testing: