# Authentication Flow

## Overview

BlindspotX uses OAuth 2.0 with Microsoft Entra ID for secure authentication. This document details the steps involved in the authentication process.

## Authentication Flow Diagram

```
┌──────────┐      1. Login Request      ┌──────────────┐      2. Redirect      ┌────────────────┐
│          │─────────────────────────────>│              │─────────────────────> │                │
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

## Authentication Process

### 1. Initial Authentication Request

When a user attempts to access BlindspotX, they are redirected to the authentication endpoint `/api/auth/login`. If the user is not already authenticated, the following occurs:

1. The system generates a secure state parameter and PKCE code verifier/challenge
2. The user is redirected to Microsoft Entra ID login page with appropriate OAuth parameters
3. The state parameter and code verifier are stored in a server-side session for validation

### 2. Microsoft Authentication

At the Microsoft Entra ID login page:

1. The user enters their credentials
2. Microsoft Entra ID validates the credentials
3. The user consents to the requested permissions (if not previously granted)
4. Microsoft Entra ID redirects back to the BlindspotX callback URL with an authorization code

### 3. Authorization Code Exchange

At the callback endpoint (`/api/auth/callback`):

1. The system validates the state parameter to prevent CSRF attacks
2. The authorization code is exchanged for access and refresh tokens using the PKCE code verifier
3. The Microsoft ID token is validated and parsed
4. User information is extracted from the ID token

### 4. User Management

After successful authentication:

1. If the user doesn't exist in the system, a new user record is created (auto-provisioning)
2. If the user exists, their information is updated if necessary
3. The user's roles and permissions are loaded from the database
4. Access and refresh tokens are securely stored

### 5. Session Establishment

To complete the authentication:

1. A session is established with the user
2. An access token (JWT) is created with user identity and role information
3. The access token is provided to the client as an HTTP-only, secure cookie
4. The refresh token is securely stored in the database with a reference token provided to the client
5. The user is redirected to the application's main page

## Token Refresh Process

When an access token expires:

1. The client sends the refresh token to `/api/auth/refresh`
2. The system validates the refresh token
3. If valid, a new access token is issued
4. Optionally, a new refresh token is generated (token rotation)
5. The new tokens are returned to the client

## Logout Process

When a user logs out:

1. The client sends a request to `/api/auth/logout`
2. The session is invalidated
3. The refresh token is added to a blocklist or deleted
4. Cookies are cleared
5. The user is redirected to the login page or home page

## Security Considerations

- All tokens are validated for authenticity and expiration
- HTTP-only secure cookies prevent JavaScript access to tokens
- CSRF protection via state parameters and tokens
- Token encryption for sensitive storage
- Token revocation mechanisms for logout and security events
- Rate limiting to prevent brute force attacks

# Authentication Flow

This document describes the authentication flow between the client, BlindspotX Auth service, and Microsoft Entra ID.

## OAuth2 Authorization Code Flow

BlindspotX Auth uses the OAuth2 Authorization Code flow with PKCE (Proof Key for Code Exchange) for secure authentication with Microsoft Entra ID. This flow involves the following steps:

1. **Login Request**: The client initiates the login process by accessing the BlindspotX Auth login endpoint.
2. **Redirect to Microsoft Entra ID**: BlindspotX Auth redirects the client to Microsoft Entra ID's authorization endpoint.
3. **User Authentication**: The user authenticates with Microsoft Entra ID using their credentials.
4. **Authorization Code**: Microsoft Entra ID redirects back to BlindspotX Auth with an authorization code.
5. **Token Exchange**: BlindspotX Auth exchanges the authorization code for access and refresh tokens.
6. **Secure Storage**: Tokens are securely stored, with access tokens delivered to the client via HTTP-only cookies.
7. **Response to Client**: BlindspotX Auth responds to the client with a successful authentication message.

## Flow Diagram

The authentication flow is illustrated in the following diagram:

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

## Token Management

The system manages several types of tokens:

1. **Access Tokens**: 
   - Short-lived JWT tokens (default: 60 minutes)
   - Contain user claims and permissions
   - Delivered via HTTP-only, secure cookies

2. **Refresh Tokens**:
   - Longer-lived tokens (default: 7 days)
   - Securely stored in the encrypted database
   - Used to obtain new access tokens when they expire

3. **ID Tokens**:
   - Contains user identity information
   - Used for user profile initialization

## Implementation Details

### Token Security Measures

- Access tokens are signed using RS256 (asymmetric) for production environments
- Refresh tokens are stored with one-way hashing
- Tokens include standard claims (exp, iat, iss, sub) and custom claims for permissions
- Token validation includes signature verification, expiration checking, and issuer validation

### Authentication Endpoints

- `GET /api/auth/login`: Initiates OAuth2 login flow with Microsoft Entra ID
- `GET /api/auth/callback`: OAuth2 callback handler
- `POST /api/auth/refresh`: Refreshes access token using refresh token
- `POST /api/auth/logout`: Logs out user and invalidates tokens

### Code Examples

Initiating the Authentication Flow:

```python
@router.get("/login", name="auth:login")
async def login(request: Request):
    redirect_uri = request.url_for("auth:callback")
    auth_url = oauth_client.get_authorization_url(redirect_uri, scope=["openid", "profile", "email"])
    return RedirectResponse(auth_url)
```

## Related Documentation

- [Authorization Flow](./authorization_flow.md)
- [Secure Token Management](../security/token_management.md)
- [OAuth2 Configuration](../operations/oauth_configuration.md)

