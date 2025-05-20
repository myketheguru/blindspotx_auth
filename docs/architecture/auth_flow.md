# Authentication Flow

## Overview

The BlindspotX Authentication System implements a secure OAuth 2.0 authentication flow in integration with Microsoft Entra ID (formerly Azure AD). This document details the authentication process, token management, and security considerations.

## OAuth 2.0 Authorization Code Flow

The system uses the OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange) for enhanced security. This flow is ideal for web applications as it keeps access tokens secure by handling them server-side.

### Step-by-Step Flow

1. **Initiate Login**: User clicks login button, redirecting to `/api/auth/login`
2. **Authorization Request**: System redirects to Microsoft Entra ID with:
   - Client ID
   - Redirect URI
   - Response type (code)
   - Scope (requested permissions)
   - State (CSRF protection token)
   - PKCE code challenge

3. **User Authentication**: User authenticates with Microsoft credentials
4. **Authorization**: User consents to the requested permissions
5. **Authorization Code**: Microsoft redirects to callback URL with:
   - Authorization code
   - State parameter (for validation)

6. **Token Exchange**: System exchanges authorization code for tokens:
   - Authorization code
   - Client ID and Secret
   - Redirect URI
   - PKCE code verifier

7. **Token Response**: Microsoft returns:
   - Access token (JWT)
   - Refresh token
   - ID token (user information)
   - Token expiration time

8. **Session Creation**: System:
   - Validates tokens
   - Creates user session
   - Securely stores refresh token
   - Sets HTTP-only cookie with access token
   - Redirects to application

## Token Management

### Access Tokens

- **Format**: JWT (JSON Web Token)
- **Signing**: RS256 (asymmetric) for production
- **Lifetime**: 60 minutes by default (configurable)
- **Storage**: HTTP-only, secure, SameSite=Strict cookie
- **Contents**:
  - User identifier
  - Scopes/permissions
  - Expiration time
  - Issuer information

### Refresh Tokens

- **Format**: Opaque token (not JWT)
- **Lifetime**: 7 days by default (configurable)
- **Storage**: Server-side encrypted database
- **Revocation**: Can be revoked through the API

### ID Tokens

- **Format**: JWT
- **Purpose**: Contains user profile information
- **Usage**: Used only during authentication, not stored long-term

## Token Refresh Process

1. **Access Token Expiration**: Frontend detects expired token
2. **Refresh Request**: System sends refresh token to `/api/auth/refresh`
3. **Token Validation**: System validates refresh token
4. **New Token Generation**: If valid, system:
   - Generates new access token
   - Optionally generates new refresh token (rotation)
   - Updates session information
5. **Response**: Returns new tokens to client

## Logout Flow

1. **Logout Request**: User initiates logout at `/api/auth/logout`
2. **Local Session Termination**: System:
   - Invalidates refresh token in database
   - Clears access token cookie
3. **Single Sign-Out**: Optionally redirects to Microsoft logout URL
4. **Completion**: Redirects to post-logout page

## Security Considerations

### Token Protection

- **HTTPS Only**: All token operations require HTTPS
- **HTTP-Only Cookies**: Prevents JavaScript access to tokens
- **Secure Flag**: Ensures tokens only sent over HTTPS
- **SameSite=Strict**: Prevents CSRF attacks
- **Short Lifetimes**: Limits damage from token exposure

### Additional Safeguards

- **CSRF Protection**: State parameter in OAuth flow
- **PKCE Extension**: Prevents authorization code interception
- **IP Binding**: Optional binding of tokens to client IP
- **Device Tracking**: Session linked to device fingerprint
- **Audit Logging**: All token operations are logged

## Integration with RBAC

The authentication system integrates with Role-Based Access Control:

1. **Permission Loading**: User permissions loaded on authentication
2. **Token Enhancement**: Access token includes essential permissions
3. **Authorization Decisions**: Token information used for access control
4. **Role Synchronization**: Roles synced from Microsoft directory (optional)

## Error Handling

The authentication flow includes comprehensive error handling:

- **OAuth Errors**: Structured handling of OAuth error responses
- **Network Issues**: Retry mechanisms for transient failures
- **Invalid Tokens**: Clear error messages for token problems
- **Session Expiration**: Graceful handling of expired sessions

