from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.exception_handlers import http_exception_handler

from app.core.celery_app import celery_app

from sqlmodel import select 

from sqlalchemy.ext.asyncio import AsyncSession
import asyncio
import logging
import time
from uuid import UUID

from app.api.routes import auth, users, rbac, drift as drift_router, drift_celery
from app.core.config import settings
from app.core.database import create_db_and_tables, get_db
from app.models.user import Permission, User, Role, get_user_permissions
from app.core.security import get_current_user
from app.services.drift_service import detect_drift
from app.core.observability import (
    initialize_metrics, setup_tracing, get_component_health,
    AUTH_REQUEST_COUNTER, API_REQUEST_DURATION, ACTIVE_USERS_GAUGE
)

# Configure logging
logging.basicConfig(
    level=logging.INFO if settings.DEBUG else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="BlindspotX Secure Authentication API",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Set up observability
initialize_metrics(app)
tracer = setup_tracing()

# Configure CORS with enhanced security
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "X-CSRF-Token"],
    expose_headers=["X-Request-ID", "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining", "X-Rate-Limit-Reset"],
    max_age=86400,  # 24 hours
)

# Add middleware to track API request duration
@app.middleware("http")
async def add_metrics_middleware(request: Request, call_next):
    # Record the start time
    start_time = time.time()
    
    # Process the request
    response = await call_next(request)
    
    # Record the response time
    duration = time.time() - start_time
    
    # Extract the path without query parameters
    path = request.url.path
    
    # Record the metric
    API_REQUEST_DURATION.labels(
        endpoint=path,
        method=request.method,
        status_code=response.status_code
    ).observe(duration)
    
    return response

# Jinja2 setup
templates = Jinja2Templates(directory="templates")

# Custom dependency for HTML routes that redirects to login on auth failure
async def get_current_user_html(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Dependency for HTML routes to handle authentication with proper cookie management.
    Returns the user object if authenticated, or redirects to login if not.
    """
    logger = logging.getLogger("auth.html")
    
    try:
        # Log all headers and cookies for comprehensive debugging
        logger.info(f"Request path: {request.url.path}")
        logger.info(f"Request headers: {request.headers}")
        logger.info(f"All available cookies: {request.cookies}")
        
        # Extract all possible sources of the token
        auth_header = request.headers.get("Authorization", "")
        cookie_token = request.cookies.get("access_token")
        
        # Log token sources
        logger.info(f"Auth header present: {bool(auth_header)}")
        logger.info(f"Cookie token present: {bool(cookie_token)}")
        
        # Prioritize cookie token
        token = cookie_token
        
        # If no cookie token, try Authorization header
        if not token and auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            logger.info("Using token from Authorization header")
        
        if not token:
            logger.warning("No access_token found in cookies or Authorization header")
            response = RedirectResponse(url="/login", status_code=307)
            return response
        
        logger.info(f"Found access_token: {token[:10]}...")
        
        try:
            # Use decode_token from security.py
            from app.core.security import decode_token
            payload = await decode_token(token)
            
            email = payload.get("sub")
            if email:
                # Fetch user from DB
                from app.models.user import get_user_by_email
                user = await get_user_by_email(email, db)
                if user and user.is_active:
                    logger.info(f"Successfully authenticated user: {email}")
                    return user
                else:
                    logger.warning(f"User not found or inactive: {email}")
            else:
                logger.warning("No email found in token payload")
                
        except Exception as token_error:
            logger.error(f"Token validation error: {str(token_error)}")
            
        # If we get here, authentication failed
        response = RedirectResponse(url="/login", status_code=307)
        return response
        
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        response = RedirectResponse(url="/login", status_code=307)
        return response

# Tailwind CSS is now loaded directly via CDN in base.html
# @app.get("/static/tailwind.css")
# async def tailwind_css():
#     # Serve Tailwind CSS directly instead of redirecting
#     content = """/* Tailwind CSS v3.4.1 */
# @import url('https://cdn.tailwindcss.com');
# """
#     return Response(content=content, media_type="text/css")

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(rbac.router, prefix="/api/rbac", tags=["Roles And Permissions"])
app.include_router(drift_celery.router, prefix="/api/drift", tags=["Drift Detection"])


# Base permissions to seed
BASE_PERMISSIONS = [
    {"name": "read:users", "description": "Read user information"},
    {"name": "create:users", "description": "Create new users"},
    {"name": "update:users", "description": "Update user information"},
    {"name": "delete:users", "description": "Delete users"},
    {"name": "read:roles", "description": "View roles"},
    {"name": "create:roles", "description": "Create new roles"},
    {"name": "update:roles", "description": "Update roles"},
    {"name": "delete:roles", "description": "Delete roles"},
    {"name": "assign:roles", "description": "Assign roles to users"},
    {"name": "assign:permissions", "description": "Assign permissions to roles"},
]

@app.on_event("startup")
async def startup_event():
    await create_db_and_tables()
    await seed_base_permissions()
    # asyncio.create_task(run_drift_detection_job())
     # Celery will handle the background tasks, no need to start them here
    logger.info("Application started - Celery tasks will handle drift detection")

# async def run_drift_detection_job():
#     while True:
#         await detect_drift()
#         await asyncio.sleep(1800)  # 30 minutes

async def seed_base_permissions():
    """Seed base permissions into the database"""
    try:
        async for db in get_db():
            for perm_data in BASE_PERMISSIONS:
                result = await db.execute(
                    select(Permission).where(Permission.name == perm_data["name"])
                )
                existing = result.scalars().first()
                if not existing:
                    permission = Permission(**perm_data)
                    db.add(permission)
            await db.commit()
    except Exception as e:
        print(f"Error seeding base permissions: {str(e)}")

# Health check 
@app.get("/api/health", tags=["Health"])
async def health_check():
    return {"status": "ok"}


# HTML ROUTES
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user = Depends(get_current_user_html),
    db: AsyncSession = Depends(get_db)
):
    """
    Dashboard view that requires authentication.
    The get_current_user_html dependency will redirect to login if not authenticated.
    """
    # Log the authentication attempt
    logger = logging.getLogger("dashboard")
    logger.info(f"Dashboard access attempt - User: {getattr(user, 'email', None)}")
    
    # If user is a RedirectResponse, it means authentication failed
    if isinstance(user, RedirectResponse):
        logger.warning("Authentication failed, redirecting to login")
        return user
    
    # User is authenticated, proceed with dashboard
    result = await db.execute(select(User))
    users = result.scalars().all()
    
    # Get permissions for the user
    permissions = await get_user_permissions(user.id, db)
    
    logger.info(f"Rendering dashboard for user: {user.email}")
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "users": users,
        "user": user,
        "permissions": permissions
    })


@app.get("/login", response_class=HTMLResponse)
async def show_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/logout")
async def logout():
    """Handle logout by clearing the access token cookie"""
    logger = logging.getLogger("auth")
    logger.info("User logging out, clearing access_token cookie")
    
    response = RedirectResponse(url="/login", status_code=307)
    response.delete_cookie(
        key="access_token",
        path="/",  # Must match the path used when setting
        httponly=True,
        samesite="lax"
    )
    return response


@app.get("/users", response_class=HTMLResponse)
async def show_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user_html)  # Use the custom HTML dependency
):
    # If we get here, user is authenticated or redirected to login
    if isinstance(user, RedirectResponse):
        return user
    
    result = await db.execute(select(User))
    users = result.scalars().all()
    return templates.TemplateResponse("users.html", {"request": request, "users": users, "user": user})


@app.get("/roles", response_class=HTMLResponse)
async def show_roles(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user_html)  # Use the custom HTML dependency
):
    """
    Display roles management interface with proper permissions context.
    Requires authentication, and shows appropriate controls based on user permissions.
    """
    logger = logging.getLogger("roles")
    
    # If we get here, user is authenticated or redirected to login
    if isinstance(user, RedirectResponse):
        return user
    
    try:
        # Get all roles
        result = await db.execute(select(Role))
        roles = result.scalars().all()
        
        # Get all permissions for the permission selection interface
        perm_result = await db.execute(select(Permission))
        permissions = perm_result.scalars().all()
        
        # Get user's permissions to check access control
        user_permissions = await get_user_permissions(user.id, db)
        
        logger.info(f"Displaying roles for user {user.email} with permissions: {', '.join(user_permissions)}")
        
        # Render template with all necessary context
        return templates.TemplateResponse(
            "roles.html", 
            {
                "request": request, 
                "roles": roles, 
                "permissions": permissions,
                "user": user,
                "user_permissions": user_permissions,
                "csrf_token": "your-csrf-token-here"  # Replace with actual CSRF token generation
            }
        )
    except Exception as e:
        logger.error(f"Error displaying roles: {str(e)}")
        # Handle errors gracefully with an error message
        return templates.TemplateResponse(
            "error.html", 
            {
                "request": request,
                "user": user,
                "error_message": "An error occurred while loading roles data. Please try again later.",
                "error_details": str(e) if settings.DEBUG else None  # Only show details in debug mode
            },
            status_code=500
        )


@app.get("/permissions", response_class=HTMLResponse)
async def show_permissions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user_html)  # Use the custom HTML dependency
):
    # If we get here, user is authenticated or redirected to login
    if isinstance(user, RedirectResponse):
        return user
    
    result = await db.execute(select(Permission))
    permissions = result.scalars().all()
    return templates.TemplateResponse("permissions.html", {
        "request": request, 
        "permissions": permissions,
        "user": user
    })


# ===================================
# HTMX Routes for Role Management
# ===================================

@app.get("/api/rbac/roles/create-form", response_class=HTMLResponse)
async def roles_create_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user_html)
):
    """Return the create role form for HTMX"""
    if isinstance(user, RedirectResponse):
        return user
    
    # Check if user has permission to create roles
    user_permissions = await get_user_permissions(user.id, db)
    if "create:roles" not in user_permissions:
        return HTMLResponse(
            content="Permission denied. You do not have the required permissions to create roles.",
            status_code=403
        )
    
    # Get all permissions for the form
    result = await db.execute(select(Permission))
    permissions = result.scalars().all()
    
    # Use Jinja2 template string for the create form
    return templates.TemplateResponse(
        "roles_create_form.html",
        {
            "request": request,
            "permissions": permissions,
            "user": user,
            "csrf_token": "your-csrf-token-here"  # Replace with actual CSRF token generation
        }
    )


@app.get("/api/rbac/roles/{role_id}/edit-form", response_class=HTMLResponse)
async def roles_edit_form(
    role_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user_html)
):
    """Return the edit role form for HTMX"""
    if isinstance(user, RedirectResponse):
        return user
    
    # Check if user has permission to update roles
    user_permissions = await get_user_permissions(user.id, db)
    if "update:roles" not in user_permissions:
        return HTMLResponse(
            content="Permission denied. You do not have the required permissions to edit roles.",
            status_code=403
        )
    
    # Get the role by ID
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalars().first()
    if not role:
        return HTMLResponse(
            content=f"Role with ID {role_id} not found.",
            status_code=404
        )
    
    # Get all permissions for the form
    permissions_result = await db.execute(select(Permission))
    permissions = permissions_result.scalars().all()
    
    # Get permissions assigned to this role
    role_permissions_result = await db.execute(
        select(RolePermission.permission_id).where(RolePermission.role_id == role_id)
    )
    role_permissions = [str(rp[0]) for rp in role_permissions_result.all()]
    
    # Return the edit form with role data
    return templates.TemplateResponse(
        "roles_edit_form.html",
        {
            "request": request,
            "role": role,
            "permissions": permissions,
            "role_permissions": role_permissions,
            "user": user,
            "csrf_token": "your-csrf-token-here"  # Replace with actual CSRF token generation
        }
    )


@app.get("/api/rbac/roles/{role_id}/delete-confirm", response_class=HTMLResponse)
async def roles_delete_confirm(
    role_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user_html)
):
    """Return the delete confirmation for HTMX"""
    if isinstance(user, RedirectResponse):
        return user
    
    # Check if user has permission to delete roles
    user_permissions = await get_user_permissions(user.id, db)
    if "delete:roles" not in user_permissions:
        return HTMLResponse(
            content="Permission denied. You do not have the required permissions to delete roles.",
            status_code=403
        )
    
    # Get the role by ID
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalars().first()
    if not role:
        return HTMLResponse(
            content=f"Role with ID {role_id} not found.",
            status_code=404
        )
    
    # Return the delete confirmation dialog
    return templates.TemplateResponse(
        "roles_delete_confirm.html",
        {
            "request": request,
            "role": role,
            "user": user,
            "csrf_token": "your-csrf-token-here"  # Replace with actual CSRF token generation
        }
    )


# Update the existing HTML route for drift dashboard
@app.get("/ui", response_class=HTMLResponse)
async def drift_dashboard(
    request: Request,
    user = Depends(get_current_user_html)
):
    """Serve drift dashboard UI with Celery integration"""
    if isinstance(user, RedirectResponse):
        return user
    
    # You can add context about Celery task status here
    celery_inspect = celery_app.control.inspect()
    worker_stats = celery_inspect.stats()
    
    dashboard_context = {
        "request": request, 
        "user": user,
        "celery_workers_active": len(worker_stats) if worker_stats else 0,
        "system_healthy": bool(worker_stats)
    }
    
    return templates.TemplateResponse("drift.html", dashboard_context)


@app.get("/auth-debug", response_class=HTMLResponse)
async def auth_debug(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Detailed authentication debug route that shows:
    1. All cookies
    2. Token extraction
    3. Token validation attempt
    4. User lookup attempt
    """
    debug_info = {
        "cookies": request.cookies,
        "token_extraction": None,
        "token_validation": None,
        "user_lookup": None,
        "final_result": None
    }
    
    # Step 1: Extract token from cookie
    token = request.cookies.get("access_token")
    debug_info["token_extraction"] = {
        "found": token is not None,
        "value_preview": token[:10] + "..." if token and len(token) > 10 else token
    }
    
    # Step 2: Try to validate token
    if token:
        try:
            from app.core.security import decode_token
            payload = await decode_token(token)
            debug_info["token_validation"] = {
                "success": True,
                "payload": payload
            }
            
            # Step 3: Try to get user
            email = payload.get("sub")
            if email:
                from app.models.user import get_user_by_email
                user = await get_user_by_email(email, db)
                debug_info["user_lookup"] = {
                    "email": email,
                    "user_found": user is not None,
                    "user_active": user.is_active if user else None
                }
                
                # Step 4: Final result
                if user and user.is_active:
                    debug_info["final_result"] = "Authentication would succeed"
                else:
                    debug_info["final_result"] = "User not found or not active"
            else:
                debug_info["final_result"] = "No email in token payload"
        except Exception as e:
            debug_info["token_validation"] = {
                "success": False,
                "error": str(e)
            }
            debug_info["final_result"] = f"Token validation failed: {str(e)}"
    else:
        debug_info["final_result"] = "No token found in cookies"
    
    # Return a formatted HTML response
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authentication Debug</title>
        <link href="/static/tailwind.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 p-8">
        <div class="max-w-3xl mx-auto bg-white p-6 rounded shadow">
            <h1 class="text-2xl font-bold mb-6">Authentication Debug</h1>
            
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">Cookies</h2>
                <div class="bg-gray-50 p-4 rounded">
                    <pre class="whitespace-pre-wrap">{debug_info['cookies']}</pre>
                </div>
            </div>
            
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">Token Extraction</h2>
                <div class="bg-gray-50 p-4 rounded">
                    <pre class="whitespace-pre-wrap">{debug_info['token_extraction']}</pre>
                </div>
            </div>
            
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">Token Validation</h2>
                <div class="bg-gray-50 p-4 rounded">
                    <pre class="whitespace-pre-wrap">{debug_info['token_validation']}</pre>
                </div>
            </div>
            
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">User Lookup</h2>
                <div class="bg-gray-50 p-4 rounded">
                    <pre class="whitespace-pre-wrap">{debug_info['user_lookup']}</pre>
                </div>
            </div>
            
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">Final Result</h2>
                <div class="bg-gray-50 p-4 rounded font-bold">
                    {debug_info['final_result']}
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

# Add this at the end of your main.py file
# This route is now just a pass-through to the auth.py implementation which sets the cookie
@app.get("/api/auth/callback", include_in_schema=False)
async def fixed_auth_callback(
    request: Request,
    code: str = None,
    state: str = None,
    error: str = None,
    error_description: str = None,
    db: AsyncSession = Depends(get_db)
):
    """Fixed OAuth2 callback handler that properly passes through to auth.py"""
    logger = logging.getLogger("auth.callback")
    
    try:
        # Import the original callback
        from app.api.routes.auth import auth_callback as original_callback
        
        # Call the original callback which now handles cookie setting directly
        result = await original_callback(
            request=request,
            code=code,
            state=state,
            error=error,
            error_description=error_description,
            db=db
        )
        
        # Debug logging
        logger.info(f"Auth callback result type: {type(result)}")
        
        # Make sure we're using status 307 for any redirect to preserve cookies
        if isinstance(result, RedirectResponse) and result.status_code != 307:
            logger.info(f"Changing redirect status from {result.status_code} to 307 to preserve cookies")
            return RedirectResponse(url=result.headers.get('location'), status_code=307)
            
        # Return the original result from auth.py
        return result
        
    except Exception as e:
        logger.error(f"Error in fixed callback: {str(e)}")
        return RedirectResponse(url="/login", status_code=307)
