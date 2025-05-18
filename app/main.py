
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from sqlmodel import select 

from sqlalchemy.ext.asyncio import AsyncSession
import asyncio

from app.api.routes import auth, users, rbac, drift as drift_router
from app.core.config import settings
from app.core.database import create_db_and_tables, get_db
from app.models.user import Permission, User, get_user_permissions
from app.core.security import get_current_user
from app.services.drift_service import detect_drift

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="BlindspotX Secure Authentication API",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Jinja2 setup
templates = Jinja2Templates(directory="templates")

# Serve Tailwind CSS
@app.get("/static/tailwind.css")
async def tailwind_css():
    return RedirectResponse(url="https://cdn.jsdelivr.net/npm/tailwindcss@3.4.1/dist/tailwind.min.css")

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(rbac.router, prefix="/api/rbac", tags=["Roles And Permissions"])
app.include_router(drift_router.router, prefix="/drift", tags=["Drift Detection"])


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
    asyncio.create_task(run_drift_detection_job())

async def run_drift_detection_job():
    while True:
        await detect_drift()
        await asyncio.sleep(1800)  # 30 minutes

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
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "users": users})


@app.get("/login", response_class=HTMLResponse)
async def show_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/users", response_class=HTMLResponse)
async def show_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return templates.TemplateResponse("users.html", {"request": request, "users": users})


@app.get("/roles", response_class=HTMLResponse)
async def show_roles(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    result = await db.execute(select(Role))
    roles = result.scalars().all()
    return templates.TemplateResponse("roles.html", {"request": request, "roles": roles})


@app.get("/permissions", response_class=HTMLResponse)
async def show_permissions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    result = await db.execute(select(Permission))
    permissions = result.scalars().all()
    return templates.TemplateResponse("permissions.html", {
        "request": request,
        "permissions": permissions
    })

@app.get("/ui", response_class=HTMLResponse)
async def drift_dashboard(request: Request):
    """Serve drift dashboard UI"""
    return templates.TemplateResponse("drift.html", {"request": request})