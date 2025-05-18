
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sqlmodel import select 

from app.api.routes import auth, users, rbac
from app.core.config import settings
from app.core.database import create_db_and_tables, get_db
from app.models.user import Permission

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

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(rbac.router, prefix="/api/rbac", tags=["Roles And Permissions"])


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