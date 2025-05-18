# setup_main_db.py
from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import create_async_engine
import asyncio
from app.models import *  # Import all your models
from app.core.config import settings

async def create_main_tables():
    # Use the main database URL from settings
    database_url = settings.DATABASE_URL.replace("sqlite:///", "sqlite+aiosqlite:///")
    print(f"Creating tables in main database: {database_url}")
    
    engine = create_async_engine(
        database_url,
        connect_args={"check_same_thread": False}
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    
    await engine.dispose()
    print("All tables created successfully in the main database!")

if __name__ == "__main__":
    asyncio.run(create_main_tables())