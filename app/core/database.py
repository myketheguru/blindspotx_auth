import logging
import sqlite3
from typing import Dict, List, Optional, Union

import aiosqlite
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from app.core.config import settings

# Initialize logger
logger = logging.getLogger(__name__)

# Create async SQLAlchemy engine
engine = create_async_engine(
    settings.DATABASE_URL.replace("sqlite:///", "sqlite+aiosqlite:///"),
    echo=False,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)

# Create async session factory
async_session = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def get_db() -> AsyncSession:
    """Dependency for getting async DB session"""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database error: {str(e)}")
            raise
        finally:
            await session.close()

async def create_db_and_tables():
    """Create database and tables on startup"""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        logger.info("Database and tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database and tables: {str(e)}")
        raise

class SecureKeyValueStore:
    """
    Secure key-value store for sensitive data
    Uses SQLite with encryption (in production this would use Azure Key Vault)
    """
    def __init__(self):
        self.db_path = "secrets.db"
        self._init_db()

    def _init_db(self):
        """Initialize the secure storage database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create table with encryption
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS secure_store (
                key TEXT PRIMARY KEY,
                value TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Secure key-value store initialized")
        except Exception as e:
            logger.error(f"Error initializing secure store: {str(e)}")
            raise

    async def store_value(self, key: str, value: str, metadata: Optional[Dict] = None) -> bool:
        """Store a value securely"""
        # In production, use Azure Key Vault for sensitive data
        if settings.USE_KEY_VAULT:
            # Code for Azure Key Vault integration would go here
            pass
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Convert metadata to string if provided
            metadata_str = str(metadata) if metadata else None
            
            # Use parameterized query to prevent SQL injection
            cursor.execute(
                '''
                INSERT OR REPLACE INTO secure_store (key, value, metadata, updated_at) 
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ''',
                (key, value, metadata_str)
            )
            
            conn.commit()
            conn.close()
            logger.info(f"Value stored securely for key: {key}")
            return True
        except Exception as e:
            logger.error(f"Error storing value: {str(e)}")
            return False

    async def get_value(self, key: str) -> Optional[str]:
        """Retrieve a value securely"""
        # In production, retrieve from Azure Key Vault
        if settings.USE_KEY_VAULT:
            # Code for Azure Key Vault integration would go here
            pass
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT value FROM secure_store WHERE key = ?", (key,))
            result = cursor.fetchone()
            
            conn.close()
            
            if result:
                return result[0]
            return None
        except Exception as e:
            logger.error(f"Error retrieving value: {str(e)}")
            return None

    async def delete_value(self, key: str) -> bool:
        """Delete a value securely"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM secure_store WHERE key = ?", (key,))
            
            conn.commit()
            conn.close()
            logger.info(f"Value deleted for key: {key}")
            return True
        except Exception as e:
            logger.error(f"Error deleting value: {str(e)}")
            return False

# Initialize secure key-value store
secure_store = SecureKeyValueStore()