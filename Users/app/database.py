import asyncpg
from dotenv import load_dotenv
import os
import logging

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

# Initialize logger
logger = logging.getLogger(__name__)

# Global variable for the asyncpg pool
db_pool = None

async def init_db_pool():
    global db_pool
    if db_pool is None:
        try:
            db_pool = await asyncpg.create_pool(
                dsn=DATABASE_URL,
                min_size=5,  # Minimum number of connections
                max_size=20,  # Maximum number of connections
                command_timeout=60  # Timeout for queries
            )
            logger.info("Asyncpg connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize asyncpg pool: {str(e)}")
            raise
    return db_pool

async def close_db_pool():
    global db_pool
    if db_pool is not None:
        await db_pool.close()
        logger.info("Asyncpg connection pool closed")
        db_pool = None

async def get_db():
    if db_pool is None:
        await init_db_pool()
    async with db_pool.acquire() as conn:
        yield conn