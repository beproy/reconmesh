"""
Database connection setup for ReconMesh.

This module owns the SQLAlchemy engine and session factory.
All other parts of the codebase that need DB access import from here.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


# ----------------------------------------------------------------------------
# Connection string — read from environment (set by docker-compose or local .env)
# ----------------------------------------------------------------------------
POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]
POSTGRES_DB = os.environ["POSTGRES_DB"]
POSTGRES_HOST = os.environ["POSTGRES_HOST"]
POSTGRES_PORT = os.environ["POSTGRES_PORT"]

DATABASE_URL = (
    f"postgresql+psycopg://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)


# ----------------------------------------------------------------------------
# Engine & session factory
# ----------------------------------------------------------------------------
# pool_pre_ping=True: silently checks for dead connections before reusing them
# pool_size=5: how many connections to keep open (small is fine for our scale)
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

# SessionLocal is the factory; calling it returns a new database session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class that all our models inherit from
Base = declarative_base()


# ----------------------------------------------------------------------------
# Dependency for FastAPI: yields a session, ensures cleanup
# ----------------------------------------------------------------------------
def get_db():
    """
    FastAPI dependency that gives an endpoint a fresh DB session
    and guarantees it gets closed (even if an exception happens).

    Used like: def my_endpoint(db: Session = Depends(get_db))
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()