"""
ReconMesh backend — main application entrypoint.
Minimal MVP: a /health endpoint that proves the stack is alive.
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
import redis


# ----------------------------------------------------------------------------
# Configuration — read from environment variables (set by docker-compose)
# ----------------------------------------------------------------------------
POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]
POSTGRES_DB = os.environ["POSTGRES_DB"]
POSTGRES_HOST = os.environ["POSTGRES_HOST"]
POSTGRES_PORT = os.environ["POSTGRES_PORT"]
REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = int(os.environ["REDIS_PORT"])

DATABASE_URL = (
    f"postgresql+psycopg://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)


# ----------------------------------------------------------------------------
# Connection setup
# ----------------------------------------------------------------------------
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs on startup and shutdown — for now just confirms connections."""
    # Startup
    print("ReconMesh backend starting up...")
    yield
    # Shutdown
    print("ReconMesh backend shutting down...")
    engine.dispose()


# ----------------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------------
app = FastAPI(
    title="ReconMesh API",
    description="Domain-centric OSINT aggregator for cyber threat intelligence",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/")
def root():
    """Tiny landing endpoint — useful sanity check."""
    return {
        "name": "ReconMesh",
        "version": "0.1.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    """
    Health check — verifies backend is alive AND can reach
    both PostgreSQL and Redis. Used by Docker's HEALTHCHECK.
    Returns HTTP 200 if all good, 503 otherwise.
    """
    checks = {
        "backend": "ok",
        "database": "unknown",
        "redis": "unknown",
    }
    healthy = True

    # Database check
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except SQLAlchemyError as e:
        checks["database"] = f"error: {type(e).__name__}"
        healthy = False

    # Redis check
    try:
        if redis_client.ping():
            checks["redis"] = "ok"
        else:
            checks["redis"] = "no pong"
            healthy = False
    except redis.RedisError as e:
        checks["redis"] = f"error: {type(e).__name__}"
        healthy = False

    return {"healthy": healthy, "checks": checks}