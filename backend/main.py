"""
ReconMesh backend — main application entrypoint.

Endpoints:
  GET  /                        — landing
  GET  /health                  — health check (backend, DB, Redis)
  POST /domains                 — create a domain row
  GET  /domains/{domain_name}   — fetch all known intel for a domain
"""
from contextlib import asynccontextmanager
from typing import Optional

import os
import redis
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from database import SessionLocal, engine, get_db
from models import Domain
from schemas import DomainCreate, DomainOut


# ----------------------------------------------------------------------------
# Redis client (used by /health only for now)
# ----------------------------------------------------------------------------
REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = int(os.environ["REDIS_PORT"])
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


# ----------------------------------------------------------------------------
# App lifecycle
# ----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("ReconMesh backend starting up...")
    yield
    print("ReconMesh backend shutting down...")
    engine.dispose()


app = FastAPI(
    title="ReconMesh API",
    description="Domain-centric OSINT aggregator for cyber threat intelligence",
    version="0.1.0",
    lifespan=lifespan,
)


# ----------------------------------------------------------------------------
# Basic endpoints
# ----------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "name": "ReconMesh",
        "version": "0.1.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    """Health check — backend + database + Redis."""
    checks = {"backend": "ok", "database": "unknown", "redis": "unknown"}
    healthy = True

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except SQLAlchemyError as e:
        checks["database"] = f"error: {type(e).__name__}"
        healthy = False

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


# ----------------------------------------------------------------------------
# Domain endpoints
# ----------------------------------------------------------------------------
@app.post(
    "/domains",
    response_model=DomainOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a domain row",
)
def create_domain(payload: DomainCreate, db: Session = Depends(get_db)):
    """
    Create a new domain entry. Domain name must be unique.
    Used during ingestion (Session 4) and for manual analyst entry.
    """
    # Normalize: domain names are case-insensitive
    name_normalized = payload.name.lower().strip()

    # Derive TLD if not provided
    tld = payload.tld
    if tld is None and "." in name_normalized:
        tld = name_normalized.rsplit(".", 1)[-1]

    domain = Domain(
        name=name_normalized,
        tld=tld,
        risk_score=payload.risk_score,
    )

    db.add(domain)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain '{name_normalized}' already exists",
        )

    db.refresh(domain)
    return domain


@app.get(
    "/domains/{domain_name}",
    response_model=DomainOut,
    summary="Fetch everything known about a domain",
)
def get_domain(domain_name: str, db: Session = Depends(get_db)):
    """
    Look up a domain by name. Returns the domain plus all linked indicators.
    Domain name lookup is case-insensitive.
    """
    name_normalized = domain_name.lower().strip()

    # joinedload eagerly fetches the indicators in one query (avoiding N+1)
    domain: Optional[Domain] = (
        db.query(Domain)
        .options(joinedload(Domain.indicators))
        .filter(Domain.name == name_normalized)
        .first()
    )

    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{name_normalized}' not found",
        )

    return domain