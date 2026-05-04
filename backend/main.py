"""
ReconMesh backend — main application entrypoint.

Endpoints:
  GET  /                         — landing
  GET  /health                   — health check (backend, DB, Redis)
  POST /domains                  — create a domain row
  GET  /domains/{domain_name}    — fetch all known intel for a domain
  POST /domains/{domain_name}/enrich — run OSINT enrichers on a domain
  GET  /sources                  — list ingested feeds
  POST /feeds/urlhaus/refresh    — pull fresh data from URLhaus
"""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import os
import redis
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from database import SessionLocal, engine, get_db
from models import Domain, Indicator, Source
from schemas import (
    DomainCreate,
    DomainOut,
    EnrichmentOut,
    EnrichResponseOut,
    IngestStatsOut,
    SourceListOut,
)
from ingesters.urlhaus import UrlhausIngester
from enrichers.dns_records import DnsEnricher
from enrichers.email_security import EmailSecurityEnricher
from enrichers.whois_lookup import WhoisEnricher
from enrichers.cert_transparency import CertTransparencyEnricher


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
    name_normalized = payload.name.lower().strip()

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
    Look up a domain by name. Returns the domain plus all linked indicators
    and enrichments. Domain name lookup is case-insensitive.
    """
    name_normalized = domain_name.lower().strip()

    domain: Optional[Domain] = (
        db.query(Domain)
        .options(
            joinedload(Domain.indicators),
            joinedload(Domain.enrichments),
        )
        .filter(Domain.name == name_normalized)
        .first()
    )

    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{name_normalized}' not found",
        )

    return domain


@app.post(
    "/domains/{domain_name}/enrich",
    response_model=EnrichResponseOut,
    summary="Run OSINT enrichers on a domain",
)
def enrich_domain(domain_name: str, db: Session = Depends(get_db)):
    """
    Run all configured enrichers against the domain.

    If the domain doesn't exist yet, it is created automatically — enrichment
    is a useful entry point that doesn't require pre-seeding.

    Each enricher runs independently. One failing does not block others;
    each result includes a status (ok / error / timeout / etc.) and an
    optional error message.

    Re-running this endpoint refreshes existing enrichments (upsert by
    domain + enrichment_type).
    """
    name_normalized = domain_name.lower().strip()

    domain = db.query(Domain).filter(Domain.name == name_normalized).first()
    if domain is None:
        tld = name_normalized.rsplit(".", 1)[-1] if "." in name_normalized else None
        domain = Domain(name=name_normalized, tld=tld)
        db.add(domain)
        db.commit()
        db.refresh(domain)

    enrichers = [
        DnsEnricher(),
        EmailSecurityEnricher(),
        WhoisEnricher(),
        CertTransparencyEnricher(),
    ]

    now = datetime.now(timezone.utc)
    results: list[EnrichmentOut] = []
    for enricher in enrichers:
        result = enricher.run_and_save(db, domain)
        results.append(
            EnrichmentOut(
                enrichment_type=result.enrichment_type.value,
                status=result.status.value,
                data=result.data,
                error_message=result.error_message,
                fetched_at=now,
            )
        )

    return EnrichResponseOut(domain=name_normalized, results=results)


# ----------------------------------------------------------------------------
# Source endpoints
# ----------------------------------------------------------------------------
@app.get(
    "/sources",
    response_model=list[SourceListOut],
    summary="List all ingested sources",
)
def list_sources(db: Session = Depends(get_db)):
    """
    Returns every source we've ingested from, with a count of indicators
    each source has contributed.
    """
    rows = (
        db.query(
            Source,
            func.count(Indicator.id).label("indicator_count"),
        )
        .outerjoin(Indicator, Indicator.source_id == Source.id)
        .group_by(Source.id)
        .order_by(Source.name)
        .all()
    )

    return [
        SourceListOut(
            id=src.id,
            name=src.name,
            source_type=src.source_type.value,
            url=src.url,
            description=src.description,
            indicator_count=count,
        )
        for src, count in rows
    ]


# ----------------------------------------------------------------------------
# Feed ingestion endpoints
# ----------------------------------------------------------------------------
@app.post(
    "/feeds/urlhaus/refresh",
    response_model=IngestStatsOut,
    summary="Pull fresh data from URLhaus and ingest into the database",
)
def refresh_urlhaus(db: Session = Depends(get_db)):
    """
    Synchronously fetch URLhaus's recent CSV and ingest it.
    Existing indicators are updated in place; new ones are inserted.
    May take 10-30 seconds depending on feed size.
    """
    ingester = UrlhausIngester()
    stats = ingester.ingest(db)
    return IngestStatsOut(
        feed="URLhaus",
        fetched_bytes=stats.fetched,
        parsed=stats.parsed,
        inserted=stats.inserted,
        updated=stats.updated,
        skipped=stats.skipped,
        errors=stats.errors,
    )
