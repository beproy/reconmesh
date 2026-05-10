"""
ReconMesh backend — main application entrypoint.

Endpoints:
  GET  /                                  — landing
  GET  /health                            — health check (backend, DB, Redis)
  POST /domains                           — create a domain row
  GET  /domains/{domain_name}             — fetch all known intel for a domain
  POST /domains/{domain_name}/enrich      — DISPATCH async enrichment, return job_id
  GET  /domains/{domain_name}/enrich/{job_id} — poll job progress
  GET  /sources                           — list ingested feeds
  POST /feeds/urlhaus/refresh             — pull fresh data from URLhaus
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
from models import (
    Domain,
    Enrichment,
    EnrichmentJob,
    EnrichmentJobStatus,
    EnrichmentType,
    Indicator,
    Source,
)
from schemas import (
    DomainCreate,
    DomainListItem,
    DomainOut,
    EnrichJobDispatchedOut,
    EnrichJobStatusOut,
    IngestStatsOut,
    SourceListOut,
)
from ingesters.urlhaus import UrlhausIngester
from tasks.enrichment_tasks import TASK_FOR_ENRICHMENT_TYPE


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
    version="0.2.0",  # Bumped for async enrichment
    lifespan=lifespan,
)


# ----------------------------------------------------------------------------
# Basic endpoints
# ----------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "name": "ReconMesh",
        "version": "0.2.0",
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
@app.get(
    "/domains",
    response_model=list[DomainListItem],
    summary="Browse all domains with filtering and sorting",
)
def list_domains(
    search: Optional[str] = None,
    tld: Optional[str] = None,
    has_indicators: Optional[bool] = None,
    has_enrichments: Optional[bool] = None,
    sort_by: str = "name",
    sort_dir: str = "asc",
    page: int = 1,
    page_size: int = 25,
    db: Session = Depends(get_db),
):
    """
    Paginated domain listing with optional filters and sorting.
    Used by the home page browse view.
    """
    query = (
        db.query(
            Domain,
            func.count(func.distinct(Indicator.id)).label("indicator_count"),
            func.count(func.distinct(Enrichment.id)).label("enrichment_count"),
        )
        .outerjoin(Indicator, Indicator.domain_id == Domain.id)
        .outerjoin(Enrichment, Enrichment.domain_id == Domain.id)
        .group_by(Domain.id)
    )

    if search:
        query = query.filter(Domain.name.ilike(f"%{search.strip().lower()}%"))
    if tld:
        query = query.filter(Domain.tld == tld.strip().lower())
    if has_indicators is True:
        query = query.having(func.count(func.distinct(Indicator.id)) > 0)
    elif has_indicators is False:
        query = query.having(func.count(func.distinct(Indicator.id)) == 0)
    if has_enrichments is True:
        query = query.having(func.count(func.distinct(Enrichment.id)) > 0)
    elif has_enrichments is False:
        query = query.having(func.count(func.distinct(Enrichment.id)) == 0)

    sort_columns = {
        "name": Domain.name,
        "tld": Domain.tld,
        "first_seen": Domain.first_seen,
        "last_seen": Domain.last_seen,
        "risk_score": Domain.risk_score,
        "indicator_count": func.count(func.distinct(Indicator.id)),
        "enrichment_count": func.count(func.distinct(Enrichment.id)),
    }
    sort_col = sort_columns.get(sort_by, Domain.name)
    if sort_dir.lower() == "desc":
        sort_col = sort_col.desc()
    else:
        sort_col = sort_col.asc()
    query = query.order_by(sort_col)

    offset = (max(page, 1) - 1) * page_size
    rows = query.offset(offset).limit(page_size).all()

    return [
        DomainListItem(
            id=domain.id,
            name=domain.name,
            tld=domain.tld,
            risk_score=domain.risk_score,
            first_seen=domain.first_seen,
            last_seen=domain.last_seen,
            indicator_count=ind_count,
            enrichment_count=enr_count,
        )
        for domain, ind_count, enr_count in rows
    ]


@app.post(
    "/domains",
    response_model=DomainOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a domain row",
)
def create_domain(payload: DomainCreate, db: Session = Depends(get_db)):
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
    response_model=EnrichJobDispatchedOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Dispatch async enrichment tasks for a domain",
)
def enrich_domain(domain_name: str, db: Session = Depends(get_db)):
    """
    Async enrichment. We:
      1. Find or create the domain row
      2. Create an EnrichmentJob row to track this batch
      3. Dispatch one Celery task per enricher (parallel execution)
      4. Return the job_id immediately

    The frontend then polls GET /domains/{name}/enrich/{job_id} until the
    job status becomes 'completed' or 'failed', and refetches the domain
    dossier when done to pick up the new enrichment data.
    """
    name_normalized = domain_name.lower().strip()

    # Find or create the domain
    domain = db.query(Domain).filter(Domain.name == name_normalized).first()
    if domain is None:
        tld = name_normalized.rsplit(".", 1)[-1] if "." in name_normalized else None
        domain = Domain(name=name_normalized, tld=tld)
        db.add(domain)
        db.commit()
        db.refresh(domain)

    # Decide which enrichers to run. For now we always run all of them.
    # Future: accept a request body with a subset of enrichers.
    enrichment_types = list(TASK_FOR_ENRICHMENT_TYPE.keys())

    # Create the EnrichmentJob row
    job = EnrichmentJob(
        domain_id=domain.id,
        status=EnrichmentJobStatus.PENDING,
        total_tasks=len(enrichment_types),
        completed_tasks=0,
        failed_tasks=0,
        enrichment_types_csv=",".join(et.value for et in enrichment_types),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Dispatch one Celery task per enricher.
    # We use `.delay()` for clarity — fire and forget. Each task gets the
    # same job_id and works against it independently.
    for et in enrichment_types:
        task = TASK_FOR_ENRICHMENT_TYPE[et]
        task.delay(job_id=job.id, domain_id=domain.id, domain_name=name_normalized)

    return EnrichJobDispatchedOut(
        job_id=job.id,
        domain=name_normalized,
        enrichment_types=[et.value for et in enrichment_types],
        poll_url=f"/domains/{name_normalized}/enrich/{job.id}",
    )


@app.get(
    "/domains/{domain_name}/enrich/{job_id}",
    response_model=EnrichJobStatusOut,
    summary="Get the status of an async enrichment job",
)
def get_enrich_job(
    domain_name: str,
    job_id: int,
    db: Session = Depends(get_db),
):
    """
    Returns the current state of an enrichment job. The frontend polls this
    every couple of seconds until status becomes 'completed' or 'failed'.
    """
    name_normalized = domain_name.lower().strip()

    domain = db.query(Domain).filter(Domain.name == name_normalized).first()
    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{name_normalized}' not found",
        )

    job = (
        db.query(EnrichmentJob)
        .filter(EnrichmentJob.id == job_id, EnrichmentJob.domain_id == domain.id)
        .first()
    )
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found for domain '{name_normalized}'",
        )

    enrichment_types = (
        job.enrichment_types_csv.split(",") if job.enrichment_types_csv else []
    )

    return EnrichJobStatusOut(
        id=job.id,
        domain_id=job.domain_id,
        status=job.status.value,
        total_tasks=job.total_tasks,
        completed_tasks=job.completed_tasks,
        failed_tasks=job.failed_tasks,
        enrichment_types=enrichment_types,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
    )


# ----------------------------------------------------------------------------
# Source endpoints
# ----------------------------------------------------------------------------
@app.get(
    "/sources",
    response_model=list[SourceListOut],
    summary="List all ingested sources",
)
def list_sources(db: Session = Depends(get_db)):
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

@app.post(
    "/feeds/threatfox/refresh",
    response_model=IngestStatsOut,
    summary="Pull fresh domain IOCs from ThreatFox",
)
def refresh_threatfox(db: Session = Depends(get_db)):
    from ingesters.threatfox import ThreatFoxIngester
    ingester = ThreatFoxIngester()
    stats = ingester.ingest(db)
    return IngestStatsOut(
        feed="ThreatFox",
        fetched_bytes=stats.fetched,
        parsed=stats.parsed,
        inserted=stats.inserted,
        updated=stats.updated,
        skipped=stats.skipped,
        errors=stats.errors,
    )


@app.post(
    "/feeds/ransomware-live/refresh",
    response_model=IngestStatsOut,
    summary="Pull recent ransomware victims from ransomware.live",
)
def refresh_ransomware_live(db: Session = Depends(get_db)):
    from ingesters.ransomware_live import RansomwareLiveIngester
    ingester = RansomwareLiveIngester()
    stats = ingester.ingest(db)
    return IngestStatsOut(
        feed="Ransomware.live",
        fetched_bytes=stats.fetched,
        parsed=stats.parsed,
        inserted=stats.inserted,
        updated=stats.updated,
        skipped=stats.skipped,
        errors=stats.errors,
    )


@app.post(
    "/feeds/otx/refresh",
    response_model=IngestStatsOut,
    summary="Pull domain IOCs from AlienVault OTX pulse subscriptions",
)
def refresh_otx(db: Session = Depends(get_db)):
    from ingesters.otx import OtxIngester
    ingester = OtxIngester()
    stats = ingester.ingest(db)
    return IngestStatsOut(
        feed="OTX",
        fetched_bytes=stats.fetched,
        parsed=stats.parsed,
        inserted=stats.inserted,
        updated=stats.updated,
        skipped=stats.skipped,
        errors=stats.errors,
    )