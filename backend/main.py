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
from pydantic import BaseModel
from fastapi import Header

from database import SessionLocal, engine, get_db
from models import (
    ApiKey,
    AttackGroup,
    AttackMalware,
    AttackRelationship,
    AttackTechnique,
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
from tasks.mitre_tasks import refresh_mitre_attack
from celery.result import AsyncResult
from celery_app import app as celery_app
from auth import generate_api_key, hash_api_key, require_api_key


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
def enrich_domain(
    domain_name: str,
    db: Session = Depends(get_db),
    api_key: ApiKey = Depends(require_api_key),
):
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


# ----------------------------------------------------------------------------
# Admin: mint API keys (bootstrap-token protected)
# ----------------------------------------------------------------------------
# This is the ONLY way to create new API keys. It is protected by a single
# server-side secret (ADMIN_BOOTSTRAP_TOKEN) read from the environment, NOT
# by an API key itself — which would be a chicken-and-egg problem.
#
# The raw key is returned in the response body exactly once and is never
# stored anywhere; only its SHA-256 hash is persisted. If lost, mint a new
# one and revoke the old.

class MintKeyRequest(BaseModel):
    name: str


class MintKeyResponse(BaseModel):
    id: int
    name: str
    api_key: str  # raw key — shown ONCE, never recoverable
    created_at: datetime


def require_bootstrap_token(
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
) -> None:
    expected = os.getenv("ADMIN_BOOTSTRAP_TOKEN")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ADMIN_BOOTSTRAP_TOKEN not configured on server",
        )
    if not x_admin_token or x_admin_token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin token",
        )


@app.post(
    "/admin/keys",
    response_model=MintKeyResponse,
    dependencies=[Depends(require_bootstrap_token)],
    tags=["admin"],
)
def mint_api_key(req: MintKeyRequest, db: Session = Depends(get_db)):
    """Mint a new API key. Bootstrap-token protected."""
    raw_key = generate_api_key()
    key_row = ApiKey(name=req.name, key_hash=hash_api_key(raw_key))
    db.add(key_row)
    db.commit()
    db.refresh(key_row)

    return MintKeyResponse(
        id=key_row.id,
        name=key_row.name,
        api_key=raw_key,  # only time this is ever visible
        created_at=key_row.created_at,
    )

# ----------------------------------------------------------------------------
# MITRE ATT&CK ingestion (Session 19)
# ----------------------------------------------------------------------------
class MitreRefreshDispatchedOut(BaseModel):
    task_id: str
    status: str
    poll_url: str
 
 
@app.post(
    "/feeds/mitre/refresh",
    response_model=MitreRefreshDispatchedOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Dispatch async MITRE ATT&CK ingestion (Celery task)",
)
def refresh_mitre(
    api_key: ApiKey = Depends(require_api_key),
):
    """
    Fires the MITRE ingest as a Celery task. Returns immediately with a
    task_id the caller polls via GET /tasks/{task_id}.
 
    Bundle is ~35MB and ingest takes a few minutes — too long for a
    synchronous HTTP request. API-key protected.
    """
    async_result = refresh_mitre_attack.delay()
    return MitreRefreshDispatchedOut(
        task_id=async_result.id,
        status="pending",
        poll_url=f"/tasks/{async_result.id}",
    )
 
 
class TaskStatusOut(BaseModel):
    task_id: str
    state: str
    ready: bool
    successful: Optional[bool] = None
    result: Optional[dict] = None
 
 
@app.get(
    "/tasks/{task_id}",
    response_model=TaskStatusOut,
    summary="Poll any Celery task by ID (generic — used by MITRE and future ingesters)",
)
def get_task_status(task_id: str):
    """
    Generic Celery AsyncResult poller. Unprotected — task IDs are
    unguessable UUIDs and contain no sensitive data.
    """
    async_result = AsyncResult(task_id, app=celery_app)
    state = async_result.state
 
    result_data = None
    successful = None
    if async_result.ready():
        successful = async_result.successful()
        if successful:
            raw = async_result.result
            if isinstance(raw, dict):
                result_data = raw
 
    return TaskStatusOut(
        task_id=task_id,
        state=state,
        ready=async_result.ready(),
        successful=successful,
        result=result_data,
    )


# ----------------------------------------------------------------------------
# MITRE ATT&CK catalog endpoints (Session 20) — public, read-only
# ----------------------------------------------------------------------------
# These serve the ATT&CK data ingested in Session 19. No auth required —
# this is public reference data. Paginated list + detail-by-attack-id.
 
class AttackGroupListItem(BaseModel):
    attack_id: str
    stix_id: str
    name: str
    aliases: list[str]
 
 
class AttackGroupDetail(BaseModel):
    attack_id: str
    stix_id: str
    name: str
    description: Optional[str] = None
    aliases: list[str]
    external_references: list[dict]
    related_techniques: list[dict] = []
    related_malware: list[dict] = []
 
 
class AttackTechniqueListItem(BaseModel):
    attack_id: str
    stix_id: str
    name: str
    is_subtechnique: bool
    tactics: list[str]
 
 
class AttackTechniqueDetail(BaseModel):
    attack_id: str
    stix_id: str
    name: str
    description: Optional[str] = None
    is_subtechnique: bool
    tactics: list[str]
    platforms: list[str]
    data_sources: list[str]
    detection: Optional[str] = None
    external_references: list[dict]
    related_groups: list[dict] = []
 
 
def _tactics_from_phases(phases: list[dict] | None) -> list[str]:
    """Pull tactic phase names out of STIX kill_chain_phases."""
    if not phases:
        return []
    return [
        p.get("phase_name", "")
        for p in phases
        if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
    ]
 
 
@app.get(
    "/attack/groups",
    response_model=list[AttackGroupListItem],
    summary="List MITRE ATT&CK threat groups (paginated, searchable)",
)
def list_attack_groups(
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 25,
    db: Session = Depends(get_db),
):
    query = db.query(AttackGroup)
    if search:
        # ILIKE search across name + aliases. aliases is JSONB so we
        # cast to text for the LIKE — simple but works.
        from sqlalchemy import or_, cast, String
        like = f"%{search.strip().lower()}%"
        query = query.filter(
            or_(
                AttackGroup.name.ilike(like),
                AttackGroup.attack_id.ilike(like),
                cast(AttackGroup.aliases, String).ilike(like),
            )
        )
 
    offset = (max(page, 1) - 1) * page_size
    rows = (
        query.order_by(AttackGroup.attack_id)
        .offset(offset)
        .limit(page_size)
        .all()
    )
 
    return [
        AttackGroupListItem(
            attack_id=g.attack_id,
            stix_id=g.stix_id,
            name=g.name,
            aliases=g.aliases or [],
        )
        for g in rows
    ]
 
 
@app.get(
    "/attack/groups/{attack_id}",
    response_model=AttackGroupDetail,
    summary="Get a single ATT&CK group with related techniques and malware",
)
def get_attack_group(attack_id: str, db: Session = Depends(get_db)):
    group = (
        db.query(AttackGroup)
        .filter(AttackGroup.attack_id == attack_id.upper())
        .first()
    )
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group '{attack_id}' not found",
        )
 
    # Find all "uses" relationships from this group
    rels = (
        db.query(AttackRelationship)
        .filter(
            AttackRelationship.source_ref == group.stix_id,
            AttackRelationship.relationship_type == "uses",
        )
        .all()
    )
 
    # Bucket targets by STIX type prefix
    technique_refs = [r.target_ref for r in rels if r.target_ref.startswith("attack-pattern--")]
    malware_refs = [r.target_ref for r in rels if r.target_ref.startswith("malware--")]
 
    # Fetch the related objects in one go each
    related_techniques = []
    if technique_refs:
        techniques = (
            db.query(AttackTechnique)
            .filter(AttackTechnique.stix_id.in_(technique_refs))
            .order_by(AttackTechnique.attack_id)
            .all()
        )
        related_techniques = [
            {"attack_id": t.attack_id, "name": t.name, "is_subtechnique": t.is_subtechnique}
            for t in techniques
        ]
 
    related_malware = []
    if malware_refs:
        malware = (
            db.query(AttackMalware)
            .filter(AttackMalware.stix_id.in_(malware_refs))
            .order_by(AttackMalware.attack_id)
            .all()
        )
        related_malware = [
            {"attack_id": m.attack_id, "name": m.name}
            for m in malware
        ]
 
    return AttackGroupDetail(
        attack_id=group.attack_id,
        stix_id=group.stix_id,
        name=group.name,
        description=group.description,
        aliases=group.aliases or [],
        external_references=group.external_references or [],
        related_techniques=related_techniques,
        related_malware=related_malware,
    )
 
 
@app.get(
    "/attack/techniques",
    response_model=list[AttackTechniqueListItem],
    summary="List MITRE ATT&CK techniques (paginated, searchable)",
)
def list_attack_techniques(
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 25,
    db: Session = Depends(get_db),
):
    query = db.query(AttackTechnique)
    if search:
        from sqlalchemy import or_
        like = f"%{search.strip().lower()}%"
        query = query.filter(
            or_(
                AttackTechnique.name.ilike(like),
                AttackTechnique.attack_id.ilike(like),
            )
        )
 
    offset = (max(page, 1) - 1) * page_size
    rows = (
        query.order_by(AttackTechnique.attack_id)
        .offset(offset)
        .limit(page_size)
        .all()
    )
 
    return [
        AttackTechniqueListItem(
            attack_id=t.attack_id,
            stix_id=t.stix_id,
            name=t.name,
            is_subtechnique=t.is_subtechnique,
            tactics=_tactics_from_phases(t.kill_chain_phases),
        )
        for t in rows
    ]
 
 
@app.get(
    "/attack/techniques/{attack_id}",
    response_model=AttackTechniqueDetail,
    summary="Get a single ATT&CK technique with related groups",
)
def get_attack_technique(attack_id: str, db: Session = Depends(get_db)):
    technique = (
        db.query(AttackTechnique)
        .filter(AttackTechnique.attack_id == attack_id.upper())
        .first()
    )
    if technique is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique '{attack_id}' not found",
        )
 
    # Find all "uses" relationships pointing AT this technique
    rels = (
        db.query(AttackRelationship)
        .filter(
            AttackRelationship.target_ref == technique.stix_id,
            AttackRelationship.relationship_type == "uses",
        )
        .all()
    )
 
    group_refs = [r.source_ref for r in rels if r.source_ref.startswith("intrusion-set--")]
    related_groups = []
    if group_refs:
        groups = (
            db.query(AttackGroup)
            .filter(AttackGroup.stix_id.in_(group_refs))
            .order_by(AttackGroup.attack_id)
            .all()
        )
        related_groups = [
            {"attack_id": g.attack_id, "name": g.name}
            for g in groups
        ]
 
    return AttackTechniqueDetail(
        attack_id=technique.attack_id,
        stix_id=technique.stix_id,
        name=technique.name,
        description=technique.description,
        is_subtechnique=technique.is_subtechnique,
        tactics=_tactics_from_phases(technique.kill_chain_phases),
        platforms=technique.platforms or [],
        data_sources=technique.data_sources or [],
        detection=technique.detection,
        external_references=technique.external_references or [],
        related_groups=related_groups,
    )

# ----------------------------------------------------------------------------
# Global stats — used by the home page banner (Session 20 polish)
# ----------------------------------------------------------------------------
class StatsOut(BaseModel):
    domains: int
    indicators: int
    enrichments: int
    sources: int
    attack_groups: int
    attack_techniques: int
 
 
@app.get(
    "/stats",
    response_model=StatsOut,
    summary="Global row counts for the home page banner",
)
def get_stats(db: Session = Depends(get_db)):
    """
    Returns counts across the core tables. Used by the home page to show
    a quick "what's in here" banner. Cheap COUNT(*) queries — fine for
    the size of data we're handling.
    """
    return StatsOut(
        domains=db.query(Domain).count(),
        indicators=db.query(Indicator).count(),
        enrichments=db.query(Enrichment).count(),
        sources=db.query(Source).count(),
        attack_groups=db.query(AttackGroup).count(),
        attack_techniques=db.query(AttackTechnique).count(),
    )