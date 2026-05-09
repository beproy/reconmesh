"""
Pydantic schemas — the shapes of API requests/responses.

Distinct from SQLAlchemy models (which are database tables).
These define what JSON comes in and goes out over HTTP.
"""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ----------------------------------------------------------------------------
# Source schemas
# ----------------------------------------------------------------------------
class SourceOut(BaseModel):
    """How a source looks when returned by the API."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    source_type: str
    url: Optional[str] = None
    description: Optional[str] = None


# ----------------------------------------------------------------------------
# Indicator schemas
# ----------------------------------------------------------------------------
class IndicatorOut(BaseModel):
    """How an indicator looks when returned by the API."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator_type: str
    value: str
    confidence: str
    tlp: str
    tags: list[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    ingested_at: datetime
    is_active: bool
    source: SourceOut


# ----------------------------------------------------------------------------
# Enrichment schemas
# ----------------------------------------------------------------------------
class EnrichmentOut(BaseModel):
    """A single enrichment result attached to a domain."""
    model_config = ConfigDict(from_attributes=True)

    enrichment_type: str
    status: str
    data: dict[str, Any] = {}
    error_message: Optional[str] = None
    fetched_at: datetime


# ----------------------------------------------------------------------------
# Enrichment job schemas (NEW in Session 8 — async)
# ----------------------------------------------------------------------------
class EnrichJobDispatchedOut(BaseModel):
    """Returned by POST /domains/{name}/enrich — async dispatch confirmation."""
    job_id: int
    domain: str
    enrichment_types: list[str]
    poll_url: str  # Frontend uses this directly so it doesn't construct URLs


class EnrichJobStatusOut(BaseModel):
    """
    Returned by GET /domains/{name}/enrich/{job_id} — current state of an
    async enrichment job. The frontend polls this until status becomes
    completed or failed.
    """
    id: int
    domain_id: int
    status: str
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    enrichment_types: list[str]  # Parsed from enrichment_types_csv
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ----------------------------------------------------------------------------
# Domain schemas
# ----------------------------------------------------------------------------
class DomainListItem(BaseModel):
    """Lightweight domain summary for the browse/list view."""
    id: int
    name: str
    tld: Optional[str] = None
    risk_score: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    indicator_count: int = 0
    enrichment_count: int = 0

class DomainListItem(BaseModel):
    """Lightweight domain summary for the browse/list view."""
    id: int
    name: str
    tld: Optional[str] = None
    risk_score: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    indicator_count: int = 0
    enrichment_count: int = 0

    
class DomainCreate(BaseModel):
    """What the client sends to create a new domain row."""
    name: str = Field(..., min_length=1, max_length=255, examples=["acmecorp.com"])
    tld: Optional[str] = Field(None, max_length=63)
    risk_score: Optional[int] = Field(None, ge=0, le=100)


class DomainOut(BaseModel):
    """How a domain looks when returned by the API (with related indicators and enrichments)."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    tld: Optional[str] = None
    registrar: Optional[str] = None
    registered_date: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    risk_score: Optional[int] = None
    indicators: list[IndicatorOut] = []
    enrichments: list[EnrichmentOut] = []


# ----------------------------------------------------------------------------
# Ingestion schemas
# ----------------------------------------------------------------------------
class IngestStatsOut(BaseModel):
    """Result of an ingestion run."""
    feed: str
    fetched_bytes: int
    parsed: int
    inserted: int
    updated: int
    skipped: int
    errors: int


class SourceListOut(BaseModel):
    """A source row in a list response."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    source_type: str
    url: Optional[str] = None
    description: Optional[str] = None
    indicator_count: int = 0
