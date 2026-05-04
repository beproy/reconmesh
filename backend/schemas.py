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
# Enrichment schemas (NEW in Session 6)
# ----------------------------------------------------------------------------
class EnrichmentOut(BaseModel):
    """A single enrichment result attached to a domain."""
    model_config = ConfigDict(from_attributes=True)

    enrichment_type: str
    status: str
    data: dict[str, Any] = {}
    error_message: Optional[str] = None
    fetched_at: datetime


class EnrichResponseOut(BaseModel):
    """Response from POST /domains/{name}/enrich — one row per enricher run."""
    domain: str
    results: list[EnrichmentOut]


# ----------------------------------------------------------------------------
# Domain schemas
# ----------------------------------------------------------------------------
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
