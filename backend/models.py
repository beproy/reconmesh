"""
ReconMesh database models.

Four core tables:
  - sources:    where data came from (feeds, reports, manual entry)
  - domains:    the central pivot — the domains we know about
  - indicators: observables (IPs, URLs, hashes, etc.) tied to domains and sources
  - notes:      analyst-added context (attribution, victimology, hypotheses)
"""
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import relationship

from database import Base


# ----------------------------------------------------------------------------
# Enums — controlled vocabularies for type-safe categorization
# ----------------------------------------------------------------------------
class SourceType(str, PyEnum):
    FEED = "feed"
    REPORT = "report"
    MANUAL = "manual"
    MISP_EVENT = "misp_event"
    STIX_BUNDLE = "stix_bundle"


class IndicatorType(str, PyEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    ASN = "asn"
    BITCOIN_ADDRESS = "bitcoin_address"
    MUTEX = "mutex"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"


class Confidence(str, PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class TLP(str, PyEnum):
    """Traffic Light Protocol — standard CTI sharing classification."""
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"


class NoteType(str, PyEnum):
    ATTRIBUTION = "attribution"
    VICTIMOLOGY = "victimology"
    TTP = "ttp"
    HYPOTHESIS = "hypothesis"
    COMMENT = "comment"


# ----------------------------------------------------------------------------
# Helper: timezone-aware UTC default for timestamps
# ----------------------------------------------------------------------------
def utc_now():
    """Returns timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------------------
# Source — where any piece of intel came from
# ----------------------------------------------------------------------------
class Source(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    source_type = Column(
        Enum(SourceType, name="source_type_enum"),
        nullable=False,
        default=SourceType.FEED,
    )
    url = Column(String(2048), nullable=True)
    description = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    # Reverse relationships (optional — useful for "show me everything from this source")
    indicators = relationship("Indicator", back_populates="source")


# ----------------------------------------------------------------------------
# Domain — the pivot point
# ----------------------------------------------------------------------------
class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    tld = Column(String(63), nullable=True, index=True)
    registrar = Column(String(255), nullable=True)
    registered_date = Column(DateTime(timezone=True), nullable=True)

    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)

    risk_score = Column(Integer, nullable=True)  # 0-100, computed later

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    # Relationships
    indicators = relationship("Indicator", back_populates="domain")
    notes = relationship("Note", back_populates="domain", cascade="all, delete-orphan")
    enrichments = relationship("Enrichment", back_populates="domain", cascade="all, delete-orphan")


# ----------------------------------------------------------------------------
# Indicator — the workhorse: observables tied to a source and (optionally) a domain
# ----------------------------------------------------------------------------
class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)

    indicator_type = Column(
        Enum(IndicatorType, name="indicator_type_enum"),
        nullable=False,
        index=True,
    )
    value = Column(String(2048), nullable=False, index=True)

    # Foreign keys
    domain_id = Column(
        Integer,
        ForeignKey("domains.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_id = Column(
        Integer,
        ForeignKey("sources.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    confidence = Column(
        Enum(Confidence, name="confidence_enum"),
        nullable=False,
        default=Confidence.MEDIUM,
    )
    tlp = Column(
        Enum(TLP, name="tlp_enum"),
        nullable=False,
        default=TLP.AMBER,
    )

    tags = Column(ARRAY(String), nullable=False, default=list)

    # Source's reported observation window
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    # When ReconMesh ingested it
    ingested_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    is_active = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True)
    reference_urls = Column(ARRAY(String), nullable=False, default=list)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    # Relationships
    domain = relationship("Domain", back_populates="indicators")
    source = relationship("Source", back_populates="indicators")
    notes = relationship("Note", back_populates="indicator")


# ----------------------------------------------------------------------------
# Note — analyst-added context (attribution, victimology, hypotheses, etc.)
# ----------------------------------------------------------------------------
class Note(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)

    domain_id = Column(
        Integer,
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    indicator_id = Column(
        Integer,
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    note_type = Column(
        Enum(NoteType, name="note_type_enum"),
        nullable=False,
        default=NoteType.COMMENT,
    )
    title = Column(String(500), nullable=False)
    body = Column(Text, nullable=False)
    confidence = Column(
        Enum(Confidence, name="confidence_enum", create_type=False),
        nullable=False,
        default=Confidence.MEDIUM,
    )
    author = Column(String(255), nullable=False, default="analyst")
    reference_urls = Column(ARRAY(String), nullable=False, default=list)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    # Relationships
    domain = relationship("Domain", back_populates="notes")
    indicator = relationship("Indicator", back_populates="notes")


# ----------------------------------------------------------------------------
# Enrichment — flexible per-domain OSINT data
# ----------------------------------------------------------------------------
class EnrichmentType(str, PyEnum):
    DNS = "dns"
    EMAIL_SECURITY = "email_security"
    WHOIS = "whois"
    CT_LOGS = "ct_logs"           # reserved for Session 7
    TYPO_SQUAT = "typo_squat"     # reserved for Session 7


class EnrichmentStatus(str, PyEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"


class Enrichment(Base):
    """
    A single enrichment result for a domain.

    Each (domain_id, enrichment_type) pair is unique — re-running an enricher
    updates the existing row rather than creating a new one.

    The `data` column is JSONB for flexibility — each enrichment type stores
    its own shape (DNS records, parsed SPF, WHOIS fields, etc.).
    """
    __tablename__ = "enrichments"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(
        Integer,
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    enrichment_type = Column(
        Enum(EnrichmentType, name="enrichment_type_enum"),
        nullable=False,
        index=True,
    )
    status = Column(
        Enum(EnrichmentStatus, name="enrichment_status_enum"),
        nullable=False,
        default=EnrichmentStatus.OK,
    )
    data = Column(JSONB, nullable=False, default=dict)
    error_message = Column(Text, nullable=True)
    fetched_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    domain = relationship("Domain", back_populates="enrichments")

    __table_args__ = (
        UniqueConstraint("domain_id", "enrichment_type", name="uq_domain_enrichment_type"),
    )
