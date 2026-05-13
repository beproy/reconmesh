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
    enrichment_jobs = relationship("EnrichmentJob", back_populates="domain", cascade="all, delete-orphan")


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
    VIRUSTOTAL = "virustotal"
    SHODAN = "shodan"
    ABUSEIPDB = "abuseipdb"
    AHMIA = "ahmia"


class EnrichmentStatus(str, PyEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"

class EnrichmentJobStatus(str, PyEnum):
    """Lifecycle of an async enrich-domain request."""
    PENDING = "pending"      # Tasks dispatched, none completed yet
    RUNNING = "running"      # At least one task in progress
    COMPLETED = "completed"  # All tasks finished (some may have failed)
    FAILED = "failed"        # All tasks failed catastrophically (rare)    


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

class EnrichmentJob(Base):
    """
    Tracks one logical "enrich this domain" request that fans out to
    multiple Celery tasks.

    A user clicks Enrich → backend creates one EnrichmentJob row +
    dispatches N tasks (one per enricher). Each task writes its result
    to the `enrichments` table as before, then increments this job's
    `completed_count`. Frontend polls this row to show progress.
    """
    __tablename__ = "enrichment_jobs"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(
        Integer,
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status = Column(
        Enum(EnrichmentJobStatus, name="enrichment_job_status_enum"),
        nullable=False,
        default=EnrichmentJobStatus.PENDING,
    )
    total_tasks = Column(Integer, nullable=False, default=0)
    completed_tasks = Column(Integer, nullable=False, default=0)
    failed_tasks = Column(Integer, nullable=False, default=0)
    # Comma-separated list of enrichment_type values dispatched. Used by the
    # API to tell the frontend which enrichers were even asked to run.
    enrichment_types_csv = Column(Text, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    domain = relationship("Domain", back_populates="enrichment_jobs")


# ----------------------------------------------------------------------------
# ApiKey — header-based auth keys for protected endpoints (Session 18)
# ----------------------------------------------------------------------------
class ApiKey(Base):
    """
    An API key issued for accessing protected endpoints (currently /enrich).

    We store only the SHA-256 hash of the key — the raw key is shown to the
    user exactly once at mint time and is never recoverable after that.

    Revocation is soft: setting `revoked_at` invalidates the key but keeps
    the row for audit history. The key is active when `revoked_at IS NULL`.
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)

    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


# ----------------------------------------------------------------------------
# MITRE ATT&CK — Enterprise taxonomy (Session 19)
#
# Four tables mirroring the STIX 2.1 object types we care about:
#   - attack_groups        (intrusion-set)
#   - attack_techniques    (attack-pattern)
#   - attack_malware       (malware)
#   - attack_relationships (relationship)
#
# Design notes:
#   * STIX ID (e.g. "intrusion-set--c416b28c-...") is the natural PK.
#     It's stable across upstream edits, globally unique, and matches the
#     references used in relationship objects.
#   * `attack_id` (G0016, T1566.001, S0154) is the human-readable ID we'll
#     show in the UI — pulled out of the `external_references` array where
#     source_name == "mitre-attack". Unique-indexed for fast lookup.
#   * Relationships use loose refs to source_ref/target_ref (no FK).
#     STIX relationships can point at object types we don't import
#     (tools, mitigations, campaigns). Loose refs + indexes is the
#     industry-standard approach.
#   * `revoked` and `deprecated` columns are present even though we skip
#     such objects on ingest — gives us an escape hatch later (e.g.
#     "show me deprecated techniques") without another migration.
#   * `kill_chain_phases`, `aliases`, etc. are JSONB — matches the
#     existing Enrichment.data pattern in this file.
# ----------------------------------------------------------------------------

class AttackGroup(Base):
    """A threat actor / intrusion-set from MITRE ATT&CK (e.g. APT29, FIN7)."""
    __tablename__ = "attack_groups"

    stix_id = Column(Text, primary_key=True)
    attack_id = Column(Text, nullable=False, unique=True, index=True)  # G0016
    name = Column(Text, nullable=False, index=True)
    description = Column(Text, nullable=True)
    aliases = Column(JSONB, nullable=False, default=list)
    external_references = Column(JSONB, nullable=False, default=list)

    created = Column(DateTime(timezone=True), nullable=True)
    modified = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)
    deprecated = Column(Boolean, nullable=False, default=False)

    ingested_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class AttackTechnique(Base):
    """A technique or sub-technique from ATT&CK Enterprise (e.g. T1566.001)."""
    __tablename__ = "attack_techniques"

    stix_id = Column(Text, primary_key=True)
    attack_id = Column(Text, nullable=False, unique=True, index=True)  # T1566 or T1566.001
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    is_subtechnique = Column(Boolean, nullable=False, default=False)
    kill_chain_phases = Column(JSONB, nullable=False, default=list)
    platforms = Column(JSONB, nullable=False, default=list)
    data_sources = Column(JSONB, nullable=False, default=list)
    detection = Column(Text, nullable=True)
    external_references = Column(JSONB, nullable=False, default=list)

    created = Column(DateTime(timezone=True), nullable=True)
    modified = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)
    deprecated = Column(Boolean, nullable=False, default=False)

    ingested_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class AttackMalware(Base):
    """A malware family from ATT&CK (e.g. Emotet — S0367)."""
    __tablename__ = "attack_malware"

    stix_id = Column(Text, primary_key=True)
    attack_id = Column(Text, nullable=False, unique=True, index=True)  # S0367
    name = Column(Text, nullable=False, index=True)
    description = Column(Text, nullable=True)
    aliases = Column(JSONB, nullable=False, default=list)
    malware_types = Column(JSONB, nullable=False, default=list)
    platforms = Column(JSONB, nullable=False, default=list)
    is_family = Column(Boolean, nullable=False, default=True)
    external_references = Column(JSONB, nullable=False, default=list)

    created = Column(DateTime(timezone=True), nullable=True)
    modified = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)
    deprecated = Column(Boolean, nullable=False, default=False)

    ingested_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class AttackRelationship(Base):
    """
    A STIX relationship object linking two ATT&CK entities.

    Common relationship_types we care about:
      - "uses"            (intrusion-set --uses--> malware/technique)
      - "attributed-to"   (intrusion-set --attributed-to--> intrusion-set)
      - "subtechnique-of" (attack-pattern --subtechnique-of--> attack-pattern)
      - "mitigates"       (course-of-action --mitigates--> attack-pattern)
      - "detects"         (x-mitre-data-component --detects--> attack-pattern)

    source_ref and target_ref are STIX IDs and are NOT FK-enforced — they
    can reference STIX types we don't import (tools, mitigations,
    campaigns, data components). Indexed for fast pivot queries.
    """
    __tablename__ = "attack_relationships"

    stix_id = Column(Text, primary_key=True)
    relationship_type = Column(Text, nullable=False, index=True)
    source_ref = Column(Text, nullable=False, index=True)
    target_ref = Column(Text, nullable=False, index=True)
    description = Column(Text, nullable=True)

    created = Column(DateTime(timezone=True), nullable=True)
    modified = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)
    deprecated = Column(Boolean, nullable=False, default=False)

    ingested_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )