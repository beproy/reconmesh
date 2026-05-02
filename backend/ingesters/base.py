"""
Base class for feed ingesters.

One transaction per record. Each record's database work is its own
atomic unit, so an error on record N never rolls back records 0 to N-1.
This is slower than batching but vastly more robust against the kind of
SQLAlchemy session-state issues that plague bulk ingestion.

Each ingester defines:
  - A name and source_type (used to find/create the matching Source row)
  - A fetch() method that returns raw bytes/text from the upstream feed
  - A parse() method that yields normalized records

The shared base handles all the database logic.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import (
    Confidence,
    Domain,
    Indicator,
    IndicatorType,
    Source,
    SourceType,
    TLP,
)


# ----------------------------------------------------------------------------
# A normalized record — what each ingester produces, regardless of feed format
# ----------------------------------------------------------------------------
@dataclass
class IngestedRecord:
    """A single piece of intel, normalized to ReconMesh's shape."""
    indicator_type: IndicatorType
    value: str
    confidence: Confidence = Confidence.MEDIUM
    tlp: TLP = TLP.CLEAR
    tags: list[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_active: bool = True
    reference_urls: list[str] = field(default_factory=list)
    related_domain: Optional[str] = None


# ----------------------------------------------------------------------------
# Stats returned from each ingest run
# ----------------------------------------------------------------------------
@dataclass
class IngestStats:
    fetched: int = 0
    parsed: int = 0
    inserted: int = 0
    updated: int = 0
    skipped: int = 0
    errors: int = 0


# ----------------------------------------------------------------------------
# Base ingester
# ----------------------------------------------------------------------------
class BaseIngester(ABC):
    name: str = ""
    source_url: str = ""
    source_type: SourceType = SourceType.FEED
    description: str = ""

    @abstractmethod
    def fetch(self) -> bytes:
        """Return raw bytes from the upstream feed."""
        ...

    @abstractmethod
    def parse(self, raw: bytes) -> Iterable[IngestedRecord]:
        """Convert raw feed bytes into normalized records."""
        ...

    # ------------------------------------------------------------------------
    # Shared ingestion entrypoint
    # ------------------------------------------------------------------------
    def ingest(self, db: Session) -> IngestStats:
        stats = IngestStats()

        # 1. Find or create the Source. This is its own transaction.
        source_id = self._upsert_source(db)

        # 2. Fetch
        try:
            raw = self.fetch()
            stats.fetched = len(raw)
        except Exception as e:
            print(f"[{self.name}] fetch failed: {type(e).__name__}: {e}")
            stats.errors += 1
            return stats

        # 3. Parse
        try:
            records = list(self.parse(raw))
            stats.parsed = len(records)
        except Exception as e:
            print(f"[{self.name}] parse failed: {type(e).__name__}: {e}")
            stats.errors += 1
            return stats

        # 4. Per-record write — each in its own transaction
        for record in records:
            try:
                action = self._write_record(db, source_id, record)
                if action == "inserted":
                    stats.inserted += 1
                elif action == "updated":
                    stats.updated += 1
                else:
                    stats.skipped += 1
            except Exception as e:
                # Roll back this record's failed transaction; previous
                # records are unaffected because they each committed.
                db.rollback()
                stats.errors += 1
                # Print only the first few so logs aren't flooded
                if stats.errors <= 5:
                    print(
                        f"[{self.name}] record write failed: "
                        f"{type(e).__name__}: {e}"
                    )

        return stats

    # ------------------------------------------------------------------------
    # Per-record DB work — each method does its own commit
    # ------------------------------------------------------------------------
    def _upsert_source(self, db: Session) -> int:
        """Find or create the Source for this ingester. Returns its id."""
        existing = db.query(Source).filter(Source.name == self.name).first()
        if existing:
            return existing.id

        source = Source(
            name=self.name,
            source_type=self.source_type,
            url=self.source_url,
            description=self.description,
        )
        db.add(source)
        db.commit()
        db.refresh(source)
        return source.id

    def _upsert_domain(self, db: Session, name: str) -> int:
        """
        Postgres-native upsert of a Domain row. Returns the row's id.
        Idempotent: if the domain already exists, no-ops and returns existing id.
        """
        name = name.lower().strip()
        tld = name.rsplit(".", 1)[-1] if "." in name else None
        now = datetime.now(timezone.utc)

        stmt = (
            pg_insert(Domain.__table__)
            .values(name=name, tld=tld, created_at=now, updated_at=now)
            .on_conflict_do_nothing(index_elements=["name"])
        )
        db.execute(stmt)
        db.commit()

        row = db.query(Domain.id).filter(Domain.name == name).first()
        return row[0] if row else None

    def _write_record(
        self,
        db: Session,
        source_id: int,
        record: IngestedRecord,
    ) -> str:
        """
        Write one indicator. Insert if new, update last_seen/tags/etc if existing.
        Returns: "inserted" | "updated"
        Each call is its own transaction.
        """
        # Resolve domain link, if any
        domain_id = None
        if record.related_domain:
            domain_id = self._upsert_domain(db, record.related_domain)

        # Look for an existing indicator: same value + same source.
        # Use limit(1) defensively — if duplicates somehow exist we just
        # update the first.
        existing = (
            db.query(Indicator)
            .filter(
                Indicator.value == record.value,
                Indicator.source_id == source_id,
            )
            .limit(1)
            .first()
        )

        now = datetime.now(timezone.utc)

        if existing is not None:
            existing.last_seen = record.last_seen or existing.last_seen
            existing.tags = record.tags or existing.tags
            existing.is_active = record.is_active
            existing.reference_urls = record.reference_urls or existing.reference_urls
            existing.ingested_at = now
            if domain_id and existing.domain_id is None:
                existing.domain_id = domain_id
            db.commit()
            self._bump_domain_seen(db, domain_id, record)
            return "updated"

        new_ind = Indicator(
            indicator_type=record.indicator_type,
            value=record.value,
            domain_id=domain_id,
            source_id=source_id,
            confidence=record.confidence,
            tlp=record.tlp,
            tags=record.tags,
            first_seen=record.first_seen,
            last_seen=record.last_seen,
            ingested_at=now,
            is_active=record.is_active,
            reference_urls=record.reference_urls,
        )
        db.add(new_ind)
        try:
            db.commit()
        except IntegrityError:
            # Race: another concurrent insert won. Fetch and update instead.
            db.rollback()
            return self._update_existing_after_race(
                db, source_id, record, domain_id, now
            )

        self._bump_domain_seen(db, domain_id, record)
        return "inserted"

    def _update_existing_after_race(
        self,
        db: Session,
        source_id: int,
        record: IngestedRecord,
        domain_id: Optional[int],
        now: datetime,
    ) -> str:
        """If insertion lost a race to a concurrent writer, update instead."""
        existing = (
            db.query(Indicator)
            .filter(
                Indicator.value == record.value,
                Indicator.source_id == source_id,
            )
            .limit(1)
            .first()
        )
        if existing is None:
            return "skipped"  # weird, give up gracefully
        existing.last_seen = record.last_seen or existing.last_seen
        existing.tags = record.tags or existing.tags
        existing.is_active = record.is_active
        existing.reference_urls = record.reference_urls or existing.reference_urls
        existing.ingested_at = now
        if domain_id and existing.domain_id is None:
            existing.domain_id = domain_id
        db.commit()
        return "updated"

    def _bump_domain_seen(
        self,
        db: Session,
        domain_id: Optional[int],
        record: IngestedRecord,
    ) -> None:
        """Update the related Domain's first_seen/last_seen if needed."""
        if not domain_id:
            return
        domain = db.get(Domain, domain_id)
        if not domain:
            return
        changed = False
        if record.first_seen and (
            domain.first_seen is None or record.first_seen < domain.first_seen
        ):
            domain.first_seen = record.first_seen
            changed = True
        if record.last_seen and (
            domain.last_seen is None or record.last_seen > domain.last_seen
        ):
            domain.last_seen = record.last_seen
            changed = True
        if changed:
            db.commit()