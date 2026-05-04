"""
Base class for domain enrichers.

Each enricher is a small module that performs one type of OSINT lookup
(DNS, email security, WHOIS, etc.) for a given domain and stores the
result as a row in the `enrichments` table.

Design principles:
  - Each enricher is independent: one failing does not block others.
  - Each enricher has its own timeout — slow upstream services don't
    hang the whole enrichment endpoint.
  - Results are upserted on (domain_id, enrichment_type), so re-running
    refreshes the data rather than creating duplicates.
  - Every enrichment stores a status (ok / error / timeout / etc.) so
    the API response is honest about what worked and what didn't.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from models import (
    Domain,
    Enrichment,
    EnrichmentStatus,
    EnrichmentType,
)


# ----------------------------------------------------------------------------
# What every enricher returns
# ----------------------------------------------------------------------------
@dataclass
class EnrichmentResult:
    """Outcome of a single enrichment run."""
    enrichment_type: EnrichmentType
    status: EnrichmentStatus
    data: dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


# ----------------------------------------------------------------------------
# Base enricher
# ----------------------------------------------------------------------------
class BaseEnricher(ABC):
    """
    Subclasses must:
      - set `enrichment_type` (one of the EnrichmentType enum values)
      - implement `enrich(domain_name)` which returns an EnrichmentResult

    Subclasses should NOT touch the database directly. The base class
    handles persistence so all enrichers behave consistently.
    """

    enrichment_type: EnrichmentType
    timeout_seconds: float = 10.0

    @abstractmethod
    def enrich(self, domain_name: str) -> EnrichmentResult:
        """
        Perform the enrichment lookup. Implementations should:
          - catch their own exceptions and convert to EnrichmentResult
            with the appropriate status (ERROR / TIMEOUT / etc.)
          - never raise — if something goes wrong, return a result with
            status != OK and an error_message
          - respect self.timeout_seconds for upstream calls
        """
        ...

    # ------------------------------------------------------------------------
    # Persistence — shared across all enrichers
    # ------------------------------------------------------------------------
    def run_and_save(self, db: Session, domain: Domain) -> EnrichmentResult:
        """
        Run the enricher and upsert the result into the enrichments table.
        Returns the EnrichmentResult so the caller can use it directly.
        """
        try:
            result = self.enrich(domain.name)
        except Exception as e:
            # Defensive — enrich() shouldn't raise, but if it does we still
            # produce a sensible row rather than crashing the whole endpoint.
            result = EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"{type(e).__name__}: {e}",
            )

        self._save(db, domain, result)
        return result

    def _save(self, db: Session, domain: Domain, result: EnrichmentResult) -> None:
        """Upsert by (domain_id, enrichment_type)."""
        now = datetime.now(timezone.utc)

        stmt = (
            pg_insert(Enrichment.__table__)
            .values(
                domain_id=domain.id,
                enrichment_type=result.enrichment_type,
                status=result.status,
                data=result.data,
                error_message=result.error_message,
                fetched_at=now,
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_update(
                constraint="uq_domain_enrichment_type",
                set_={
                    "status": result.status,
                    "data": result.data,
                    "error_message": result.error_message,
                    "fetched_at": now,
                    "updated_at": now,
                },
            )
        )
        db.execute(stmt)
        db.commit()
