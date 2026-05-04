"""
WHOIS enricher.

Uses python-whois to look up WHOIS data for a domain. Honest expectations:
  - Many TLDs return GDPR-scrubbed records (no registrant details).
  - The library's field shapes vary: some fields are strings, some are
    lists, some are datetime objects, some are missing. We normalize.
  - Some TLDs aren't supported and raise on lookup.
  - WHOIS servers rate-limit aggressively. Repeat calls quickly may fail.

We extract the most reliably-available fields (registrar, registration
date, expiry, nameservers) and let the rest go.
"""
from datetime import datetime
from typing import Any, Optional

import whois

from models import EnrichmentStatus, EnrichmentType
from .base import BaseEnricher, EnrichmentResult


class WhoisEnricher(BaseEnricher):
    enrichment_type = EnrichmentType.WHOIS
    timeout_seconds = 15.0

    def enrich(self, domain_name: str) -> EnrichmentResult:
        try:
            record = whois.whois(domain_name)
        except whois.parser.PywhoisError as e:
            # Domain not found, or unsupported TLD
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.NOT_FOUND,
                error_message=f"WHOIS not available: {e}",
            )
        except Exception as e:
            # Network errors, parse errors, rate-limits
            msg = str(e).lower()
            if "rate" in msg or "limit" in msg or "throttle" in msg:
                status = EnrichmentStatus.RATE_LIMITED
            elif "timeout" in msg or "timed out" in msg:
                status = EnrichmentStatus.TIMEOUT
            else:
                status = EnrichmentStatus.ERROR
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=status,
                error_message=f"{type(e).__name__}: {e}",
            )

        # python-whois sometimes returns a record with all-None fields when
        # the underlying server gave nothing useful. Treat that as not_found.
        if not record or all(record.get(k) is None for k in ("registrar", "creation_date", "expiration_date")):
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.NOT_FOUND,
                error_message="WHOIS returned an empty record",
                data={"raw_keys": list(record.keys()) if record else []},
            )

        normalized = self._normalize(record)

        return EnrichmentResult(
            enrichment_type=self.enrichment_type,
            status=EnrichmentStatus.OK,
            data=normalized,
        )

    # ------------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------------
    def _normalize(self, record: Any) -> dict[str, Any]:
        """
        python-whois fields can be:
          - a single string
          - a list of strings (e.g. multiple nameservers)
          - a datetime
          - a list of datetimes (rare, but happens)
          - None / missing
        We pick the best representation and serialize to JSON-safe types.
        """
        return {
            "registrar": self._first_str(record.get("registrar")),
            "registrant_org": self._first_str(record.get("org")),
            "registrant_country": self._first_str(record.get("country")),
            "creation_date": self._first_date(record.get("creation_date")),
            "expiration_date": self._first_date(record.get("expiration_date")),
            "updated_date": self._first_date(record.get("updated_date")),
            "name_servers": self._normalize_list(record.get("name_servers")),
            "status": self._normalize_list(record.get("status")),
            "emails": self._normalize_list(record.get("emails")),
            "dnssec": self._first_str(record.get("dnssec")),
        }

    @staticmethod
    def _first_str(value: Any) -> Optional[str]:
        """Coerce single-or-list-of-strings down to one string (or None)."""
        if value is None:
            return None
        if isinstance(value, list):
            for item in value:
                if item:
                    return str(item)
            return None
        return str(value)

    @staticmethod
    def _first_date(value: Any) -> Optional[str]:
        """Coerce single-or-list-of-datetimes to one ISO string (or None)."""
        if value is None:
            return None
        if isinstance(value, list):
            for item in value:
                if isinstance(item, datetime):
                    return item.isoformat()
                if item:
                    return str(item)
            return None
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    @staticmethod
    def _normalize_list(value: Any) -> list[str]:
        """Always return a list of unique non-empty strings, lowercased and stripped."""
        if value is None:
            return []
        if not isinstance(value, list):
            value = [value]
        seen: set[str] = set()
        out: list[str] = []
        for item in value:
            if item is None:
                continue
            s = str(item).strip().lower()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out
