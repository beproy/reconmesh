"""
Mnemonic Passive DNS enricher.

Queries mnemonic's public Passive DNS API for historical DNS resolution
data about a domain. Passive DNS tells you what IP addresses a domain
has resolved to over time — useful for spotting infrastructure changes,
fast-flux behaviour, and shared hosting.

API: GET https://api.mnemonic.no/pdns/v3/{query}
Auth: none required for public (TLP:WHITE) data
Limits: 10 requests/minute, 1000/day for unauthenticated users
Docs: https://docs.mnemonic.no/api/services/pdns/01-public_api.html

Response shape (per record):
  {
    "rrtype": "a",
    "query": "example.com.",
    "answer": "93.184.216.34",
    "firstSeenTimestamp": 1340308340000,   # epoch millis
    "lastSeenTimestamp": 1377520248000,
    "times": 675,                          # observation count
    "tlp": "white"
  }

We summarise: total record count, unique answers, the rrtypes seen, and
a capped list of the most-observed records.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


MNEMONIC_API_BASE = "https://api.mnemonic.no/pdns/v3"
HTTP_TIMEOUT_SECONDS = 20

# Mnemonic can return thousands of records for a busy domain. Cap what we
# store so the JSONB column and the UI stay manageable. We keep the records
# with the highest observation count ("times").
RECORD_CAP = 100

USER_AGENT = "ReconMesh/0.2 (CTI aggregator)"


class MnemonicPdnsEnricher(BaseEnricher):
    """Enricher that queries mnemonic's public Passive DNS API."""

    enrichment_type = EnrichmentType.MNEMONIC_PDNS
    timeout_seconds = 30.0

    def enrich(self, domain_name: str) -> EnrichmentResult:
        url = f"{MNEMONIC_API_BASE}/{domain_name}"

        try:
            with httpx.Client(
                timeout=HTTP_TIMEOUT_SECONDS,
                follow_redirects=True,
            ) as client:
                response = client.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                )
        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.TIMEOUT,
                error_message=f"mnemonic PDNS did not respond within {HTTP_TIMEOUT_SECONDS}s",
            )
        except httpx.HTTPError as exc:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"HTTP error: {exc}",
            )

        # mnemonic returns 402 when the rate limit is hit
        if response.status_code == 402:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.RATE_LIMITED,
                error_message="mnemonic PDNS rate limit exceeded (10/min, 1000/day unauthenticated)",
            )

        if response.status_code == 404:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.NOT_FOUND,
                error_message="No passive DNS records found for this domain",
            )

        if response.status_code != 200:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"mnemonic PDNS returned HTTP {response.status_code}",
            )

        # Parse the JSON envelope
        try:
            body = response.json()
        except Exception as exc:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"Failed to parse mnemonic response: {exc}",
            )

        # The v3 API wraps results in a container: {responseCode, data: [...], ...}
        records = body.get("data", [])
        if not isinstance(records, list):
            records = []

        if not records:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.NOT_FOUND,
                error_message="No passive DNS records found for this domain",
                data={
                    "query": domain_name,
                    "total_records": 0,
                    "unique_answers": 0,
                    "rrtypes": [],
                    "records": [],
                    "cap_applied": RECORD_CAP,
                },
            )

        # Normalise each record into a clean shape
        normalised: list[dict[str, Any]] = []
        for rec in records:
            normalised.append({
                "rrtype": (rec.get("rrtype") or "").lower(),
                "query": (rec.get("query") or "").rstrip("."),
                "answer": (rec.get("answer") or "").rstrip("."),
                "first_seen": _epoch_ms_to_iso(rec.get("firstSeenTimestamp")),
                "last_seen": _epoch_ms_to_iso(rec.get("lastSeenTimestamp")),
                "times": rec.get("times", 0),
            })

        # Sort by observation count (most-seen first), then cap
        normalised.sort(key=lambda r: r.get("times", 0), reverse=True)
        capped = normalised[:RECORD_CAP]

        # Summary stats computed over ALL records, not just the capped slice
        unique_answers = len({r["answer"] for r in normalised if r["answer"]})
        rrtypes = sorted({r["rrtype"] for r in normalised if r["rrtype"]})

        data = {
            "query": domain_name,
            "total_records": len(normalised),
            "unique_answers": unique_answers,
            "rrtypes": rrtypes,
            "records": capped,
            "cap_applied": RECORD_CAP,
        }

        return EnrichmentResult(
            enrichment_type=self.enrichment_type,
            status=EnrichmentStatus.OK,
            data=data,
        )


def _epoch_ms_to_iso(value: Any) -> str | None:
    """Convert mnemonic's epoch-millisecond timestamps to ISO 8601 strings."""
    if not value:
        return None
    try:
        # mnemonic timestamps are milliseconds since epoch
        dt = datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None
