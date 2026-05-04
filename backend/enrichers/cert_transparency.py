"""
Certificate transparency enricher.

Queries crt.sh's public JSON API to find every TLS certificate ever issued
for a domain, then extracts the unique subdomains from those certs.

Honest about CT limitations:
  - CT logs are append-only — a name appearing here does NOT mean it
    currently exists or resolves. Many entries are years old.
  - A single certificate can list many names (SANs). One cert covering
    [example.com, www.example.com, mail.example.com] yields 3 entries.
  - We filter to names that are the queried domain or a subdomain of it.
    Otherwise crt.sh sometimes returns unrelated names from shared certs.
  - Wildcard names (e.g. *.example.com) are kept and surfaced honestly.

Operational notes:
  - crt.sh handles ~250k req/day comfortably (per their maintainer).
    We make exactly ONE request per enrich call. Polite citizen.
  - Output for popular domains can be thousands of rows. We cap at 200
    most-recent unique subdomains in storage; counters are surfaced so
    the UI can say "200 of 4,832 shown".
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from models import EnrichmentStatus, EnrichmentType
from .base import BaseEnricher, EnrichmentResult


CRTSH_URL = "https://crt.sh/"
HTTP_TIMEOUT_SECONDS = 30.0
MAX_STORED_SUBDOMAINS = 200


class CertTransparencyEnricher(BaseEnricher):
    enrichment_type = EnrichmentType.CT_LOGS
    timeout_seconds = HTTP_TIMEOUT_SECONDS + 5  # slight headroom over httpx's own timeout

    def enrich(self, domain_name: str) -> EnrichmentResult:
        # Single query to the API
        try:
            response = httpx.get(
                CRTSH_URL,
                params={"q": domain_name, "output": "json"},
                timeout=HTTP_TIMEOUT_SECONDS,
                follow_redirects=True,
            )
        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.TIMEOUT,
                error_message=f"crt.sh did not respond within {HTTP_TIMEOUT_SECONDS}s",
            )
        except httpx.HTTPError as e:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"HTTP error contacting crt.sh: {type(e).__name__}: {e}",
            )

        # crt.sh returns 200 + empty array for unknown domains.
        # Other status codes are treated as errors / rate limits.
        if response.status_code == 429:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.RATE_LIMITED,
                error_message="crt.sh returned HTTP 429 (rate limited)",
            )
        if response.status_code != 200:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"crt.sh returned HTTP {response.status_code}",
            )

        try:
            payload = response.json()
        except ValueError as e:
            # crt.sh occasionally returns malformed JSON when overloaded
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"crt.sh returned non-JSON response: {e}",
            )

        if not isinstance(payload, list):
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message="Unexpected response shape from crt.sh (not a list)",
            )

        # Extract subdomains
        return self._build_result(domain_name, payload)

    # ------------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------------
    def _build_result(self, domain_name: str, certs: list[dict[str, Any]]) -> EnrichmentResult:
        domain_lower = domain_name.lower().strip()
        total_certs = len(certs)

        # Map subdomain -> most recent not_before timestamp seen for it.
        # We keep the most recent so we can sort by recency.
        subdomain_recency: dict[str, str] = {}

        for cert in certs:
            name_value = cert.get("name_value")
            if not name_value:
                continue

            not_before = cert.get("not_before") or cert.get("min_entry_timestamp") or ""

            # name_value can contain multiple names separated by newlines
            for raw in str(name_value).splitlines():
                name = raw.strip().lower()
                if not name:
                    continue
                if not self._is_relevant(name, domain_lower):
                    continue

                # Keep the most recent not_before timestamp for this name
                existing = subdomain_recency.get(name)
                if existing is None or not_before > existing:
                    subdomain_recency[name] = not_before

        unique_count = len(subdomain_recency)

        # Sort by recency (most recent first), cap at MAX_STORED_SUBDOMAINS
        sorted_pairs = sorted(
            subdomain_recency.items(),
            key=lambda kv: kv[1],
            reverse=True,
        )
        kept = sorted_pairs[:MAX_STORED_SUBDOMAINS]

        subdomains: list[dict[str, str]] = [
            {"name": name, "most_recent_not_before": ts}
            for name, ts in kept
        ]

        if total_certs == 0:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.NOT_FOUND,
                error_message="No certificates found for this domain in CT logs",
                data={
                    "total_certs_found": 0,
                    "unique_subdomains_found": 0,
                    "subdomains_stored": 0,
                    "subdomains": [],
                },
            )

        return EnrichmentResult(
            enrichment_type=self.enrichment_type,
            status=EnrichmentStatus.OK,
            data={
                "total_certs_found": total_certs,
                "unique_subdomains_found": unique_count,
                "subdomains_stored": len(subdomains),
                "subdomains": subdomains,
            },
        )

    @staticmethod
    def _is_relevant(candidate: str, domain: str) -> bool:
        """
        Keep names that are the apex domain itself, a subdomain of it, or
        a wildcard for it. Filter out unrelated names that sometimes appear
        in shared / multi-domain certs.
        """
        if candidate == domain:
            return True
        if candidate == f"*.{domain}":
            return True
        if candidate.endswith(f".{domain}"):
            return True
        return False
