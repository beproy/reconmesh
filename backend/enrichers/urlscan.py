"""
URLScan.io enricher (BYOK).

Queries the URLScan.io Search API for historical scans of a domain.
URLScan browses submitted URLs like a real user and records the
infrastructure they touch — domains contacted, IPs, page metadata,
screenshots. The Search API lets us pull every historical scan for a
given domain.

This is an infrastructure-pivot enricher: it tells you when a domain
was scanned, what other domains/IPs those scans involved, and what the
pages looked like. Complements VirusTotal/AbuseIPDB (which answer "is it
malicious") with "what does its history look like".

API: GET https://urlscan.io/api/v1/search/?q=domain:{domain}
Auth: API-Key header. Unauthenticated users get minor quotas; a key is
      strongly recommended. Set URLSCAN_API_KEY in .env.
Docs: https://urlscan.io/docs/search/

Response shape (per result):
  {
    "task": {"time": "...", "url": "...", "domain": "..."},
    "page": {"domain": "...", "ip": "...", "country": "...", "server": "..."},
    "stats": {"uniqIPs": N, "uniqCountries": N, ...},
    "_id": "...",
    "result": "https://urlscan.io/api/v1/result/{uuid}/"
  }
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
HTTP_TIMEOUT_SECONDS = 20

# URLScan can have thousands of scans for a busy domain. We ask for a
# bounded page and store a capped slice. Summary counts are computed over
# whatever the API returned in that page.
SEARCH_SIZE = 100      # how many results to request from the API
RESULT_CAP = 25        # how many individual scans we store/show

USER_AGENT = "ReconMesh/0.2 (CTI aggregator)"


class UrlscanEnricher(BaseEnricher):
    """Enricher that queries URLScan.io's Search API for a domain's scan history."""

    enrichment_type = EnrichmentType.URLSCAN
    timeout_seconds = 30.0

    def __init__(self) -> None:
        self._api_key = os.environ.get("URLSCAN_API_KEY", "")

    def enrich(self, domain_name: str) -> EnrichmentResult:
        if not self._api_key:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=(
                    "URLSCAN_API_KEY not set. Add it to .env and restart. "
                    "Get a free key at urlscan.io."
                ),
            )

        headers = {
            "API-Key": self._api_key,
            "User-Agent": USER_AGENT,
        }
        params = {
            "q": f"domain:{domain_name}",
            "size": str(SEARCH_SIZE),
        }

        try:
            with httpx.Client(
                timeout=HTTP_TIMEOUT_SECONDS,
                follow_redirects=True,
            ) as client:
                response = client.get(
                    URLSCAN_SEARCH_URL,
                    headers=headers,
                    params=params,
                )
        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.TIMEOUT,
                error_message=f"URLScan did not respond within {HTTP_TIMEOUT_SECONDS}s",
            )
        except httpx.HTTPError as exc:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"HTTP error: {exc}",
            )

        if response.status_code == 401:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message="URLScan rejected the API key (HTTP 401). Check URLSCAN_API_KEY.",
            )

        if response.status_code == 429:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.RATE_LIMITED,
                error_message="URLScan rate limit exceeded (HTTP 429). Try again later.",
            )

        if response.status_code != 200:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"URLScan returned HTTP {response.status_code}",
            )

        try:
            body = response.json()
        except Exception as exc:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"Failed to parse URLScan response: {exc}",
            )

        results = body.get("results", [])
        total = body.get("total", 0)
        has_more = body.get("has_more", False)

        if not results:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.NOT_FOUND,
                error_message="No URLScan scans found for this domain",
                data={
                    "query": domain_name,
                    "total_scans": 0,
                    "has_more": False,
                    "unique_ips": 0,
                    "unique_countries": 0,
                    "scans": [],
                    "cap_applied": RESULT_CAP,
                },
            )

        # Normalise each scan result into a clean shape
        normalised: list[dict[str, Any]] = []
        all_ips: set[str] = set()
        all_countries: set[str] = set()

        for r in results:
            task = r.get("task", {}) or {}
            page = r.get("page", {}) or {}

            ip = page.get("ip") or ""
            country = page.get("country") or ""
            if ip:
                all_ips.add(ip)
            if country:
                all_countries.add(country)

            normalised.append({
                "scanned_at": task.get("time"),
                "url": task.get("url") or "",
                "page_domain": page.get("domain") or "",
                "ip": ip,
                "country": country,
                "server": page.get("server") or "",
                "result_url": r.get("result") or "",
            })

        # Most recent first — URLScan returns newest-first already, but be safe.
        # task.time is an ISO string so string sort works.
        normalised.sort(key=lambda s: s.get("scanned_at") or "", reverse=True)
        capped = normalised[:RESULT_CAP]

        data = {
            "query": domain_name,
            # `total` from the API is the true count (capped at 10k by URLScan).
            # If total is 0 but we have results, fall back to the result count.
            "total_scans": total if total else len(normalised),
            "has_more": bool(has_more),
            "unique_ips": len(all_ips),
            "unique_countries": len(all_countries),
            "scans": capped,
            "cap_applied": RESULT_CAP,
        }

        return EnrichmentResult(
            enrichment_type=self.enrichment_type,
            status=EnrichmentStatus.OK,
            data=data,
        )
