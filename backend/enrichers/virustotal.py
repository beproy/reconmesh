"""
VirusTotal domain enricher (BYOK).

Queries the VirusTotal API v3 domain endpoint to get:
  - Analysis stats (how many engines flag it as malicious/suspicious/harmless)
  - Reputation score (community voting)
  - Categories (what security vendors classify this domain as)
  - Popularity ranks (Alexa, Statvoo, etc.)
  - JARM fingerprint (TLS fingerprint for the domain's server)

Requires VIRUSTOTAL_API_KEY environment variable. Free tier allows 4
requests/minute — sufficient for single-domain enrichment but will
rate-limit during bulk operations.

API: GET https://www.virustotal.com/api/v3/domains/{domain}
Auth: x-apikey header
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


log = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"
HTTP_TIMEOUT_SECONDS = 15


class VirusTotalEnricher(BaseEnricher):
    """Enricher that queries VirusTotal for domain reputation data."""

    enrichment_type = EnrichmentType.VIRUSTOTAL

    def __init__(self) -> None:
        self._api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    def enrich(self, domain_name: str) -> EnrichmentResult:
        if not self._api_key:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.VIRUSTOTAL,
                status=EnrichmentStatus.ERROR,
                data={},
                error_message=(
                    "VIRUSTOTAL_API_KEY not set. Add it to .env and restart."
                ),
            )

        try:
            with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
                response = client.get(
                    f"{VT_API_BASE}/domains/{domain_name}",
                    headers={"x-apikey": self._api_key},
                )
        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.VIRUSTOTAL,
                status=EnrichmentStatus.TIMEOUT,
                data={},
                error_message=f"VirusTotal did not respond within {HTTP_TIMEOUT_SECONDS}s",
            )
        except httpx.HTTPError as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.VIRUSTOTAL,
                status=EnrichmentStatus.ERROR,
                data={},
                error_message=f"HTTP error: {exc}",
            )

        # Handle specific status codes
        if response.status_code == 404:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.VIRUSTOTAL,
                status=EnrichmentStatus.NOT_FOUND,
                data={},
                error_message="Domain not found in VirusTotal",
            )

        if response.status_code == 429:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.VIRUSTOTAL,
                status=EnrichmentStatus.RATE_LIMITED,
                data={},
                error_message="VirusTotal rate limit exceeded (4 req/min on free tier)",
            )

        if response.status_code != 200:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.VIRUSTOTAL,
                status=EnrichmentStatus.ERROR,
                data={},
                error_message=f"VirusTotal returned HTTP {response.status_code}",
            )

        # Parse the response
        try:
            body = response.json()
            attrs = body.get("data", {}).get("attributes", {})
        except Exception as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.VIRUSTOTAL,
                status=EnrichmentStatus.ERROR,
                data={},
                error_message=f"Failed to parse VT response: {exc}",
            )

        # Extract the fields we care about
        stats = attrs.get("last_analysis_stats", {})
        reputation = attrs.get("reputation", 0)
        categories = attrs.get("categories", {})
        popularity = attrs.get("popularity_ranks", {})
        jarm = attrs.get("jarm", "")
        creation_date = attrs.get("creation_date")
        last_analysis_date = attrs.get("last_analysis_date")

        # Compute a simple verdict based on analysis stats
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif total > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        # Flatten categories into a simple list
        category_list = sorted(set(
            v.split(" (")[0] if " (" in v else v
            for v in categories.values()
            if v
        ))

        # Flatten popularity into a simple dict
        popularity_flat = {}
        for source, rank_data in popularity.items():
            if isinstance(rank_data, dict) and "rank" in rank_data:
                popularity_flat[source] = rank_data["rank"]
            elif isinstance(rank_data, (int, float)):
                popularity_flat[source] = rank_data

        data = {
            "verdict": verdict,
            "analysis_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total,
            },
            "reputation": reputation,
            "categories": category_list,
            "popularity_ranks": popularity_flat,
            "jarm": jarm or None,
            "creation_date": creation_date,
            "last_analysis_date": last_analysis_date,
        }

        return EnrichmentResult(
            enrichment_type=EnrichmentType.VIRUSTOTAL,
            status=EnrichmentStatus.OK,
            data=data,
        )
