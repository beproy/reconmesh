"""
AbuseIPDB domain enricher (BYOK).

Resolves the domain's A record, then queries AbuseIPDB's check endpoint
to get:
  - Abuse confidence score (0-100)
  - Total reports and distinct reporters
  - Country, ISP, usage type
  - Whether the IP is a known Tor exit node
  - Whether the IP is whitelisted

Requires ABUSEIPDB_API_KEY environment variable. Free tier allows 1,000
checks per day — sufficient for normal enrichment use.

Flow: domain -> DNS A record -> AbuseIPDB /api/v2/check?ipAddress={ip}
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import dns.resolver
import dns.exception
import httpx

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


log = logging.getLogger(__name__)

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"
HTTP_TIMEOUT_SECONDS = 15
DNS_TIMEOUT_SECONDS = 5


class AbuseIPDBEnricher(BaseEnricher):
    """Enricher that queries AbuseIPDB for IP abuse history."""

    enrichment_type = EnrichmentType.ABUSEIPDB

    def __init__(self) -> None:
        self._api_key = os.environ.get("ABUSEIPDB_API_KEY", "")

    def _resolve_a_record(self, domain_name: str) -> Optional[str]:
        """Resolve domain to its first A record IP."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT_SECONDS
            resolver.lifetime = DNS_TIMEOUT_SECONDS
            answer = resolver.resolve(domain_name, "A")
            for rdata in answer:
                return rdata.address
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return None
        return None

    def enrich(self, domain_name: str) -> EnrichmentResult:
        if not self._api_key:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.ABUSEIPDB,
                status=EnrichmentStatus.ERROR,
                data={},
                error_message="ABUSEIPDB_API_KEY not set. Add it to .env and restart.",
            )

        # Step 1: Resolve domain to IP
        ip = self._resolve_a_record(domain_name)
        if not ip:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.ABUSEIPDB,
                status=EnrichmentStatus.NOT_FOUND,
                data={"reason": "domain_did_not_resolve"},
                error_message=f"Could not resolve A record for {domain_name}",
            )

        # Step 2: Query AbuseIPDB
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
                response = client.get(
                    f"{ABUSEIPDB_API_BASE}/check",
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": "",
                    },
                    headers={
                        "Key": self._api_key,
                        "Accept": "application/json",
                    },
                )
        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.ABUSEIPDB,
                status=EnrichmentStatus.TIMEOUT,
                data={"ip": ip},
                error_message=f"AbuseIPDB did not respond within {HTTP_TIMEOUT_SECONDS}s",
            )
        except httpx.HTTPError as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.ABUSEIPDB,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message=f"HTTP error: {exc}",
            )

        if response.status_code == 401:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.ABUSEIPDB,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message="AbuseIPDB API key is invalid",
            )

        if response.status_code == 429:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.ABUSEIPDB,
                status=EnrichmentStatus.RATE_LIMITED,
                data={"ip": ip},
                error_message="AbuseIPDB rate limit exceeded (1,000/day on free tier)",
            )

        if response.status_code != 200:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.ABUSEIPDB,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message=f"AbuseIPDB returned HTTP {response.status_code}",
            )

        try:
            body = response.json()
            attrs = body.get("data", {})
        except Exception as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.ABUSEIPDB,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message=f"Failed to parse AbuseIPDB response: {exc}",
            )

        # Extract key fields
        abuse_score = attrs.get("abuseConfidenceScore", 0)
        total_reports = attrs.get("totalReports", 0)
        distinct_users = attrs.get("numDistinctUsers", 0)
        country_code = attrs.get("countryCode")
        country_name = attrs.get("countryName")
        isp_name = attrs.get("isp")
        usage_type = attrs.get("usageType")
        domain_field = attrs.get("domain")
        is_tor = attrs.get("isTor", False)
        is_whitelisted = attrs.get("isWhitelisted", False)
        last_reported = attrs.get("lastReportedAt")

        # Compute a simple threat level based on abuse score
        if abuse_score >= 80:
            threat_level = "high"
        elif abuse_score >= 40:
            threat_level = "medium"
        elif abuse_score > 0:
            threat_level = "low"
        else:
            threat_level = "none"

        data = {
            "ip": ip,
            "abuse_confidence_score": abuse_score,
            "threat_level": threat_level,
            "total_reports": total_reports,
            "distinct_reporters": distinct_users,
            "country_code": country_code,
            "country_name": country_name,
            "isp": isp_name,
            "usage_type": usage_type,
            "domain": domain_field,
            "is_tor": is_tor,
            "is_whitelisted": is_whitelisted,
            "last_reported_at": last_reported,
        }

        return EnrichmentResult(
            enrichment_type=EnrichmentType.ABUSEIPDB,
            status=EnrichmentStatus.OK,
            data=data,
        )
