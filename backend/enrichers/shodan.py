"""
Shodan domain enricher (BYOK).

Resolves the domain's A record, then queries Shodan's host API to get:
  - Open ports and services (banners)
  - Operating system detection
  - Organization / ISP
  - Known vulnerabilities (CVEs)
  - Country / city geolocation

Requires SHODAN_API_KEY environment variable. Free tier allows limited
queries but sufficient for single-domain enrichment.

Flow: domain -> DNS A record -> Shodan /shodan/host/{ip}
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

SHODAN_API_BASE = "https://api.shodan.io"
HTTP_TIMEOUT_SECONDS = 15
DNS_TIMEOUT_SECONDS = 5


class ShodanEnricher(BaseEnricher):
    """Enricher that queries Shodan for infrastructure exposure data."""

    enrichment_type = EnrichmentType.SHODAN

    def __init__(self) -> None:
        self._api_key = os.environ.get("SHODAN_API_KEY", "")

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
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.ERROR,
                data={},
                error_message="SHODAN_API_KEY not set. Add it to .env and restart.",
            )

        # Step 1: Resolve domain to IP
        ip = self._resolve_a_record(domain_name)
        if not ip:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.NOT_FOUND,
                data={"reason": "domain_did_not_resolve"},
                error_message=f"Could not resolve A record for {domain_name}",
            )

        # Step 2: Query Shodan host API
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
                response = client.get(
                    f"{SHODAN_API_BASE}/shodan/host/{ip}",
                    params={"key": self._api_key},
                )
        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.TIMEOUT,
                data={"ip": ip},
                error_message=f"Shodan did not respond within {HTTP_TIMEOUT_SECONDS}s",
            )
        except httpx.HTTPError as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message=f"HTTP error: {exc}",
            )

        if response.status_code == 404:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.NOT_FOUND,
                data={"ip": ip},
                error_message=f"IP {ip} not found in Shodan",
            )

        if response.status_code == 401:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message="Shodan API key is invalid",
            )

        if response.status_code == 429:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.RATE_LIMITED,
                data={"ip": ip},
                error_message="Shodan rate limit exceeded",
            )

        if response.status_code != 200:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message=f"Shodan returned HTTP {response.status_code}",
            )

        try:
            body = response.json()
        except Exception as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message=f"Failed to parse Shodan response: {exc}",
            )

        # Extract key fields
        ports = sorted(body.get("ports", []))
        vulns = sorted(body.get("vulns", []))
        os_name = body.get("os")
        org = body.get("org")
        isp = body.get("isp")
        country = body.get("country_name")
        city = body.get("city")
        asn = body.get("asn")
        last_update = body.get("last_update")

        # Extract service summaries from the data array
        services = []
        for item in body.get("data", [])[:20]:  # Cap at 20 services
            svc = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product"),
                "version": item.get("version"),
                "module": item.get("_shodan", {}).get("module"),
            }
            # Clean out None values
            services.append({k: v for k, v in svc.items() if v is not None})

        data = {
            "ip": ip,
            "ports": ports,
            "ports_count": len(ports),
            "vulns": vulns,
            "vulns_count": len(vulns),
            "os": os_name,
            "org": org,
            "isp": isp,
            "asn": asn,
            "country": country,
            "city": city,
            "services": services,
            "last_update": last_update,
        }

        return EnrichmentResult(
            enrichment_type=EnrichmentType.SHODAN,
            status=EnrichmentStatus.OK,
            data=data,
        )
