"""
Shodan domain enricher (BYOK — free tier compatible).

Uses the Shodan free tier endpoints to provide basic infrastructure intel:
  - DNS resolution (domain -> IP)
  - Host count (how many scan results Shodan has for that IP)

The full host details (open ports, services, vulns, OS) require a Shodan
membership ($59 one-time). If the API key has membership access, this
enricher will automatically use the full host endpoint instead.

Flow:
  1. Resolve domain via Shodan DNS API
  2. Try full host endpoint (works on paid tier)
  3. If 403, fall back to host count (works on free tier)

Requires SHODAN_API_KEY environment variable.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


log = logging.getLogger(__name__)

SHODAN_API_BASE = "https://api.shodan.io"
HTTP_TIMEOUT_SECONDS = 15


class ShodanEnricher(BaseEnricher):
    """Enricher that queries Shodan for infrastructure exposure data."""

    enrichment_type = EnrichmentType.SHODAN

    def __init__(self) -> None:
        self._api_key = os.environ.get("SHODAN_API_KEY", "")

    def enrich(self, domain_name: str) -> EnrichmentResult:
        if not self._api_key:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.ERROR,
                data={},
                error_message="SHODAN_API_KEY not set. Add it to .env and restart.",
            )

        # Step 1: Resolve domain via Shodan's DNS API
        ip = self._resolve_via_shodan(domain_name)
        if not ip:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.NOT_FOUND,
                data={"reason": "domain_did_not_resolve"},
                error_message=f"Could not resolve {domain_name} via Shodan DNS",
            )

        # Step 2: Try full host endpoint first (paid tier)
        full_result = self._try_full_host(ip)
        if full_result is not None:
            return full_result

        # Step 3: Fall back to host count (free tier)
        return self._host_count_fallback(ip, domain_name)

    # ------------------------------------------------------------------
    # Shodan DNS resolution
    # ------------------------------------------------------------------
    def _resolve_via_shodan(self, domain_name: str) -> Optional[str]:
        """Resolve domain to IP using Shodan's DNS endpoint."""
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
                r = client.get(
                    f"{SHODAN_API_BASE}/dns/resolve",
                    params={"hostnames": domain_name, "key": self._api_key},
                )
                if r.status_code == 200:
                    data = r.json()
                    return data.get(domain_name)
        except Exception as exc:
            log.warning("Shodan DNS resolve failed: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Full host endpoint (paid tier)
    # ------------------------------------------------------------------
    def _try_full_host(self, ip: str) -> Optional[EnrichmentResult]:
        """
        Try the full /shodan/host/{ip} endpoint. Returns None if the
        endpoint is blocked (403 = free tier), letting the caller fall
        back to the count endpoint.
        """
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

        # 403 = free tier, fall back to count
        if response.status_code == 403:
            return None

        if response.status_code == 404:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.NOT_FOUND,
                data={"ip": ip, "tier": "paid"},
                error_message=f"IP {ip} not found in Shodan",
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

        # Full host data available (paid tier)
        ports = sorted(body.get("ports", []))
        vulns = sorted(body.get("vulns", []))
        services = []
        for item in body.get("data", [])[:20]:
            svc = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product"),
                "version": item.get("version"),
                "module": item.get("_shodan", {}).get("module"),
            }
            services.append({k: v for k, v in svc.items() if v is not None})

        return EnrichmentResult(
            enrichment_type=EnrichmentType.SHODAN,
            status=EnrichmentStatus.OK,
            data={
                "ip": ip,
                "tier": "paid",
                "ports": ports,
                "ports_count": len(ports),
                "vulns": vulns,
                "vulns_count": len(vulns),
                "os": body.get("os"),
                "org": body.get("org"),
                "isp": body.get("isp"),
                "asn": body.get("asn"),
                "country": body.get("country_name"),
                "city": body.get("city"),
                "services": services,
                "last_update": body.get("last_update"),
            },
        )

    # ------------------------------------------------------------------
    # Host count fallback (free tier)
    # ------------------------------------------------------------------
    def _host_count_fallback(
        self, ip: str, domain_name: str
    ) -> EnrichmentResult:
        """
        Use /shodan/host/count to check if Shodan has scanned this IP.
        Available on the free (oss) tier.
        """
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
                r = client.get(
                    f"{SHODAN_API_BASE}/shodan/host/count",
                    params={"query": f"ip:{ip}", "key": self._api_key},
                )
        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.TIMEOUT,
                data={"ip": ip},
                error_message="Shodan host count timed out",
            )
        except httpx.HTTPError as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message=f"HTTP error on host count: {exc}",
            )

        if r.status_code != 200:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.SHODAN,
                status=EnrichmentStatus.ERROR,
                data={"ip": ip},
                error_message=f"Shodan host count returned HTTP {r.status_code}",
            )

        try:
            body = r.json()
        except Exception:
            body = {}

        total = body.get("total", 0)
        seen_by_shodan = total > 0

        return EnrichmentResult(
            enrichment_type=EnrichmentType.SHODAN,
            status=EnrichmentStatus.OK,
            data={
                "ip": ip,
                "tier": "free",
                "seen_by_shodan": seen_by_shodan,
                "scan_results_count": total,
                "note": (
                    f"Shodan has {total} scan result(s) for {ip}. "
                    "Full port/service/vulnerability details require a "
                    "Shodan membership (shodan.io/store/member)."
                    if seen_by_shodan
                    else f"IP {ip} has not been observed by Shodan scanners."
                ),
            },
        )
