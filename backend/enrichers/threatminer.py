"""
ThreatMiner enricher.

ThreatMiner is a threat-intel portal aggregating IOC data. For a domain
it can return several data types, selected by the `rt` (report type)
query parameter:
  rt=1  WHOIS
  rt=2  Passive DNS
  rt=3  Subdomains
  rt=4  Related URIs
  rt=5  Related samples (malware hashes seen contacting the domain)
  rt=6  Related reports

We pull the three most useful-for-pivoting types in one enrichment:
  - Passive DNS (rt=2)     — historical IP resolutions
  - Subdomains (rt=3)      — discovered subdomains
  - Related samples (rt=5) — malware hashes associated with the domain

Each is a separate HTTP call. If one fails, the others still return —
the enricher only fails entirely if ALL three fail.

API: GET https://api.threatminer.org/v2/domain.php?q={domain}&rt={type}
Auth: none required. Rate limit ~10 requests/minute.
Docs: https://www.threatminer.org/api.php

Note: ThreatMiner has historically had patchy uptime. The per-call
error handling here is deliberately tolerant.

Response envelope:
  {"status_code": "200", "status_message": "Results found.", "results": [...]}
  status_code "404" means no results for that type (not an error).
"""
from __future__ import annotations

from typing import Any

import httpx

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


THREATMINER_DOMAIN_URL = "https://api.threatminer.org/v2/domain.php"
HTTP_TIMEOUT_SECONDS = 15

# Per data-type caps — ThreatMiner can return large lists.
PDNS_CAP = 100
SUBDOMAIN_CAP = 200
SAMPLE_CAP = 100

USER_AGENT = "ReconMesh/0.2 (CTI aggregator)"

# The report types we fetch, mapped to friendly names.
REPORT_TYPES = {
    "2": "passive_dns",
    "3": "subdomains",
    "5": "related_samples",
}


class ThreatMinerEnricher(BaseEnricher):
    """Enricher that queries ThreatMiner for passive DNS, subdomains, and samples."""

    enrichment_type = EnrichmentType.THREATMINER
    timeout_seconds = 60.0  # three sequential calls, each up to 15s + retries

    def enrich(self, domain_name: str) -> EnrichmentResult:
        # Track per-type outcomes so we can decide overall status.
        passive_dns: list[dict[str, Any]] = []
        subdomains: list[str] = []
        related_samples: list[dict[str, Any]] = []

        errors: list[str] = []
        any_call_succeeded = False
        any_timeout = False

        with httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
        ) as client:
            for rt, name in REPORT_TYPES.items():
                try:
                    response = client.get(
                        THREATMINER_DOMAIN_URL,
                        headers={"User-Agent": USER_AGENT},
                        params={"q": domain_name, "rt": rt},
                    )
                except httpx.TimeoutException:
                    errors.append(f"{name}: timeout")
                    any_timeout = True
                    continue
                except httpx.HTTPError as exc:
                    errors.append(f"{name}: {type(exc).__name__}")
                    continue

                if response.status_code != 200:
                    errors.append(f"{name}: HTTP {response.status_code}")
                    continue

                try:
                    body = response.json()
                except Exception:
                    errors.append(f"{name}: non-JSON response")
                    continue

                status_code = str(body.get("status_code", ""))
                results = body.get("results", [])

                # ThreatMiner uses status_code "404" for "no results" — that's
                # not an error, just an empty set.
                if status_code == "404":
                    any_call_succeeded = True
                    continue

                if status_code != "200":
                    errors.append(
                        f"{name}: status {status_code} "
                        f"({body.get('status_message', 'unknown')})"
                    )
                    continue

                any_call_succeeded = True

                # Parse per type
                if name == "passive_dns":
                    passive_dns = self._parse_passive_dns(results)
                elif name == "subdomains":
                    subdomains = self._parse_subdomains(results)
                elif name == "related_samples":
                    related_samples = self._parse_samples(results)

        # Decide overall status.
        # - Nothing succeeded + a timeout happened → TIMEOUT (retryable)
        # - Nothing succeeded, no timeout → ERROR (retryable)
        # - At least one call succeeded but everything's empty → NOT_FOUND
        # - At least one call succeeded with data → OK
        has_any_data = bool(passive_dns or subdomains or related_samples)

        if not any_call_succeeded:
            if any_timeout:
                return EnrichmentResult(
                    enrichment_type=self.enrichment_type,
                    status=EnrichmentStatus.TIMEOUT,
                    error_message="ThreatMiner timed out on all requests: " + "; ".join(errors),
                )
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message="ThreatMiner failed on all requests: " + "; ".join(errors),
            )

        data = {
            "query": domain_name,
            "passive_dns": passive_dns[:PDNS_CAP],
            "passive_dns_count": len(passive_dns),
            "subdomains": subdomains[:SUBDOMAIN_CAP],
            "subdomains_count": len(subdomains),
            "related_samples": related_samples[:SAMPLE_CAP],
            "related_samples_count": len(related_samples),
            "partial_errors": errors,  # surfaced in the UI if non-empty
            "caps": {
                "passive_dns": PDNS_CAP,
                "subdomains": SUBDOMAIN_CAP,
                "related_samples": SAMPLE_CAP,
            },
        }

        if not has_any_data:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.NOT_FOUND,
                error_message="ThreatMiner has no passive DNS, subdomains, or samples for this domain",
                data=data,
            )

        return EnrichmentResult(
            enrichment_type=self.enrichment_type,
            status=EnrichmentStatus.OK,
            data=data,
        )

    # ------------------------------------------------------------------------
    # Per-type parsers
    # ------------------------------------------------------------------------
    @staticmethod
    def _parse_passive_dns(results: list) -> list[dict[str, Any]]:
        """
        Passive DNS results look like:
          {"ip": "1.2.3.4", "first_seen": "...", "last_seen": "..."}
        """
        out: list[dict[str, Any]] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            out.append({
                "ip": r.get("ip") or "",
                "first_seen": r.get("first_seen") or None,
                "last_seen": r.get("last_seen") or None,
            })
        return out

    @staticmethod
    def _parse_subdomains(results: list) -> list[str]:
        """Subdomain results are a plain list of hostname strings."""
        out: list[str] = []
        seen: set[str] = set()
        for r in results:
            if not isinstance(r, str):
                continue
            low = r.lower().strip()
            if low and low not in seen:
                seen.add(low)
                out.append(r.strip())
        return out

    @staticmethod
    def _parse_samples(results: list) -> list[dict[str, Any]]:
        """
        Related samples can be either bare hash strings or dicts with
        hash + metadata depending on the ThreatMiner response. Handle both.
        """
        out: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r, str):
                out.append({"hash": r.strip()})
            elif isinstance(r, dict):
                out.append({
                    "hash": r.get("md5") or r.get("sha256") or r.get("hash") or "",
                    "family": r.get("family") or None,
                })
        # Drop any with no hash
        return [s for s in out if s.get("hash")]
