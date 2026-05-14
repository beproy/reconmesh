"""
HackerTarget reverse-IP enricher.

Reverse-IP lookup: given a domain, find OTHER hostnames that share the
same IP address. This surfaces co-hosted infrastructure — useful for
spotting that a malicious domain sits on the same box as other domains
(shared hosting, or a threat actor's infrastructure cluster).

Two-step lookup:
  1. Resolve the domain to an IP (HackerTarget's dnslookup, or we could
     use the domain directly — HackerTarget's reverseiplookup accepts a
     hostname and resolves it server-side).
  2. reverseiplookup returns all hostnames seen on that IP.

API: GET https://api.hackertarget.com/reverseiplookup/?q={domain}
Auth: none required. Free tier: 20 queries/day, 50 results/request.
      An optional API key (HACKERTARGET_API_KEY) raises the limits — we
      use it if set, work without it if not.
Docs: https://hackertarget.com/reverse-ip-lookup/

Response format: PLAIN TEXT, one hostname per line. NOT JSON.
  example.com
  www.example.com
  mail.example.com
  ...
Error responses are also plain text, e.g.:
  "error check your search parameter"
  "API count exceeded - Increase Quota with Membership"
"""
from __future__ import annotations

import os

import httpx

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


HACKERTARGET_REVERSEIP_URL = "https://api.hackertarget.com/reverseiplookup/"
HTTP_TIMEOUT_SECONDS = 20

# Free tier caps results at 50 anyway; we store up to this many.
RESULT_CAP = 100

USER_AGENT = "ReconMesh/0.2 (CTI aggregator)"

# HackerTarget signals errors in the plain-text body. These substrings
# (lowercased) indicate an error rather than real results.
ERROR_MARKERS = (
    "error",
    "api count exceeded",
    "api limit",
    "invalid",
    "no records",
    "no dns records",
)


class HackerTargetEnricher(BaseEnricher):
    """Enricher that does a reverse-IP lookup via HackerTarget."""

    enrichment_type = EnrichmentType.HACKERTARGET
    timeout_seconds = 30.0

    def __init__(self) -> None:
        # Optional — works without it, just with tighter rate limits.
        self._api_key = os.environ.get("HACKERTARGET_API_KEY", "")

    def enrich(self, domain_name: str) -> EnrichmentResult:
        params = {"q": domain_name}
        headers = {"User-Agent": USER_AGENT}

        # If a key is set, HackerTarget accepts it as the X-API-Key header.
        if self._api_key:
            headers["X-API-Key"] = self._api_key

        try:
            with httpx.Client(
                timeout=HTTP_TIMEOUT_SECONDS,
                follow_redirects=True,
            ) as client:
                response = client.get(
                    HACKERTARGET_REVERSEIP_URL,
                    headers=headers,
                    params=params,
                )
        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.TIMEOUT,
                error_message=f"HackerTarget did not respond within {HTTP_TIMEOUT_SECONDS}s",
            )
        except httpx.HTTPError as exc:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"HTTP error: {exc}",
            )

        if response.status_code == 429:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.RATE_LIMITED,
                error_message="HackerTarget rate limit exceeded (free tier: 20/day)",
            )

        if response.status_code != 200:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"HackerTarget returned HTTP {response.status_code}",
            )

        text = response.text.strip()

        # HackerTarget returns errors as plain text in a 200 response.
        # Check the first line against known error markers.
        first_line_lower = text.split("\n")[0].lower() if text else ""

        # Quota-exceeded is specifically a rate-limit condition
        if "api count exceeded" in first_line_lower or "api limit" in first_line_lower:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.RATE_LIMITED,
                error_message=(
                    "HackerTarget daily quota exceeded (free tier: 20 queries/day). "
                    "Set HACKERTARGET_API_KEY in .env for higher limits."
                ),
            )

        if not text:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.NOT_FOUND,
                error_message="HackerTarget returned no data for this domain",
            )

        if any(marker in first_line_lower for marker in ERROR_MARKERS):
            # "no records" style responses → NOT_FOUND; anything else → ERROR
            if "no records" in first_line_lower or "no dns records" in first_line_lower:
                return EnrichmentResult(
                    enrichment_type=self.enrichment_type,
                    status=EnrichmentStatus.NOT_FOUND,
                    error_message="No reverse-IP records found for this domain",
                    data={
                        "query": domain_name,
                        "resolved_ip": None,
                        "total_hostnames": 0,
                        "hostnames": [],
                        "cap_applied": RESULT_CAP,
                        "free_tier_note": not bool(self._api_key),
                    },
                )
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message=f"HackerTarget error: {text.split(chr(10))[0][:200]}",
            )

        # Real results — one hostname per line.
        # HackerTarget's reverseiplookup output is just hostnames; it does
        # not echo the resolved IP. We surface the hostname list.
        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]

        # De-dupe while preserving order, and drop the queried domain itself
        # from the "other hostnames" list (it's not interesting to show the
        # domain as co-hosted with itself).
        seen: set[str] = set()
        hostnames: list[str] = []
        for ln in lines:
            low = ln.lower()
            if low in seen:
                continue
            seen.add(low)
            hostnames.append(ln)

        capped = hostnames[:RESULT_CAP]
        was_capped = len(hostnames) > RESULT_CAP
 
        data = {
            "query": domain_name,
            "resolved_ip": None,  # reverseiplookup doesn't echo the IP
            # total_returned = what HackerTarget actually gave us this call.
            # stored = what we kept after applying our own RESULT_CAP.
            # These can differ; the UI shows both honestly.
            "total_returned": len(hostnames),
            "stored": len(capped),
            "hostnames": capped,
            "cap_applied": RESULT_CAP,
            "was_capped": was_capped,
            # Tell the UI whether we're on the free tier (HackerTarget caps
            # results upstream — 50 for free) so it can show a note.
            "free_tier_note": not bool(self._api_key),
        }

        return EnrichmentResult(
            enrichment_type=self.enrichment_type,
            status=EnrichmentStatus.OK,
            data=data,
        )
