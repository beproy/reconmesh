"""
AlienVault OTX ingester.

Fetches pulses from your OTX subscriptions and extracts domain/hostname
indicators. Each indicator becomes an IngestedRecord linked to its
registrable parent domain.

API: GET https://otx.alienvault.com/api/v1/pulses/subscribed
Auth: X-OTX-API-KEY header (free key from otx.alienvault.com)
Response: paginated JSON with pulses, each containing an indicators array.

We filter for indicator types 'domain' and 'hostname' only — file hashes,
IPs, URLs, etc. are skipped because ReconMesh is domain-centric.

Pagination: the API returns 50 pulses per page by default. We cap at
MAX_PAGES (10) pages per run to avoid running forever on accounts with
thousands of subscriptions. Each run processes the most recent pulses
first. Subsequent runs will update existing indicators via the base
class's upsert logic.

Requires: OTX_API_KEY environment variable. If not set, fetch() raises
with a clear error message.
"""
import json
import os
from datetime import datetime, timezone
from typing import Iterable, Optional

import httpx
import tldextract

from models import Confidence, IndicatorType, SourceType, TLP

from .base import BaseIngester, IngestedRecord


OTX_API_BASE = "https://otx.alienvault.com/api/v1"
HTTP_TIMEOUT_SECONDS = 30
PULSES_PER_PAGE = 50
MAX_PAGES = 10  # 10 pages x 50 pulses = 500 pulses max per run

# OTX indicator types we care about (domain-centric)
DOMAIN_TYPES = {"domain", "hostname"}


class OtxIngester(BaseIngester):
    name = "OTX"
    source_url = "https://otx.alienvault.com/"
    source_type = SourceType.FEED
    description = (
        "Domain and hostname IOCs from AlienVault Open Threat Exchange (OTX) "
        "pulse subscriptions. Requires a free API key."
    )

    def __init__(self) -> None:
        self._api_key = os.environ.get("OTX_API_KEY", "")

    # --------------------------------------------------------------------
    # Fetch — paginated API, returns concatenated JSON
    # --------------------------------------------------------------------
    def fetch(self) -> bytes:
        if not self._api_key:
            raise RuntimeError(
                "OTX_API_KEY not set. Add it to your .env file and restart "
                "the backend container. Get a free key at "
                "https://otx.alienvault.com/"
            )

        all_pulses: list[dict] = []
        headers = {"X-OTX-API-KEY": self._api_key}

        with httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True
        ) as client:
            for page_num in range(1, MAX_PAGES + 1):
                url = (
                    f"{OTX_API_BASE}/pulses/subscribed"
                    f"?page={page_num}&limit={PULSES_PER_PAGE}"
                )

                response = client.get(url, headers=headers)
                response.raise_for_status()

                data = response.json()
                results = data.get("results", [])
                if not results:
                    break

                all_pulses.extend(results)

                # Stop if there's no next page
                if not data.get("next"):
                    break

                print(
                    f"[OTX] fetched page {page_num} "
                    f"({len(results)} pulses, {len(all_pulses)} total)"
                )

        print(f"[OTX] fetch complete: {len(all_pulses)} pulses across {page_num} page(s)")

        # Serialize all pulses as JSON bytes for the parse() method
        return json.dumps(all_pulses).encode("utf-8")

    # --------------------------------------------------------------------
    # Parse — extract domain/hostname indicators from pulses
    # --------------------------------------------------------------------
    def parse(self, raw: bytes) -> Iterable[IngestedRecord]:
        try:
            pulses = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[OTX] JSON parse error: {e}")
            return

        if not isinstance(pulses, list):
            print(f"[OTX] unexpected data type: {type(pulses)}")
            return

        for pulse in pulses:
            try:
                yield from self._pulse_to_records(pulse)
            except Exception as e:
                pulse_name = pulse.get("name", "unknown")[:50]
                print(
                    f"[OTX] skipping pulse '{pulse_name}': "
                    f"{type(e).__name__}: {e}"
                )
                continue

    # --------------------------------------------------------------------
    # Per-pulse logic
    # --------------------------------------------------------------------
    def _pulse_to_records(self, pulse: dict) -> Iterable[IngestedRecord]:
        pulse_name = pulse.get("name", "")
        pulse_id = pulse.get("id", "")
        pulse_tags = pulse.get("tags", [])
        pulse_tlp = pulse.get("TLP", "white")
        pulse_created = pulse.get("created", "")
        pulse_modified = pulse.get("modified", "")
        adversary = pulse.get("adversary", "")
        references = pulse.get("references", [])

        # Map OTX TLP to our enum
        tlp = self._map_tlp(pulse_tlp)

        indicators = pulse.get("indicators", [])

        for ind in indicators:
            ind_type = (ind.get("type") or "").lower()
            if ind_type not in DOMAIN_TYPES:
                continue

            value = (ind.get("indicator") or "").strip().lower()
            if not value or "." not in value:
                continue

            ind_created = ind.get("created", "")
            is_active = bool(ind.get("is_active", 1))

            # Parse timestamps
            first_seen = self._parse_dt(ind_created) or self._parse_dt(pulse_created)
            last_seen = self._parse_dt(pulse_modified) or first_seen

            # Build tags from pulse metadata
            tags = self._build_tags(
                pulse_name, pulse_id, pulse_tags, adversary, ind_type,
            )

            # Reference URLs
            reference_urls = list(references[:3]) if references else []
            reference_urls.append(
                f"https://otx.alienvault.com/pulse/{pulse_id}"
            )

            # Extract registrable domain
            registrable = self._registrable_domain(value)

            yield IngestedRecord(
                indicator_type=IndicatorType.DOMAIN,
                value=value,
                confidence=Confidence.MEDIUM,
                tlp=tlp,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                is_active=is_active,
                reference_urls=reference_urls,
                related_domain=registrable or value,
            )

    # --------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------
    @staticmethod
    def _parse_dt(value) -> Optional[datetime]:
        """Parse OTX timestamps (ISO-ish, no timezone suffix — assumed UTC)."""
        if not value or not isinstance(value, str):
            return None
        # Try ISO format first (some have timezone)
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
        # Fallback: 'YYYY-MM-DDTHH:MM:SS'
        try:
            naive = datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
            return naive.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def _map_tlp(value: str) -> TLP:
        mapping = {
            "white": TLP.CLEAR,
            "green": TLP.GREEN,
            "amber": TLP.AMBER,
            "red": TLP.RED,
        }
        return mapping.get((value or "").lower(), TLP.CLEAR)

    @staticmethod
    def _registrable_domain(host: str) -> Optional[str]:
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return None

    @staticmethod
    def _build_tags(
        pulse_name: str,
        pulse_id: str,
        pulse_tags: list,
        adversary: str,
        ind_type: str,
    ) -> list[str]:
        out: list[str] = [f"otx_type:{ind_type}"]
        if pulse_tags:
            out.extend(str(t).strip() for t in pulse_tags[:10] if t)
        if adversary:
            out.append(f"adversary:{adversary.strip()}")
        if pulse_name:
            # Truncate long pulse names
            out.append(f"pulse:{pulse_name[:60].strip()}")
        if pulse_id:
            out.append(f"otx_pulse:{pulse_id}")
        return out
