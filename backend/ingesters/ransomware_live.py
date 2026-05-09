"""
Ransomware.live victim ingester.

Fetches recent ransomware victims from the ransomware.live API and
turns each victim entry into a DOMAIN indicator linked to the victim's
website domain.

API endpoint: GET https://api.ransomware.live/v1/recentvictims
Returns a JSON array of victim objects with fields including:
    website, group_name, discovered, country, activity, description,
    post_title, infostealer, etc.

We extract the victim's website domain and create indicators tagged
with the ransomware group, country, and sector. The signal here is
"this organization appeared on a ransomware leak site" — useful for
threat intel but NOT proof of a successful attack (groups sometimes
list victims preemptively or incorrectly).

No API key required for the free tier (personal use).
"""
from datetime import datetime, timezone
from typing import Iterable, Optional

import httpx
import tldextract

from models import Confidence, IndicatorType, SourceType, TLP

from .base import BaseIngester, IngestedRecord


RANSOMWARE_LIVE_API = "https://api.ransomware.live/v1/recentvictims"
HTTP_TIMEOUT_SECONDS = 30


class RansomwareLiveIngester(BaseIngester):
    name = "Ransomware.live"
    source_url = RANSOMWARE_LIVE_API
    source_type = SourceType.FEED
    description = (
        "Recent ransomware victims from ransomware.live. "
        "Tracks ransomware group leak sites and victim disclosures. "
        "Free API, no key required for personal use."
    )

    # --------------------------------------------------------------------
    # Fetch
    # --------------------------------------------------------------------
    def fetch(self) -> bytes:
        with httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True
        ) as client:
            response = client.get(
                RANSOMWARE_LIVE_API,
                headers={"User-Agent": "ReconMesh/0.4 (CTI aggregator)"},
            )
            response.raise_for_status()
            return response.content

    # --------------------------------------------------------------------
    # Parse
    # --------------------------------------------------------------------
    def parse(self, raw: bytes) -> Iterable[IngestedRecord]:
        import json

        try:
            victims = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[Ransomware.live] JSON parse error: {e}")
            return

        if not isinstance(victims, list):
            print(f"[Ransomware.live] unexpected response type: {type(victims)}")
            return

        for victim in victims:
            try:
                record = self._victim_to_record(victim)
                if record is not None:
                    yield record
            except Exception as e:
                print(
                    f"[Ransomware.live] skipping victim: "
                    f"{type(e).__name__}: {e}"
                )
                continue

    # --------------------------------------------------------------------
    # Per-victim logic
    # --------------------------------------------------------------------
    def _victim_to_record(self, victim: dict) -> Optional[IngestedRecord]:
        website = (victim.get("website") or "").strip().lower()
        if not website:
            return None

        # Clean up the website field — sometimes has protocol prefix
        if website.startswith("http://"):
            website = website[7:]
        elif website.startswith("https://"):
            website = website[8:]
        # Remove trailing slashes and paths
        website = website.split("/")[0].strip()

        if not website or "." not in website:
            return None

        group_name = (victim.get("group_name") or "unknown").strip()
        country = (victim.get("country") or "").strip()
        activity = (victim.get("activity") or "").strip()
        post_title = (victim.get("post_title") or "").strip()
        discovered = victim.get("discovered")

        # Parse the discovered timestamp
        first_seen = self._parse_dt(discovered)

        # Build tags
        tags = self._build_tags(group_name, country, activity, post_title)

        # Extract registrable domain
        registrable = self._registrable_domain(website)

        # Build reference URL — link to ransomware.live group page
        reference_urls = [
            f"https://www.ransomware.live/group/{group_name}"
        ]

        return IngestedRecord(
            indicator_type=IndicatorType.DOMAIN,
            value=website,
            confidence=Confidence.HIGH,
            tlp=TLP.CLEAR,
            tags=tags,
            first_seen=first_seen,
            last_seen=first_seen,  # discovery date is all we have
            is_active=True,
            reference_urls=reference_urls,
            related_domain=registrable or website,
        )

    # --------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------
    @staticmethod
    def _parse_dt(value) -> Optional[datetime]:
        """Parse ransomware.live ISO format timestamps."""
        if not value:
            return None
        if isinstance(value, str):
            # Handle ISO format with timezone: 2026-05-09T08:56:53.056312+00:00
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                pass
            # Fallback: try without timezone
            try:
                naive = datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
                return naive.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None

    @staticmethod
    def _registrable_domain(host: str) -> Optional[str]:
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return None

    @staticmethod
    def _build_tags(
        group_name: str,
        country: str,
        activity: str,
        post_title: str,
    ) -> list[str]:
        out: list[str] = ["ransomware_victim"]
        if group_name and group_name != "unknown":
            out.append(f"group:{group_name}")
        if country:
            out.append(f"country:{country}")
        if activity:
            out.append(f"sector:{activity}")
        if post_title:
            # Truncate long post titles for the tag
            title = post_title[:80]
            out.append(f"victim:{title}")
        return out
