"""
URLhaus ingester (abuse.ch).

Fetches the recent URLs CSV from URLhaus and turns each row into:
  - a URL indicator (the malicious URL itself)
  - an IPV4/IPV6 indicator if the host is an IP address
  - a Domain row (and link the URL indicator to it) if the host is a domain

Feed format (9 columns, comment lines start with #):
    id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"""
import csv
import io
import ipaddress
from datetime import datetime, timezone
from typing import Iterable, Optional
from urllib.parse import urlparse

import httpx
import tldextract

from models import Confidence, IndicatorType, SourceType, TLP

from .base import BaseIngester, IngestedRecord


URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Reasonable timeout — feed is a few MB, should download in seconds
HTTP_TIMEOUT_SECONDS = 60


class UrlhausIngester(BaseIngester):
    name = "URLhaus"
    source_url = URLHAUS_FEED_URL
    source_type = SourceType.FEED
    description = (
        "Recent malware distribution URLs from URLhaus (abuse.ch). "
        "Public feed, no API key. Updated frequently."
    )

    # ------------------------------------------------------------------------
    # Fetch
    # ------------------------------------------------------------------------
    def fetch(self) -> bytes:
        """Download the URLhaus recent CSV. Raises on HTTP errors."""
        with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = client.get(
                URLHAUS_FEED_URL,
                headers={"User-Agent": "ReconMesh/0.1 (CTI aggregator)"},
            )
            response.raise_for_status()
            return response.content

    # ------------------------------------------------------------------------
    # Parse
    # ------------------------------------------------------------------------
    def parse(self, raw: bytes) -> Iterable[IngestedRecord]:
        """
        URLhaus CSV is comment-prefixed. We strip comment lines, then read
        the rest as CSV. Each row produces one URL indicator, plus
        sometimes an IP indicator if the host is an IP.
        """
        text = raw.decode("utf-8", errors="replace")

        # Filter out comment lines (start with #)
        data_lines = [
            line for line in text.splitlines()
            if line and not line.startswith("#")
        ]

        # Read as CSV — URLhaus quotes every field
        reader = csv.reader(io.StringIO("\n".join(data_lines)))

        for row in reader:
            if len(row) != 9:
                # malformed line, skip rather than crash
                continue

            try:
                yield from self._row_to_records(row)
            except Exception as e:
                print(f"[URLhaus] skipping malformed row: {type(e).__name__}: {e}")
                continue

    # ------------------------------------------------------------------------
    # Per-row logic
    # ------------------------------------------------------------------------
    def _row_to_records(self, row: list[str]) -> Iterable[IngestedRecord]:
        (
            urlhaus_id,
            dateadded,
            url,
            url_status,
            last_online,
            threat,
            tags_field,
            urlhaus_link,
            reporter,
        ) = row

        # Parse the URL to extract the host
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            # Malformed URL — skip
            return

        # Combine the threat category with the tags field
        tags = self._build_tags(threat, tags_field, reporter, urlhaus_id)

        # Parse timestamps (URLhaus uses UTC, no tz suffix)
        first_seen = self._parse_dt(dateadded)
        last_seen = self._parse_dt(last_online)
        is_active = url_status.lower() == "online"

        reference_urls = [urlhaus_link] if urlhaus_link else []

        # Decide: is the host an IP or a domain?
        ip_version = self._ip_version(host)

        if ip_version is not None:
            # Host is an IP — emit a URL indicator (no domain link) AND an IP indicator
            yield IngestedRecord(
                indicator_type=IndicatorType.URL,
                value=url,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                is_active=is_active,
                reference_urls=reference_urls,
                confidence=Confidence.HIGH,
                tlp=TLP.CLEAR,
                related_domain=None,
            )
            yield IngestedRecord(
                indicator_type=(
                    IndicatorType.IPV4 if ip_version == 4 else IndicatorType.IPV6
                ),
                value=host,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                is_active=is_active,
                reference_urls=reference_urls,
                confidence=Confidence.HIGH,
                tlp=TLP.CLEAR,
                related_domain=None,
            )
        else:
            # Host is a domain — extract the registrable parent
            registrable = self._registrable_domain(host)
            yield IngestedRecord(
                indicator_type=IndicatorType.URL,
                value=url,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                is_active=is_active,
                reference_urls=reference_urls,
                confidence=Confidence.HIGH,
                tlp=TLP.CLEAR,
                related_domain=registrable,
            )

    # ------------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------------
    @staticmethod
    def _parse_dt(value: str) -> Optional[datetime]:
        """URLhaus dates: 'YYYY-MM-DD HH:MM:SS' in UTC."""
        if not value:
            return None
        try:
            naive = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S")
            return naive.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def _ip_version(host: str) -> Optional[int]:
        """Return 4 if host is an IPv4 address, 6 if IPv6, None if not an IP."""
        try:
            return ipaddress.ip_address(host).version
        except ValueError:
            return None

    @staticmethod
    def _registrable_domain(host: str) -> Optional[str]:
        """
        Extract the registrable (eTLD+1) domain from a hostname.
        e.g. 'logic.archiv-checkered.surf' -> 'archiv-checkered.surf'
             'www.example.co.uk'           -> 'example.co.uk'
        """
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return None

    @staticmethod
    def _build_tags(
        threat: str,
        tags_field: str,
        reporter: str,
        urlhaus_id: str,
    ) -> list[str]:
        """Merge URLhaus's threat + tags into a single tag list."""
        out: list[str] = []
        if threat:
            out.append(threat.strip())
        if tags_field:
            out.extend(t.strip() for t in tags_field.split(",") if t.strip())
        if reporter:
            out.append(f"reporter:{reporter.strip()}")
        if urlhaus_id:
            out.append(f"urlhaus_id:{urlhaus_id.strip()}")
        return out