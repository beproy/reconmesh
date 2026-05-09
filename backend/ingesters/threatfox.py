"""
ThreatFox domain ingester (abuse.ch).

Fetches the recent-domains CSV from ThreatFox and turns each row into
a DOMAIN indicator linked to its registrable parent domain.

Feed format (15 columns, comment lines start with #):
    first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type,
    fk_malware, malware_alias, malware_printable, last_seen_utc,
    confidence_level, is_compromised, reference, tags, anonymous, reporter

We only process rows where ioc_type == "domain". The feed URL returns
domains observed in the last ~30 days. No API key required for this
specific export endpoint.
"""
import csv
import io
from datetime import datetime, timezone
from typing import Iterable, Optional

import httpx
import tldextract

from models import Confidence, IndicatorType, SourceType, TLP

from .base import BaseIngester, IngestedRecord


THREATFOX_FEED_URL = "https://threatfox.abuse.ch/export/csv/domains/recent/"
HTTP_TIMEOUT_SECONDS = 60


class ThreatFoxIngester(BaseIngester):
    name = "ThreatFox"
    source_url = THREATFOX_FEED_URL
    source_type = SourceType.FEED
    description = (
        "Recent malware/botnet C2 domain IOCs from ThreatFox (abuse.ch). "
        "Public feed, no API key. Domains observed in the last ~30 days."
    )

    # --------------------------------------------------------------------
    # Fetch
    # --------------------------------------------------------------------
    def fetch(self) -> bytes:
        with httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True
        ) as client:
            response = client.get(
                THREATFOX_FEED_URL,
                headers={"User-Agent": "ReconMesh/0.4 (CTI aggregator)"},
            )
            response.raise_for_status()
            return response.content

    # --------------------------------------------------------------------
    # Parse
    # --------------------------------------------------------------------
    def parse(self, raw: bytes) -> Iterable[IngestedRecord]:
        text = raw.decode("utf-8", errors="replace")

        # Strip comment lines (start with #) and blank lines
        data_lines = [
            line for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]

        reader = csv.reader(io.StringIO("\n".join(data_lines)))

        for row in reader:
            # ThreatFox CSV has 15 columns; some older exports had 14
            # (missing is_compromised). Accept both.
            if len(row) < 14:
                continue

            try:
                yield from self._row_to_records(row)
            except Exception as e:
                print(
                    f"[ThreatFox] skipping malformed row: "
                    f"{type(e).__name__}: {e}"
                )
                continue

    # --------------------------------------------------------------------
    # Per-row logic
    # --------------------------------------------------------------------
    def _row_to_records(self, row: list[str]) -> Iterable[IngestedRecord]:
        # Fields are space-padded after commas in the CSV — strip each
        first_seen_utc = row[0].strip().strip('"')
        ioc_id = row[1].strip().strip('"')
        ioc_value = row[2].strip().strip('"')
        ioc_type = row[3].strip().strip('"')
        threat_type = row[4].strip().strip('"')
        fk_malware = row[5].strip().strip('"')
        malware_alias = row[6].strip().strip('"')
        malware_printable = row[7].strip().strip('"')
        last_seen_utc = row[8].strip().strip('"')
        confidence_str = row[9].strip().strip('"')
        # is_compromised may or may not exist (column 10)
        # reference is column 11 (or 10 in older format)
        reference = row[11].strip().strip('"') if len(row) > 11 else ""
        tags_field = row[12].strip().strip('"') if len(row) > 12 else ""
        reporter = row[14].strip().strip('"') if len(row) > 14 else ""

        # We only care about domain IOCs
        if ioc_type.lower() != "domain":
            return

        if not ioc_value:
            return

        domain_name = ioc_value.lower().strip()

        # Map ThreatFox confidence (0-100 int) to our enum
        confidence = self._map_confidence(confidence_str)

        # Parse timestamps
        first_seen = self._parse_dt(first_seen_utc)
        last_seen = self._parse_dt(last_seen_utc)

        # Build tags
        tags = self._build_tags(
            threat_type, fk_malware, malware_printable,
            malware_alias, tags_field, reporter, ioc_id,
        )

        # Reference URLs
        reference_urls = []
        if reference and reference.lower() != "none":
            reference_urls.append(reference)
        # Always add the ThreatFox page for this IOC
        reference_urls.append(
            f"https://threatfox.abuse.ch/ioc/{ioc_id}/"
        )

        # Extract registrable domain for the domain link
        registrable = self._registrable_domain(domain_name)

        yield IngestedRecord(
            indicator_type=IndicatorType.DOMAIN,
            value=domain_name,
            confidence=confidence,
            tlp=TLP.CLEAR,
            tags=tags,
            first_seen=first_seen,
            last_seen=last_seen,
            is_active=True,
            reference_urls=reference_urls,
            related_domain=registrable or domain_name,
        )

    # --------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------
    @staticmethod
    def _parse_dt(value: str) -> Optional[datetime]:
        """ThreatFox dates: 'YYYY-MM-DD HH:MM:SS' in UTC."""
        if not value:
            return None
        try:
            naive = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S")
            return naive.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def _map_confidence(value: str) -> Confidence:
        """Map ThreatFox's 0-100 confidence to our enum."""
        try:
            level = int(value)
        except (ValueError, TypeError):
            return Confidence.MEDIUM

        if level >= 90:
            return Confidence.CONFIRMED
        if level >= 70:
            return Confidence.HIGH
        if level >= 40:
            return Confidence.MEDIUM
        return Confidence.LOW

    @staticmethod
    def _registrable_domain(host: str) -> Optional[str]:
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return None

    @staticmethod
    def _build_tags(
        threat_type: str,
        fk_malware: str,
        malware_printable: str,
        malware_alias: str,
        tags_field: str,
        reporter: str,
        ioc_id: str,
    ) -> list[str]:
        out: list[str] = []
        if threat_type:
            out.append(threat_type.strip())
        if malware_printable and malware_printable.lower() != "none":
            out.append(f"malware:{malware_printable.strip()}")
        if malware_alias and malware_alias.lower() != "none":
            out.append(f"alias:{malware_alias.strip()}")
        if tags_field:
            out.extend(t.strip() for t in tags_field.split(",") if t.strip())
        if reporter:
            out.append(f"reporter:{reporter.strip()}")
        if ioc_id:
            out.append(f"threatfox_id:{ioc_id.strip()}")
        return out
