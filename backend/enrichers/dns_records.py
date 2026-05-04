"""
DNS records enricher.

Looks up the standard DNS record types for a domain:
  - A     (IPv4 addresses)
  - AAAA  (IPv6 addresses)
  - MX    (mail exchangers)
  - NS    (authoritative nameservers)
  - TXT   (text records — SPF, DKIM hints, verification, etc.)
  - CNAME (aliases)

Each record type is queried independently. If one type fails (NXDOMAIN,
NoAnswer, timeout) the others still return. The enricher itself never
raises — it always returns an EnrichmentResult.
"""
from typing import Any

import dns.exception
import dns.resolver

from models import EnrichmentStatus, EnrichmentType
from .base import BaseEnricher, EnrichmentResult


# Record types we always try
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

# Per-query timeout. dnspython has both `timeout` (per-attempt) and
# `lifetime` (total time including retries). We set both.
PER_QUERY_TIMEOUT = 5.0


class DnsEnricher(BaseEnricher):
    enrichment_type = EnrichmentType.DNS
    timeout_seconds = 30.0  # generous overall budget

    def enrich(self, domain_name: str) -> EnrichmentResult:
        resolver = dns.resolver.Resolver()
        resolver.timeout = PER_QUERY_TIMEOUT
        resolver.lifetime = PER_QUERY_TIMEOUT

        records: dict[str, Any] = {}
        per_type_status: dict[str, str] = {}
        any_succeeded = False

        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain_name, rtype)
                records[rtype] = self._format_answers(rtype, answers)
                per_type_status[rtype] = "ok"
                any_succeeded = True
            except dns.resolver.NXDOMAIN:
                # The domain itself doesn't exist — no point trying further
                return EnrichmentResult(
                    enrichment_type=self.enrichment_type,
                    status=EnrichmentStatus.NOT_FOUND,
                    error_message=f"NXDOMAIN: {domain_name} does not exist",
                    data={"records": {}, "per_type_status": {"_": "nxdomain"}},
                )
            except dns.resolver.NoAnswer:
                # Domain exists but has no records of this type — common,
                # not an error
                records[rtype] = []
                per_type_status[rtype] = "no_answer"
            except dns.exception.Timeout:
                records[rtype] = []
                per_type_status[rtype] = "timeout"
            except dns.resolver.NoNameservers:
                records[rtype] = []
                per_type_status[rtype] = "no_nameservers"
            except Exception as e:
                records[rtype] = []
                per_type_status[rtype] = f"error: {type(e).__name__}"

        # If literally nothing worked, return an error so the caller can flag it
        if not any_succeeded:
            return EnrichmentResult(
                enrichment_type=self.enrichment_type,
                status=EnrichmentStatus.ERROR,
                error_message="No DNS record types could be resolved",
                data={"records": records, "per_type_status": per_type_status},
            )

        return EnrichmentResult(
            enrichment_type=self.enrichment_type,
            status=EnrichmentStatus.OK,
            data={
                "records": records,
                "per_type_status": per_type_status,
            },
        )

    @staticmethod
    def _format_answers(rtype: str, answers: dns.resolver.Answer) -> list[dict[str, Any]]:
        """
        Normalize DNS answers into JSON-friendly dicts.
        Each record type has slightly different rdata fields worth surfacing.
        """
        out: list[dict[str, Any]] = []
        for rdata in answers:
            entry: dict[str, Any] = {"value": rdata.to_text()}

            if rtype == "MX":
                # MX records have preference + exchange — surface them explicitly
                entry["preference"] = rdata.preference
                entry["exchange"] = str(rdata.exchange).rstrip(".")
            elif rtype in ("A", "AAAA"):
                entry["address"] = rdata.address
            elif rtype == "NS":
                entry["target"] = str(rdata.target).rstrip(".")
            elif rtype == "CNAME":
                entry["target"] = str(rdata.target).rstrip(".")
            elif rtype == "TXT":
                # TXT rdata.strings is a tuple of bytes — join into one string
                joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
                entry["text"] = joined

            out.append(entry)
        return out
