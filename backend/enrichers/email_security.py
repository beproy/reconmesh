"""
Email security enricher.

Checks a domain's email-spoofing protections:
  - SPF   — Sender Policy Framework, in a TXT record at the domain root
  - DMARC — Domain-based Message Authentication, in a TXT record at
            _dmarc.<domain>
  - DKIM  — best-effort. DKIM keys live at <selector>._domainkey.<domain>
            but selectors are arbitrary; we try a handful of common ones.

The result includes the raw records, parsed fields where useful, and a
simple posture score so the UI can show "well-configured / partial /
absent" at a glance.
"""
from typing import Any, Optional

import dns.exception
import dns.resolver

from models import EnrichmentStatus, EnrichmentType
from .base import BaseEnricher, EnrichmentResult


PER_QUERY_TIMEOUT = 5.0

# Common DKIM selectors. This is best-effort — real DKIM enumeration
# requires the domain owner to tell you their selector.
COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim")


class EmailSecurityEnricher(BaseEnricher):
    enrichment_type = EnrichmentType.EMAIL_SECURITY
    timeout_seconds = 30.0

    def enrich(self, domain_name: str) -> EnrichmentResult:
        resolver = dns.resolver.Resolver()
        resolver.timeout = PER_QUERY_TIMEOUT
        resolver.lifetime = PER_QUERY_TIMEOUT

        spf = self._fetch_spf(resolver, domain_name)
        dmarc = self._fetch_dmarc(resolver, domain_name)
        dkim = self._fetch_dkim(resolver, domain_name)

        posture = self._score_posture(spf, dmarc, dkim)

        return EnrichmentResult(
            enrichment_type=self.enrichment_type,
            status=EnrichmentStatus.OK,
            data={
                "spf": spf,
                "dmarc": dmarc,
                "dkim": dkim,
                "posture": posture,
            },
        )

    # ------------------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------------------
    def _fetch_spf(self, resolver: dns.resolver.Resolver, domain: str) -> dict[str, Any]:
        """SPF lives in a TXT record at the domain root, starting with 'v=spf1'."""
        record = self._first_txt_matching(resolver, domain, prefix="v=spf1")
        if record is None:
            return {"present": False, "raw": None}

        return {
            "present": True,
            "raw": record,
            "parsed": self._parse_spf(record),
        }

    @staticmethod
    def _parse_spf(record: str) -> dict[str, Any]:
        """Pull out the parts of an SPF record that matter most."""
        parts = record.split()
        # The all-mechanism (e.g. -all, ~all, ?all, +all) is the catch-all
        # at the end. -all is strict reject, ~all is softfail, ?all is neutral.
        all_token: Optional[str] = None
        includes: list[str] = []
        ip4: list[str] = []
        ip6: list[str] = []

        for p in parts:
            if p in ("-all", "~all", "?all", "+all"):
                all_token = p
            elif p.startswith("include:"):
                includes.append(p.removeprefix("include:"))
            elif p.startswith("ip4:"):
                ip4.append(p.removeprefix("ip4:"))
            elif p.startswith("ip6:"):
                ip6.append(p.removeprefix("ip6:"))

        return {
            "all": all_token,
            "includes": includes,
            "ip4": ip4,
            "ip6": ip6,
        }

    # ------------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------------
    def _fetch_dmarc(self, resolver: dns.resolver.Resolver, domain: str) -> dict[str, Any]:
        """DMARC lives at _dmarc.<domain> as a TXT record starting with 'v=DMARC1'."""
        record = self._first_txt_matching(resolver, f"_dmarc.{domain}", prefix="v=DMARC1")
        if record is None:
            return {"present": False, "raw": None}

        return {
            "present": True,
            "raw": record,
            "parsed": self._parse_dmarc(record),
        }

    @staticmethod
    def _parse_dmarc(record: str) -> dict[str, Any]:
        """Pull out the policy and reporting fields from a DMARC record."""
        # DMARC fields are 'tag=value' separated by ';'
        fields: dict[str, str] = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                fields[k.strip()] = v.strip()

        return {
            "policy": fields.get("p"),                 # none / quarantine / reject
            "subdomain_policy": fields.get("sp"),
            "percent": fields.get("pct"),
            "rua": fields.get("rua"),                  # aggregate-report destinations
            "ruf": fields.get("ruf"),                  # forensic-report destinations
            "alignment_spf": fields.get("aspf"),
            "alignment_dkim": fields.get("adkim"),
        }

    # ------------------------------------------------------------------------
    # DKIM (best-effort)
    # ------------------------------------------------------------------------
    def _fetch_dkim(self, resolver: dns.resolver.Resolver, domain: str) -> dict[str, Any]:
        """
        Try a small set of commonly-used DKIM selectors. If one resolves
        and looks DKIM-shaped (contains 'v=DKIM1'), record it as present.
        We don't enumerate exhaustively — that's not possible without the
        domain owner naming their selectors.
        """
        found: list[dict[str, str]] = []

        for selector in COMMON_DKIM_SELECTORS:
            record = self._first_txt_matching(
                resolver,
                f"{selector}._domainkey.{domain}",
                prefix="v=DKIM1",
            )
            if record is not None:
                found.append({"selector": selector, "raw": record})

        return {
            "present": len(found) > 0,
            "selectors_found": [f["selector"] for f in found],
            "raw_records": found,
            "selectors_checked": list(COMMON_DKIM_SELECTORS),
        }

    # ------------------------------------------------------------------------
    # Posture score
    # ------------------------------------------------------------------------
    @staticmethod
    def _score_posture(
        spf: dict[str, Any],
        dmarc: dict[str, Any],
        dkim: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Simple, transparent scoring. Higher is better, max 100.

          SPF:   present (20) + strict -all (15)        = up to 35
          DMARC: present (20) + p=reject (15) + p=quarantine (10) + rua (5) = up to 40
          DKIM:  any selector found (25)                = up to 25
        """
        score = 0
        notes: list[str] = []

        if spf.get("present"):
            score += 20
            all_token = spf.get("parsed", {}).get("all")
            if all_token == "-all":
                score += 15
                notes.append("SPF strict (-all)")
            elif all_token == "~all":
                notes.append("SPF softfail (~all) — not strict")
            elif all_token == "?all":
                notes.append("SPF neutral (?all) — almost no protection")
        else:
            notes.append("SPF absent — domain is impersonable for email spoofing")

        if dmarc.get("present"):
            score += 20
            policy = dmarc.get("parsed", {}).get("policy")
            if policy == "reject":
                score += 15
                notes.append("DMARC p=reject")
            elif policy == "quarantine":
                score += 10
                notes.append("DMARC p=quarantine")
            elif policy == "none":
                notes.append("DMARC p=none — monitoring only, no enforcement")
            if dmarc.get("parsed", {}).get("rua"):
                score += 5
        else:
            notes.append("DMARC absent — no policy on what to do with spoofed mail")

        if dkim.get("present"):
            score += 25
        else:
            notes.append(
                "No DKIM keys at common selectors "
                "(may still exist at a custom selector)"
            )

        if score >= 75:
            tier = "strong"
        elif score >= 40:
            tier = "partial"
        else:
            tier = "weak"

        return {"score": score, "tier": tier, "notes": notes}

    # ------------------------------------------------------------------------
    # Shared TXT helper
    # ------------------------------------------------------------------------
    @staticmethod
    def _first_txt_matching(
        resolver: dns.resolver.Resolver,
        name: str,
        prefix: str,
    ) -> Optional[str]:
        """
        Return the first TXT record at `name` whose joined text starts with
        `prefix` (case-insensitive). Returns None on NXDOMAIN, NoAnswer,
        timeout, or no match.
        """
        try:
            answers = resolver.resolve(name, "TXT")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
            Exception,
        ):
            return None

        prefix_lower = prefix.lower()
        for rdata in answers:
            joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if joined.lower().startswith(prefix_lower):
                return joined
        return None
