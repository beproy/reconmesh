"""
Typo-squat enricher — find live lookalike domains.

Uses dnstwist to generate permutations (homoglyph, bitsquat, insertion,
hyphenation, etc.) and dnspython to resolve each one's A records. We
record only the permutations that resolve, since dead lookalikes are
noise. Aggregate counts (generated, attempted, alive) are kept so the
user can judge how exhaustive the scan was.

Design choices made for v1:
  - 250 permutation cap, taken in dnstwist's natural order. We do NOT
    filter by fuzzer type; users can see the `fuzzer` field in the UI
    and judge each lookalike themselves.
  - A-records ONLY. No banner grabbing, no MX probing, no SMTP, no SSL
    cert fetching, no fuzzy-hash comparison. Brand-protection workflows
    that need deeper analysis can search the lookalike directly in
    ReconMesh and run the full enricher suite on it.
  - Concurrent resolution via ThreadPoolExecutor — 20 workers, 3s per
    lookup, total budget capped at 75s. Celery's hard kill at 60s would
    cut us off if we let the resolver hang on flaky DNS, so we own the
    deadline ourselves.
  - The original domain is excluded from the permutation set (dnstwist
    emits it as fuzzer='*original' — not an attack).
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

import dns.exception
import dns.resolver
from dnstwist import Fuzzer

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


log = logging.getLogger(__name__)


# Tunables. Kept as module constants so they're easy to find/adjust later
# without digging through method bodies.
PERMUTATION_CAP = 250
DNS_TIMEOUT_SECONDS = 3.0
DNS_LIFETIME_SECONDS = 3.0
THREAD_POOL_WORKERS = 20
TOTAL_BUDGET_SECONDS = 75.0  # leaves headroom under Celery's 60s soft / 90s hard


@dataclass
class _ResolveOutcome:
    """Per-permutation resolution result, kept tight for clarity."""
    domain: str
    fuzzer: str
    alive: bool
    a_records: list[str]


class TypoSquatEnricher(BaseEnricher):
    """Enricher that finds live typo-squat lookalikes for a domain."""

    enrichment_type = EnrichmentType.TYPO_SQUAT

    # ------------------------------------------------------------------
    # Permutation generation (cheap, in-process)
    # ------------------------------------------------------------------
    def _generate_permutations(self, domain: str) -> list[dict]:
        """
        Use dnstwist to generate lookalike permutations. Excludes the
        original domain itself. Returns at most PERMUTATION_CAP entries
        in dnstwist's natural order.
        """
        fuzzer = Fuzzer(domain)
        fuzzer.generate()
        all_perms = fuzzer.permutations()

        filtered = [
            p for p in all_perms
            if p.get("fuzzer") != "*original" and p.get("domain")
        ]
        return filtered[:PERMUTATION_CAP]

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------
    def _make_resolver(self) -> dns.resolver.Resolver:
        """One resolver per task — thread-safe to share across the pool."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT_SECONDS
        resolver.lifetime = DNS_LIFETIME_SECONDS
        return resolver

    def _resolve_one(
        self,
        resolver: dns.resolver.Resolver,
        permutation: dict,
    ) -> _ResolveOutcome:
        """
        Resolve A records for a single permutation. Any failure (NXDOMAIN,
        timeout, no answer, DNS error) is treated as 'not alive' — for
        typo-squat purposes we don't care WHY it didn't resolve.
        """
        domain = permutation["domain"]
        fuzzer = permutation["fuzzer"]

        try:
            answer = resolver.resolve(domain, "A")
            ips = sorted({rdata.address for rdata in answer})
            return _ResolveOutcome(
                domain=domain,
                fuzzer=fuzzer,
                alive=True,
                a_records=ips,
            )
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return _ResolveOutcome(
                domain=domain,
                fuzzer=fuzzer,
                alive=False,
                a_records=[],
            )
        except Exception as exc:
            # Belt-and-suspenders. Truly unexpected error — log it but
            # don't fail the whole task; this one permutation just
            # counts as not-alive.
            log.warning(
                "typo_squat: unexpected error resolving %s: %s",
                domain, exc,
            )
            return _ResolveOutcome(
                domain=domain,
                fuzzer=fuzzer,
                alive=False,
                a_records=[],
            )

    def _resolve_concurrent(
        self,
        permutations: list[dict],
        deadline: float,
    ) -> tuple[list[_ResolveOutcome], int]:
        """
        Resolve all permutations concurrently. Returns (outcomes, attempted).
        `attempted` may be less than len(permutations) if we hit the deadline.
        """
        resolver = self._make_resolver()
        outcomes: list[_ResolveOutcome] = []
        attempted = 0

        with ThreadPoolExecutor(max_workers=THREAD_POOL_WORKERS) as pool:
            futures = {
                pool.submit(self._resolve_one, resolver, perm): perm
                for perm in permutations
            }

            for future in as_completed(futures):
                if time.monotonic() >= deadline:
                    # Stop pulling results; outstanding futures will be
                    # cancelled when the executor exits.
                    log.info(
                        "typo_squat: deadline reached after %d/%d resolutions",
                        attempted, len(permutations),
                    )
                    break
                try:
                    outcomes.append(future.result(timeout=0.1))
                    attempted += 1
                except Exception as exc:
                    log.warning("typo_squat: future failed: %s", exc)
                    attempted += 1

        return outcomes, attempted

    # ------------------------------------------------------------------
    # BaseEnricher contract
    # ------------------------------------------------------------------
    def enrich(self, domain_name: str) -> EnrichmentResult:
        """
        Generate permutations, resolve each in parallel, return the alive
        ones. Always returns OK even if zero lookalikes are alive — that's
        a meaningful finding ("no live lookalikes for this domain"),
        not an error.
        """
        try:
            permutations = self._generate_permutations(domain_name)
        except Exception as exc:
            log.exception("typo_squat: failed to generate permutations")
            return EnrichmentResult(
                enrichment_type=EnrichmentType.TYPO_SQUAT,
                status=EnrichmentStatus.ERROR,
                data={},
                error_message=f"dnstwist generation failed: {exc}",
            )

        if not permutations:
            # Vanishingly unlikely, but be explicit. dnstwist always
            # produces something for valid domains.
            return EnrichmentResult(
                enrichment_type=EnrichmentType.TYPO_SQUAT,
                status=EnrichmentStatus.OK,
                data={
                    "permutations_generated": 0,
                    "permutations_attempted": 0,
                    "alive_count": 0,
                    "alive": [],
                    "cap_applied": PERMUTATION_CAP,
                    "budget_seconds": TOTAL_BUDGET_SECONDS,
                },
            )

        deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
        outcomes, attempted = self._resolve_concurrent(permutations, deadline)

        alive = [
            {
                "domain": o.domain,
                "fuzzer": o.fuzzer,
                "a_records": o.a_records,
            }
            for o in outcomes
            if o.alive
        ]
        # Sort alive results by domain name for deterministic UI rendering.
        alive.sort(key=lambda x: x["domain"])

        return EnrichmentResult(
            enrichment_type=EnrichmentType.TYPO_SQUAT,
            status=EnrichmentStatus.OK,
            data={
                "permutations_generated": len(permutations),
                "permutations_attempted": attempted,
                "alive_count": len(alive),
                "alive": alive,
                "cap_applied": PERMUTATION_CAP,
                "budget_seconds": TOTAL_BUDGET_SECONDS,
            },
        )
