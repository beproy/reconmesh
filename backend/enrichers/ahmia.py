"""
Ahmia dark web mention enricher (v2).

Queries the Ahmia clearnet search (https://ahmia.fi/search/) to find
references to a given domain's apex label on indexed .onion services.

Ahmia is a filtered Tor search engine — results are clearnet metadata
(onion URL, title, snippet, last-seen date), no Tor proxy required.

Two-step request flow (required as of 2026):
  1. GET https://ahmia.fi/search/ to harvest an anti-bot token. Ahmia
     embeds a hidden input with a randomized field name + value that
     rotates each page-load. Submitting a search without the matching
     token returns the landing page instead of results.
  2. GET https://ahmia.fi/search/?q={apex}&{token_field}={token_value}
     for the actual search.

Query strategy: apex label only (e.g. "paypal" for paypal.com) — catches
more mentions than the full FQDN at the cost of some false positives.

Caps: 25 mentions stored, deduplicated by onion *host* (so multiple
product pages on the same dark-web site count once). 30s HTTP timeout
applied to each of the two requests.

Failure modes handled:
  - ConnectTimeout / ReadTimeout      -> EnrichmentStatus.TIMEOUT
  - ConnectError (refused)            -> EnrichmentStatus.ERROR
  - RemoteProtocolError (server drop) -> EnrichmentStatus.ERROR
  - 5xx response                      -> EnrichmentStatus.ERROR
  - Missing token on homepage         -> EnrichmentStatus.ERROR
  - 200 with zero hits                -> EnrichmentStatus.NOT_FOUND
  - 200 with hits                     -> EnrichmentStatus.OK
"""
from __future__ import annotations

import re
from html import unescape
from urllib.parse import urlparse

import httpx
import tldextract

from enrichers.base import BaseEnricher, EnrichmentResult
from models import EnrichmentStatus, EnrichmentType


AHMIA_SEARCH_URL = "https://ahmia.fi/search/"
HTTP_TIMEOUT_SECONDS = 30
MAX_RESULTS = 25
# Mimic a real browser. Ahmia treats default httpx UA as suspicious.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Regex for harvesting the anti-bot token from the homepage form.
# Ahmia ships ONE hidden input per form; the field name and value are
# both randomized hex strings that rotate per page-load.
TOKEN_RE = re.compile(
    r'<input\s+type="hidden"\s+name="([^"]+)"\s+value="([^"]+)"',
    re.IGNORECASE,
)

# Each result is rendered as <li class="result"> ... </li>.
RESULT_BLOCK_RE = re.compile(
    r'<li[^>]*class="result"[^>]*>(.*?)</li>',
    re.DOTALL | re.IGNORECASE,
)

# Inside a result block:
#   <h4><a href="/search/redirect?search_term=...&redirect_url={ONION_URL}">{TITLE}</a></h4>
#   <p>{SNIPPET}</p>
#   <cite>{ONION_HOST}</cite>
#   <span class="lastSeen" data-timestamp="{ISO-ISH DATE}">...</span>
ONION_URL_RE = re.compile(r'redirect_url=([^"\s]+)', re.IGNORECASE)
TITLE_RE = re.compile(r"<h4[^>]*>\s*<a[^>]*>(.*?)</a>", re.DOTALL | re.IGNORECASE)
SNIPPET_RE = re.compile(r"<p[^>]*>(.*?)</p>", re.DOTALL | re.IGNORECASE)
CITE_RE = re.compile(r"<cite[^>]*>(.*?)</cite>", re.DOTALL | re.IGNORECASE)
TIMESTAMP_RE = re.compile(
    r'class="lastSeen"\s+data-timestamp="([^"]+)"',
    re.IGNORECASE,
)
TAG_STRIP_RE = re.compile(r"<[^>]+>")


def _clean(text: str) -> str:
    """Strip HTML tags + decode entities + collapse whitespace."""
    text = TAG_STRIP_RE.sub("", text)
    text = unescape(text)
    return " ".join(text.split())


def _apex_label(domain_name: str) -> str:
    """
    'paypal.com' -> 'paypal'
    'mail.google.co.uk' -> 'google'
    Uses tldextract (already a project dependency) for PSL handling.
    """
    extracted = tldextract.extract(domain_name)
    return extracted.domain.lower()


def _onion_host(onion_url: str) -> str:
    """Extract just the .onion hostname from a full URL, e.g.
    'http://abc123.onion/product/4' -> 'abc123.onion'.
    Used for dedup so multiple pages on the same dark-web site
    count as one mention."""
    try:
        return urlparse(onion_url).hostname or onion_url
    except Exception:
        return onion_url


def _parse_results(html: str) -> list[dict]:
    """Pull structured records out of Ahmia's HTML result list,
    deduplicating by onion host."""
    seen_hosts: set[str] = set()
    mentions: list[dict] = []

    for block_match in RESULT_BLOCK_RE.finditer(html):
        if len(mentions) >= MAX_RESULTS:
            break
        block = block_match.group(1)

        onion_match = ONION_URL_RE.search(block)
        if not onion_match:
            continue

        onion_url = unescape(onion_match.group(1)).strip()
        host = _onion_host(onion_url)
        if host in seen_hosts:
            continue
        seen_hosts.add(host)

        title_match = TITLE_RE.search(block)
        snippet_match = SNIPPET_RE.search(block)
        cite_match = CITE_RE.search(block)
        timestamp_match = TIMESTAMP_RE.search(block)

        mentions.append({
            "onion_url": onion_url,
            "onion_host": host,
            "title": _clean(title_match.group(1)) if title_match else "",
            "snippet": _clean(snippet_match.group(1)) if snippet_match else "",
            "cite": _clean(cite_match.group(1)) if cite_match else host,
            "last_seen": timestamp_match.group(1).strip() if timestamp_match else "",
        })

    return mentions


class AhmiaEnricher(BaseEnricher):
    """Dark-web-mention check via Ahmia's clearnet search."""

    enrichment_type = EnrichmentType.AHMIA
    timeout_seconds = HTTP_TIMEOUT_SECONDS

    def enrich(self, domain_name: str) -> EnrichmentResult:
        apex = _apex_label(domain_name)
        if not apex:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.AHMIA,
                status=EnrichmentStatus.ERROR,
                data={"query": domain_name},
                error_message=f"Could not extract apex label from '{domain_name}'",
            )

        try:
            with httpx.Client(
                timeout=HTTP_TIMEOUT_SECONDS,
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
            ) as client:
                # Step 1: fetch homepage and harvest the rotating anti-bot token.
                home = client.get(AHMIA_SEARCH_URL)
                if home.status_code != 200:
                    return EnrichmentResult(
                        enrichment_type=EnrichmentType.AHMIA,
                        status=EnrichmentStatus.ERROR,
                        data={"query": apex, "http_status": home.status_code},
                        error_message=(
                            f"Ahmia homepage returned HTTP {home.status_code}"
                        ),
                    )

                token_match = TOKEN_RE.search(home.text)
                if not token_match:
                    return EnrichmentResult(
                        enrichment_type=EnrichmentType.AHMIA,
                        status=EnrichmentStatus.ERROR,
                        data={"query": apex},
                        error_message=(
                            "Could not extract anti-bot token from Ahmia "
                            "homepage. The page structure may have changed."
                        ),
                    )

                token_field = token_match.group(1)
                token_value = token_match.group(2)

                # Step 2: actual search with token attached.
                params = {"q": apex, token_field: token_value}
                response = client.get(AHMIA_SEARCH_URL, params=params)

        except httpx.TimeoutException:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.AHMIA,
                status=EnrichmentStatus.TIMEOUT,
                data={"query": apex},
                error_message=f"Ahmia request timed out after {HTTP_TIMEOUT_SECONDS}s",
            )
        except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.AHMIA,
                status=EnrichmentStatus.ERROR,
                data={"query": apex},
                error_message=f"Ahmia upstream unavailable: {type(exc).__name__}: {exc}",
            )
        except httpx.HTTPError as exc:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.AHMIA,
                status=EnrichmentStatus.ERROR,
                data={"query": apex},
                error_message=f"Ahmia HTTP error: {type(exc).__name__}: {exc}",
            )

        if response.status_code != 200:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.AHMIA,
                status=EnrichmentStatus.ERROR,
                data={"query": apex, "http_status": response.status_code},
                error_message=f"Ahmia search returned HTTP {response.status_code}",
            )

        # Count total raw results (before dedup) for context, then parse.
        raw_count = len(RESULT_BLOCK_RE.findall(response.text))
        mentions = _parse_results(response.text)

        if not mentions:
            return EnrichmentResult(
                enrichment_type=EnrichmentType.AHMIA,
                status=EnrichmentStatus.NOT_FOUND,
                data={
                    "query": apex,
                    "mention_count": 0,
                    "unique_sites": 0,
                    "raw_result_count": raw_count,
                    "mentions": [],
                    "note": (
                        f"Ahmia returned no indexed onion services mentioning "
                        f"'{apex}'. Note: Ahmia filters certain query terms by "
                        "policy — an empty result is not proof of absence."
                    ),
                },
            )

        return EnrichmentResult(
            enrichment_type=EnrichmentType.AHMIA,
            status=EnrichmentStatus.OK,
            data={
                "query": apex,
                "mention_count": len(mentions),
                "unique_sites": len(mentions),
                "raw_result_count": raw_count,
                "mentions": mentions,
                "source_url": f"{AHMIA_SEARCH_URL}?q={apex}",
                "note": (
                    f"Found {raw_count} raw results across "
                    f"{len(mentions)} distinct onion site(s) "
                    f"(capped at {MAX_RESULTS})."
                ),
            },
        )
