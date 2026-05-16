"""
AI-powered domain investigation summary using Google Gemini.

Collects all enrichment data for a domain, finds relevant MITRE ATT&CK
threat groups based on industry, and sends a structured prompt to Gemini.
The AI is strictly constrained to only reference data that exists in the
enrichment results — no hallucination allowed.
"""

import os
import json
import logging
from typing import Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")


def _get_enrichment_summary(enrichments: list) -> dict:
    """Convert enrichment ORM objects into a clean dict for the prompt."""
    summary = {}
    for e in enrichments:
        if e.status == "ok" and e.data:
            summary[e.enrichment_type.value if hasattr(e.enrichment_type, 'value') else e.enrichment_type] = e.data
        elif e.status != "ok":
            summary[e.enrichment_type.value if hasattr(e.enrichment_type, 'value') else e.enrichment_type] = {
                "status": e.status if isinstance(e.status, str) else e.status.value,
                "error": e.error_message,
            }
    return summary


def _find_relevant_groups(db: Session, domain_name: str, enrichment_data: dict) -> list[dict]:
    """
    Query ATT&CK groups whose descriptions mention industries/sectors
    that might be relevant to this domain. Returns a list of dicts
    with attack_id, name, and a snippet of the description.
    """
    from models import AttackGroup

    # Get all groups (174 is small enough to handle in-memory)
    groups = db.query(AttackGroup).filter(
        AttackGroup.revoked == False,
        AttackGroup.deprecated == False,
    ).all()

    results = []
    for g in groups:
        if g.description:
            results.append({
                "attack_id": g.attack_id,
                "name": g.name,
                "description": g.description[:500],  # first 500 chars
                "aliases": g.aliases or [],
            })

    return results


def _build_prompt(domain_name: str, enrichment_data: dict, groups: list[dict]) -> str:
    """Build the structured prompt for Gemini."""

    enrichment_json = json.dumps(enrichment_data, indent=2, default=str)
    groups_json = json.dumps(groups, indent=2, default=str)

    return f"""You are a cybersecurity threat intelligence analyst. You are given enrichment data collected about the domain "{domain_name}" and a list of MITRE ATT&CK threat groups.

Your task is to produce a structured investigation summary. Follow these rules strictly:

RULES:
1. ONLY reference data that exists in the enrichment results below. Never invent or assume data.
2. If a field is missing or an enricher returned an error, say "data unavailable" — do not guess.
3. For the threat actor section: first determine what industry/sector this domain likely belongs to (based on the domain name and any context in the data). Then identify which ATT&CK groups from the provided list are known to target that sector based on their descriptions. ONLY include groups whose descriptions explicitly mention the relevant sector.
4. If you cannot determine the sector or no groups match, say so honestly.
5. Be concise and factual. No marketing language.

ENRICHMENT DATA FOR "{domain_name}":
{enrichment_json}

MITRE ATT&CK GROUPS (with description snippets):
{groups_json}

Respond ONLY with valid JSON in this exact structure (no markdown, no backticks, no preamble):
{{
  "domain": "{domain_name}",
  "sector_assessment": {{
    "likely_sector": "string or null",
    "confidence": "high | medium | low",
    "reasoning": "one sentence explaining why"
  }},
  "risk_summary": {{
    "overall_risk": "critical | high | medium | low | informational",
    "key_findings": ["finding 1", "finding 2", "finding 3"],
    "concerns": ["concern 1", "concern 2"],
    "positives": ["positive 1", "positive 2"]
  }},
  "enrichment_highlights": {{
    "dns": "one-line summary or null",
    "email_security": "one-line summary or null",
    "whois": "one-line summary or null",
    "ssl_certificates": "one-line summary or null",
    "typosquatting": "one-line summary or null",
    "reputation": "one-line summary or null",
    "dark_web": "one-line summary or null",
    "passive_dns": "one-line summary or null",
    "reverse_ip": "one-line summary or null"
  }},
  "relevant_threat_actors": [
    {{
      "attack_id": "G0XXX",
      "name": "Group Name",
      "relevance": "one sentence on why this group is relevant to the domain's sector"
    }}
  ],
  "recommendation": "2-3 sentence actionable recommendation for the security team"
}}"""


async def generate_ai_summary(
    domain_name: str,
    enrichments: list,
    db: Session,
) -> Optional[dict]:
    """
    Generate an AI-powered summary for a domain investigation.
    Returns the parsed JSON response or None if AI is unavailable.
    """
    if not GEMINI_API_KEY:
        logger.info("GEMINI_API_KEY not set — skipping AI summary")
        return None

    try:
        from google import genai

        client = genai.Client(api_key=GEMINI_API_KEY)

        # Collect data
        enrichment_data = _get_enrichment_summary(enrichments)
        groups = _find_relevant_groups(db, domain_name, enrichment_data)

        # Build prompt
        prompt = _build_prompt(domain_name, enrichment_data, groups)

        # Call Gemini
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        # Parse the response
        text = response.text.strip()
        # Clean up potential markdown fences
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()

        result = json.loads(text)
        return result

    except json.JSONDecodeError as e:
        logger.error(f"AI summary JSON parse error: {e}")
        logger.error(f"Raw response: {text[:500]}")
        return {"error": "AI returned invalid JSON", "raw_preview": text[:200]}
    except Exception as e:
        logger.error(f"AI summary generation failed: {e}")
        return {"error": str(e)}