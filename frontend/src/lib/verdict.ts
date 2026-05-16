/**
 * verdict.ts
 *
 * Computes a 3-state verdict for a domain based on its enrichments.
 * Pure function — no React, no side effects. Safe to unit test later.
 *
 * Used by:
 *   - VerdictPill (rendered in HeaderStrip)
 *   - MetricGrid (to flag individual cells)
 *
 * The rules are deliberately simple. Session 22+ may replace this with
 * a model-generated rationale, but the visual contract stays the same.
 */

import type {
  Domain,
  Enrichment,
  VirusTotalData,
  AbuseIPDBData,
  TypoSquatData,
  EmailSecurityData,
  WhoisData,
} from './api';

export type VerdictState = 'investigate' | 'mixed' | 'clean';

export interface Verdict {
  state: VerdictState;
  label: string;
  reasons: string[];
}

/**
 * Look up an enrichment by its `enrichment_type` string and return its
 * `.data` cast to the requested type. Returns null if not found or errored.
 */
function findEnrichment<T>(
  enrichments: Enrichment[],
  type: string
): T | null {
  const e = enrichments.find((x) => x.enrichment_type === type);
  if (!e) return null;
  if (e.status !== 'ok') return null;
  return e.data as T;
}

/**
 * Compute days between a date string and today. Returns null if unparseable.
 */
function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  const then = new Date(iso);
  if (isNaN(then.getTime())) return null;
  const ms = Date.now() - then.getTime();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

export function computeVerdict(domain: Domain): Verdict {
  const reasons: string[] = [];
  let investigateHits = 0;
  let mixedHits = 0;

  const vt = findEnrichment<VirusTotalData>(
    domain.enrichments,
    'virustotal'
  );
  const abuse = findEnrichment<AbuseIPDBData>(
    domain.enrichments,
    'abuseipdb'
  );
  const typo = findEnrichment<TypoSquatData>(
    domain.enrichments,
    'typosquat'
  );
  const email = findEnrichment<EmailSecurityData>(
    domain.enrichments,
    'email_security'
  );
  const whois = findEnrichment<WhoisData>(domain.enrichments, 'whois');

  // --- Strong "investigate" signals ---
  if (vt && vt.verdict === 'malicious') {
    investigateHits++;
    reasons.push('Flagged malicious on VirusTotal.');
  }
  if (abuse && abuse.threat_level === 'high') {
    investigateHits++;
    reasons.push(`AbuseIPDB threat level: high (${abuse.abuse_confidence_score}%).`);
  }
  if (typo && typo.alive_count >= 3) {
    investigateHits++;
    reasons.push(`${typo.alive_count} typosquats resolve to live IPs.`);
  }

  // Young domain + no SPF is a common phish signal
  const age = whois ? daysSince(whois.creation_date) : null;
  if (age !== null && age < 30 && email && !email.spf.present) {
    investigateHits++;
    reasons.push(`Registered ${age} days ago with no SPF record.`);
  }

  // --- Softer "mixed" signals ---
  if (vt && vt.verdict === 'suspicious') {
    mixedHits++;
    reasons.push('Flagged suspicious on VirusTotal.');
  }
  if (abuse && abuse.threat_level === 'medium') {
    mixedHits++;
    reasons.push('AbuseIPDB threat level: medium.');
  }
  if (typo && typo.alive_count >= 1 && typo.alive_count < 3) {
    mixedHits++;
    reasons.push(`${typo.alive_count} typosquat(s) resolve to live IPs.`);
  }
  if (email && (email.posture.tier === 'partial' || email.posture.tier === 'weak')) {
    mixedHits++;
    reasons.push(`Email posture: ${email.posture.tier}.`);
  }

  // --- Decide ---
  if (investigateHits > 0) {
    return {
      state: 'investigate',
      label: 'Worth investigating',
      reasons,
    };
  }
  if (mixedHits > 0) {
    return {
      state: 'mixed',
      label: 'Mixed signals',
      reasons,
    };
  }
  return {
    state: 'clean',
    label: 'Looks clean',
    reasons: ['No malicious signals detected across enabled enrichers.'],
  };
}
