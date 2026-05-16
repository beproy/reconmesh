/**
 * summaryTemplate.ts
 *
 * Builds a 2-4 sentence factual summary of a domain from its enrichments.
 * Pure function — each rule reads structured data and emits one sentence
 * (or null if there's nothing to say).
 *
 * Session 22+ may replace the body of buildSummary() with model output,
 * but the return type (string[]) and the rendering component stay identical.
 */

import type {
  Domain,
  Enrichment,
  DnsData,
  WhoisData,
  EmailSecurityData,
  TypoSquatData,
  VirusTotalData,
  AbuseIPDBData,
  ShodanData,
  MnemonicPdnsData,
} from './api';

function findEnrichment<T>(
  enrichments: Enrichment[],
  type: string
): T | null {
  const e = enrichments.find((x) => x.enrichment_type === type);
  if (!e || e.status !== 'ok') return null;
  return e.data as T;
}

function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  const then = new Date(iso);
  if (isNaN(then.getTime())) return null;
  return Math.floor((Date.now() - then.getTime()) / (1000 * 60 * 60 * 24));
}

function formatNumber(n: number): string {
  return n.toLocaleString();
}

// ----------------------------------------------------------------------------
// Individual sentence rules
// ----------------------------------------------------------------------------

function ageSentence(whois: WhoisData | null): string | null {
  if (!whois) return null;
  const days = daysSince(whois.creation_date);
  if (days === null) return null;

  const registrar = whois.registrar ? ` to ${whois.registrar}` : '';

  if (days < 30) {
    return `Registered just ${days} days ago${registrar} — recently created domains are higher risk.`;
  }
  if (days < 365) {
    return `Registered ${days} days ago${registrar}.`;
  }
  const years = Math.floor(days / 365);
  return `Registered ${formatNumber(days)} days ago${registrar} (~${years} year${years === 1 ? '' : 's'}).`;
}

function hostingSentence(
  dns: DnsData | null,
  shodan: ShodanData | null
): string | null {
  if (!dns) return null;
  const aRecords = dns.records?.A || [];
  if (aRecords.length === 0) return null;

  const ipCount = aRecords.length;
  const ipPlural = ipCount === 1 ? 'IP' : 'IPs';

  // If Shodan has ASN/org info, use it for richer context
  if (shodan && shodan.org) {
    return `Resolves to ${ipCount} ${ipPlural}, hosted on ${shodan.org}${shodan.asn ? ` (${shodan.asn})` : ''}.`;
  }
  return `Resolves to ${ipCount} ${ipPlural}.`;
}

function emailSentence(email: EmailSecurityData | null): string | null {
  if (!email) return null;
  const parts: string[] = [];
  if (email.spf.present) parts.push('SPF');
  if (email.dmarc.present) parts.push('DMARC');
  if (email.dkim.present) parts.push('DKIM');

  if (parts.length === 0) {
    return `No SPF, DMARC, or DKIM records present — this domain cannot send authenticated email and may be spoofed.`;
  }
  if (parts.length === 3) {
    return `Strong email posture: SPF, DMARC, and DKIM all configured.`;
  }
  return `Partial email posture: only ${parts.join(' and ')} configured.`;
}

function reputationSentence(
  vt: VirusTotalData | null,
  abuse: AbuseIPDBData | null
): string | null {
  if (!vt && !abuse) return null;

  if (vt && vt.verdict === 'malicious') {
    const flagged = vt.analysis_stats.malicious;
    const total = vt.analysis_stats.total;
    return `Flagged malicious by ${flagged} of ${total} VirusTotal engines.`;
  }
  if (vt && vt.verdict === 'suspicious') {
    return `Flagged suspicious by ${vt.analysis_stats.suspicious} VirusTotal engines.`;
  }
  if (abuse && abuse.threat_level === 'high') {
    return `AbuseIPDB rates this domain's IP as high threat (${abuse.abuse_confidence_score}% confidence, ${abuse.total_reports} reports).`;
  }
  if (vt && vt.verdict === 'clean' && vt.analysis_stats.total > 0) {
    return `Clean across ${vt.analysis_stats.total} VirusTotal engines.`;
  }
  return null;
}

function typosquatSentence(typo: TypoSquatData | null): string | null {
  if (!typo) return null;
  if (typo.alive_count === 0) {
    return `None of ${formatNumber(typo.permutations_attempted)} typosquat permutations resolve to live infrastructure.`;
  }
  if (typo.alive_count === 1) {
    return `1 typosquat lookalike resolves to a live IP — worth a closer look.`;
  }
  return `${typo.alive_count} typosquat lookalikes resolve to live IPs.`;
}

function pdnsSentence(pdns: MnemonicPdnsData | null): string | null {
  if (!pdns || pdns.total_records === 0) return null;
  if (pdns.unique_answers > 50) {
    return `Heavy historical DNS activity: ${formatNumber(pdns.total_records)} records across ${pdns.unique_answers} unique answers.`;
  }
  return null; // Don't bother surfacing low-activity PDNS
}

// ----------------------------------------------------------------------------
// Main entry point
// ----------------------------------------------------------------------------

export function buildSummary(domain: Domain): string[] {
  const whois = findEnrichment<WhoisData>(domain.enrichments, 'whois');
  const dns = findEnrichment<DnsData>(domain.enrichments, 'dns');
  const email = findEnrichment<EmailSecurityData>(
    domain.enrichments,
    'email_security'
  );
  const typo = findEnrichment<TypoSquatData>(domain.enrichments, 'typosquat');
  const vt = findEnrichment<VirusTotalData>(domain.enrichments, 'virustotal');
  const abuse = findEnrichment<AbuseIPDBData>(domain.enrichments, 'abuseipdb');
  const shodan = findEnrichment<ShodanData>(domain.enrichments, 'shodan');
  const pdns = findEnrichment<MnemonicPdnsData>(
    domain.enrichments,
    'mnemonic_pdns'
  );

  // Order matters — sentences read top-to-bottom in this priority
  const sentences = [
    ageSentence(whois),
    hostingSentence(dns, shodan),
    emailSentence(email),
    reputationSentence(vt, abuse),
    typosquatSentence(typo),
    pdnsSentence(pdns),
  ];

  return sentences.filter((s): s is string => s !== null);
}
