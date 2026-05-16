/**
 * MetricGrid.tsx
 *
 * The 4-cell metric summary on the investigation page.
 *
 *   ┌─ Age ──────────┐  ┌─ Email Posture ┐
 *   └────────────────┘  └────────────────┘
 *   ┌─ Reputation ───┐  ┌─ Typosquats ───┐
 *   └────────────────┘  └────────────────┘
 *
 * 2x2 on desktop, stacks vertically on narrow screens.
 * Each cell's status color is derived from the underlying data.
 */

import React from 'react';
import { MetricCell, type CellStatus } from './MetricCell';
import type {
  Domain,
  Enrichment,
  WhoisData,
  EmailSecurityData,
  VirusTotalData,
  AbuseIPDBData,
  TypoSquatData,
} from '@/lib/api';

interface MetricGridProps {
  domain: Domain;
}

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

// ----------------------------------------------------------------------------
// Cell value+status derivation
// ----------------------------------------------------------------------------

function ageCell(whois: WhoisData | null): {
  value: string;
  subtext: string;
  status: CellStatus;
} {
  if (!whois) {
    return { value: '—', subtext: 'WHOIS not run', status: 'neutral' };
  }
  const days = daysSince(whois.creation_date);
  if (days === null) {
    return {
      value: '—',
      subtext: 'No creation date',
      status: 'neutral',
    };
  }
  let status: CellStatus = 'clean';
  if (days < 30) status = 'investigate';
  else if (days < 180) status = 'mixed';

  const years = Math.floor(days / 365);
  const subtext = years >= 1 ? `~${years} year${years === 1 ? '' : 's'} old` : `Registered recently`;
  return { value: `${days.toLocaleString()} days`, subtext, status };
}

function emailCell(email: EmailSecurityData | null): {
  value: string;
  subtext: string;
  status: CellStatus;
} {
  if (!email) {
    return { value: '—', subtext: 'Not checked', status: 'neutral' };
  }
  const parts: string[] = [];
  if (email.spf.present) parts.push('SPF');
  if (email.dmarc.present) parts.push('DMARC');
  if (email.dkim.present) parts.push('DKIM');

  const tier = email.posture.tier;
  const status: CellStatus =
    tier === 'strong' ? 'clean' : tier === 'partial' ? 'mixed' : 'investigate';

  const label =
    tier === 'strong' ? 'Strong' : tier === 'partial' ? 'Partial' : 'Weak';
  const subtext = parts.length === 0 ? 'None configured' : parts.join(' + ');

  return { value: label, subtext, status };
}

function reputationCell(
  vt: VirusTotalData | null,
  abuse: AbuseIPDBData | null
): { value: string; subtext: string; status: CellStatus } {
  if (!vt && !abuse) {
    return { value: '—', subtext: 'No reputation data', status: 'neutral' };
  }

  // Worst signal wins
  if (vt?.verdict === 'malicious' || abuse?.threat_level === 'high') {
    const subtext = vt
      ? `${vt.analysis_stats.malicious}/${vt.analysis_stats.total} engines flag`
      : `AbuseIPDB ${abuse?.abuse_confidence_score}% confidence`;
    return { value: 'Malicious', subtext, status: 'investigate' };
  }
  if (vt?.verdict === 'suspicious' || abuse?.threat_level === 'medium') {
    return {
      value: 'Suspicious',
      subtext: vt ? `${vt.analysis_stats.suspicious} engines flag` : 'AbuseIPDB medium',
      status: 'mixed',
    };
  }
  if (vt && vt.verdict === 'clean') {
    return {
      value: 'Clean',
      subtext: `0/${vt.analysis_stats.total} engines flag`,
      status: 'clean',
    };
  }
  return { value: 'Unknown', subtext: 'Mixed signals', status: 'neutral' };
}

function typosquatCell(typo: TypoSquatData | null): {
  value: string;
  subtext: string;
  status: CellStatus;
} {
  if (!typo) {
    return { value: '—', subtext: 'Not scanned', status: 'neutral' };
  }
  const status: CellStatus =
    typo.alive_count >= 3 ? 'investigate' : typo.alive_count >= 1 ? 'mixed' : 'clean';

  return {
    value: `${typo.alive_count} live`,
    subtext: `${typo.permutations_attempted.toLocaleString()} permutations scanned`,
    status,
  };
}

// ----------------------------------------------------------------------------
// Component
// ----------------------------------------------------------------------------

export const MetricGrid: React.FC<MetricGridProps> = ({ domain }) => {
  const whois = findEnrichment<WhoisData>(domain.enrichments, 'whois');
  const email = findEnrichment<EmailSecurityData>(
    domain.enrichments,
    'email_security'
  );
  const vt = findEnrichment<VirusTotalData>(domain.enrichments, 'virustotal');
  const abuse = findEnrichment<AbuseIPDBData>(domain.enrichments, 'abuseipdb');
  const typo = findEnrichment<TypoSquatData>(domain.enrichments, 'typosquat');

  const age = ageCell(whois);
  const eml = emailCell(email);
  const rep = reputationCell(vt, abuse);
  const typ = typosquatCell(typo);

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '12px',
        marginBottom: '24px',
      }}
    >
      <MetricCell label="Age" {...age} />
      <MetricCell label="Email Posture" {...eml} />
      <MetricCell label="Reputation" {...rep} />
      <MetricCell label="Typosquats" {...typ} />
    </div>
  );
};
