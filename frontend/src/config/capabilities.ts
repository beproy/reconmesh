/**
 * ReconMesh platform capabilities.
 *
 * Rendered as a horizontal manifest strip below the search hero.
 * Lowercase + underscore styling is intentional — reads as a system manifest,
 * not as marketing feature cards.
 *
 * Add entries here as new enrichers ship. Order matters: this is the
 * order they'll appear left-to-right in the strip.
 */

export interface Capability {
  /** Stable id, used for React keys and future routing */
  id: string;

  /** Display label — lowercase, snake_case, mono-rendered */
  label: string;

  /** Short human-readable description */
  description: string;

  /** Tabler icon name (without the `ti-` prefix). Outline only. */
  icon: string;

  /** Whether this capability currently ships. False = render greyed out. */
  ready: boolean;
}

export const CAPABILITIES: Capability[] = [
  {
    id: 'dns_intelligence',
    label: 'dns_intelligence',
    description: 'A, AAAA, MX, TXT records plus SPF, DKIM and DMARC validation.',
    icon: 'affiliate',
    ready: true,
  },
  {
    id: 'whois_correlation',
    label: 'whois_correlation',
    description: 'Registrar, creation date, expiry and registrant details.',
    icon: 'id',
    ready: true,
  },
  {
    id: 'cert_transparency',
    label: 'cert_transparency',
    description: 'Subdomain discovery via public certificate transparency logs.',
    icon: 'certificate',
    ready: true,
  },
  {
    id: 'typosquat_detection',
    label: 'typosquat_detection',
    description: 'Permutation fuzzing to find lookalike domains with live A-records.',
    icon: 'copy',
    ready: true,
  },
  {
    id: 'threat_feed_correlation',
    label: 'threat_feed_correlation',
    description: 'Cross-reference against URLhaus, OTX, ThreatFox and ransomware leak feeds.',
    icon: 'radar-2',
    ready: true,
  },
  {
    id: 'dark_web_monitoring',
    label: 'dark_web_monitoring',
    description: 'Search Tor hidden services for mentions of a domain via Ahmia.',
    icon: 'eye-off',
    ready: true,
  },
  {
    id: 'ai_threat_summary',
    label: 'ai_threat_summary',
    description: 'AI-powered investigation summaries with sector-aware threat actor mapping.',
    icon: 'brain',
    ready: true,
  },
];