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

  /** Tabler icon name (without the `ti-` prefix). Outline only. */
  icon: string;

  /** Whether this capability currently ships. False = render greyed out. */
  ready: boolean;
}

export const CAPABILITIES: Capability[] = [
  {
    id: 'dns_intelligence',
    label: 'dns_intelligence',
    icon: 'affiliate',
    ready: true,
  },
  {
    id: 'whois_correlation',
    label: 'whois_correlation',
    icon: 'id',
    ready: true,
  },
  {
    id: 'cert_transparency',
    label: 'cert_transparency',
    icon: 'certificate',
    ready: true,
  },
  {
    id: 'typosquat_detection',
    label: 'typosquat_detection',
    icon: 'copy',
    ready: true,
  },
  {
    id: 'threat_feed_correlation',
    label: 'threat_feed_correlation',
    icon: 'radar-2',
    ready: true,
  },
];
