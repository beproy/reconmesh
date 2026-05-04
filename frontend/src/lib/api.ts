/**
 * API client for the ReconMesh backend.
 *
 * All calls go through the Vite dev-proxy: /api/* on the browser side
 * is forwarded to backend:8000 inside Docker. In production we'll point
 * at a real origin; the surface area here doesn't change.
 */

// ----------------------------------------------------------------------------
// Error type
// ----------------------------------------------------------------------------
export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(`API error ${status}: ${detail}`);
    this.status = status;
    this.detail = detail;
    this.name = 'ApiError';
  }
}

// ----------------------------------------------------------------------------
// Source types
// ----------------------------------------------------------------------------
export interface Source {
  id: number;
  name: string;
  source_type: string;
  url: string | null;
  description: string | null;
}

export interface SourceListItem extends Source {
  indicator_count: number;
}

// ----------------------------------------------------------------------------
// Indicator types
// ----------------------------------------------------------------------------
export interface Indicator {
  id: number;
  indicator_type: string;
  value: string;
  confidence: string;
  tlp: string;
  tags: string[];
  first_seen: string | null;
  last_seen: string | null;
  ingested_at: string;
  is_active: boolean;
  source: Source;
}

// ----------------------------------------------------------------------------
// Enrichment types — match backend shapes
// ----------------------------------------------------------------------------
export type EnrichmentStatus = 'ok' | 'error' | 'timeout' | 'rate_limited' | 'not_found';

// DNS data shape
export interface DnsRecord {
  value: string;
  address?: string;
  preference?: number;
  exchange?: string;
  target?: string;
  text?: string;
}

export interface DnsData {
  records: Record<string, DnsRecord[]>;
  per_type_status: Record<string, string>;
}

// Email security data shape
export interface SpfData {
  present: boolean;
  raw: string | null;
  parsed?: {
    all: string | null;
    includes: string[];
    ip4: string[];
    ip6: string[];
  };
}

export interface DmarcData {
  present: boolean;
  raw: string | null;
  parsed?: {
    policy: string | null;
    subdomain_policy: string | null;
    percent: string | null;
    rua: string | null;
    ruf: string | null;
    alignment_spf: string | null;
    alignment_dkim: string | null;
  };
}

export interface DkimData {
  present: boolean;
  selectors_found: string[];
  raw_records: Array<{ selector: string; raw: string }>;
  selectors_checked: string[];
}

export interface PostureData {
  score: number;
  tier: 'strong' | 'partial' | 'weak';
  notes: string[];
}

export interface EmailSecurityData {
  spf: SpfData;
  dmarc: DmarcData;
  dkim: DkimData;
  posture: PostureData;
}

// WHOIS data shape
export interface WhoisData {
  registrar: string | null;
  registrant_org: string | null;
  registrant_country: string | null;
  creation_date: string | null;
  expiration_date: string | null;
  updated_date: string | null;
  name_servers: string[];
  status: string[];
  emails: string[];
  dnssec: string | null;
}

// Generic enrichment record
export interface Enrichment {
  enrichment_type: string;
  status: EnrichmentStatus;
  data: DnsData | EmailSecurityData | WhoisData | Record<string, unknown>;
  error_message: string | null;
  fetched_at: string;
}

export interface EnrichResponse {
  domain: string;
  results: Enrichment[];
}

// ----------------------------------------------------------------------------
// Domain types
// ----------------------------------------------------------------------------
export interface Domain {
  id: number;
  name: string;
  tld: string | null;
  registrar: string | null;
  registered_date: string | null;
  first_seen: string | null;
  last_seen: string | null;
  risk_score: number | null;
  indicators: Indicator[];
  enrichments: Enrichment[];
}

// ----------------------------------------------------------------------------
// Fetch helper
// ----------------------------------------------------------------------------
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch {
      // Response body not JSON; keep the status text
    }
    throw new ApiError(response.status, detail);
  }

  return response.json() as Promise<T>;
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------
export const api = {
  getDomain: (name: string): Promise<Domain> =>
    request<Domain>(`/domains/${encodeURIComponent(name)}`),

  enrichDomain: (name: string): Promise<EnrichResponse> =>
    request<EnrichResponse>(`/domains/${encodeURIComponent(name)}/enrich`, {
      method: 'POST',
    }),

  listSources: (): Promise<SourceListItem[]> => request<SourceListItem[]>('/sources'),
};
