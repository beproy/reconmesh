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

export interface TypoSquatAlive {
  domain: string;
  fuzzer: string;
  a_records: string[];
}

export interface TypoSquatData {
  permutations_generated: number;
  permutations_attempted: number;
  alive_count: number;
  alive: TypoSquatAlive[];
  cap_applied: number;
  budget_seconds: number;
}

export interface VirusTotalData {
  verdict: 'clean' | 'malicious' | 'suspicious' | 'unknown';
  analysis_stats: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    total: number;
  };
  reputation: number;
  categories: string[];
  popularity_ranks: Record<string, number>;
  jarm: string | null;
  creation_date: number | null;
  last_analysis_date: number | null;
}

export interface ShodanData {
  ip: string;
  ports: number[];
  ports_count: number;
  vulns: string[];
  vulns_count: number;
  os: string | null;
  org: string | null;
  isp: string | null;
  asn: string | null;
  country: string | null;
  city: string | null;
  services: Array<{ port: number; transport?: string; product?: string; version?: string; module?: string }>;
  last_update: string | null;
}

export interface AbuseIPDBData {
  ip: string;
  abuse_confidence_score: number;
  threat_level: 'high' | 'medium' | 'low' | 'none';
  total_reports: number;
  distinct_reporters: number;
  country_code: string | null;
  country_name: string | null;
  isp: string | null;
  usage_type: string | null;
  domain: string | null;
  is_tor: boolean;
  is_whitelisted: boolean;
  last_reported_at: string | null;
}

export interface Enrichment {
  enrichment_type: string;
  status: EnrichmentStatus;
  data: DnsData | EmailSecurityData | WhoisData | TypoSquatData | VirusTotalData | ShodanData | AbuseIPDBData | Record<string, unknown>;
  error_message: string | null;
  fetched_at: string;
}

// ----------------------------------------------------------------------------
// Async enrichment job types (NEW in Session 8)
// ----------------------------------------------------------------------------
export type EnrichJobStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface EnrichJobDispatched {
  job_id: number;
  domain: string;
  enrichment_types: string[];
  poll_url: string;
}

export interface EnrichJob {
  id: number;
  domain_id: number;
  status: EnrichJobStatus;
  total_tasks: number;
  completed_tasks: number;
  failed_tasks: number;
  enrichment_types: string[];
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

// ----------------------------------------------------------------------------
// Domain types
// ----------------------------------------------------------------------------
export interface DomainListItem {
  id: number;
  name: string;
  tld: string | null;
  risk_score: number | null;
  first_seen: string | null;
  last_seen: string | null;
  indicator_count: number;
  enrichment_count: number;
}

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
  listDomains: (params: Record<string, string>): Promise<DomainListItem[]> => {
    const qs = new URLSearchParams(params).toString();
    return request<DomainListItem[]>(`/domains?${qs}`);
  },

  getDomain: (name: string): Promise<Domain> =>
    request<Domain>(`/domains/${encodeURIComponent(name)}`),

  /**
   * Dispatch async enrichment. Returns immediately with a job_id; the
   * actual work happens in the Celery worker.
   * Status code is 202 Accepted, but our request() helper handles 2xx the
   * same way so we just consume the JSON body.
   */
  enrichDomainAsync: (name: string): Promise<EnrichJobDispatched> =>
    request<EnrichJobDispatched>(
      `/domains/${encodeURIComponent(name)}/enrich`,
      { method: 'POST' }
    ),

  /**
   * Poll the status of an enrichment job. Frontend calls this every couple
   * of seconds while a job is in flight. Stops when status is 'completed'
   * or 'failed'.
   */
  getEnrichJob: (name: string, jobId: number): Promise<EnrichJob> =>
    request<EnrichJob>(
      `/domains/${encodeURIComponent(name)}/enrich/${jobId}`
    ),

  listSources: (): Promise<SourceListItem[]> => request<SourceListItem[]>('/sources'),
};
