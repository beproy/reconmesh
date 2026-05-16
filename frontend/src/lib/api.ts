/**
 * API client for the ReconMesh backend.
 *
 * Session 19.5: X-API-Key header injection.
 * Session 20: MITRE ATT&CK catalog + global stats.
 */
import { getApiKey } from './apiKey';

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
// Enrichment types
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
  parsed?: { all: string | null; includes: string[]; ip4: string[]; ip6: string[]; };
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
  analysis_stats: { malicious: number; suspicious: number; harmless: number; undetected: number; total: number; };
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

export interface AhmiaMention {
  onion_url: string;
  onion_host: string;
  title: string;
  snippet: string;
  cite: string;
  last_seen: string;
}

export interface AhmiaData {
  query: string;
  mention_count: number;
  unique_sites: number;
  raw_result_count: number;
  mentions: AhmiaMention[];
  note: string;
  source_url: string;
}

export interface MnemonicPdnsRecord {
      rrtype: string;
      query: string;
      answer: string;
      first_seen: string | null;
      last_seen: string | null;
      times: number;
    }
 
export interface MnemonicPdnsData {
      query: string;
      total_records: number;
      unique_answers: number;
      rrtypes: string[];
      records: MnemonicPdnsRecord[];
      cap_applied: number;
    }

export interface UrlscanScan {
      scanned_at: string | null;
      url: string;
      page_domain: string;
      ip: string;
      country: string;
      server: string;
      result_url: string;
    }
 
export interface UrlscanData {
      query: string;
      total_scans: number;
      has_more: boolean;
      unique_ips: number;
      unique_countries: number;
      scans: UrlscanScan[];
      cap_applied: number;
    }
 
    // --- HackerTarget (Session 23) ---
export interface HackerTargetData {
      query: string;
      resolved_ip: string | null;
      total_hostnames: number;
      hostnames: string[];
      cap_applied: number;
      free_tier_note: boolean;
    }
 
    // --- ThreatMiner (Session 25) ---
export interface ThreatMinerPdnsRecord {
      ip: string;
      first_seen: string | null;
      last_seen: string | null;
    }
 
export interface ThreatMinerSample {
      hash: string;
      family?: string | null;
    }
 
export interface ThreatMinerData {
      query: string;
      passive_dns: ThreatMinerPdnsRecord[];
      passive_dns_count: number;
      subdomains: string[];
      subdomains_count: number;
      related_samples: ThreatMinerSample[];
      related_samples_count: number;
      partial_errors: string[];
      caps: {
        passive_dns: number;
        subdomains: number;
        related_samples: number;
      };
    }
export interface Enrichment {
  enrichment_type: string;
  status: EnrichmentStatus;
  data: DnsData | EmailSecurityData | WhoisData | TypoSquatData | VirusTotalData | ShodanData | AbuseIPDBData | AhmiaData | MnemonicPdnsData | UrlscanData | HackerTargetData | ThreatMinerData | Record<string, unknown>;
  error_message: string | null;
  fetched_at: string;
}


// ----------------------------------------------------------------------------
// AI Summary types (Session 22)
// ----------------------------------------------------------------------------
export interface AiSummaryResponse {
  domain: string;
  sector_assessment: {
    likely_sector: string | null;
    confidence: 'high' | 'medium' | 'low';
    reasoning: string;
  };
  risk_summary: {
    overall_risk: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    key_findings: string[];
    concerns: string[];
    positives: string[];
  };
  enrichment_highlights: Record<string, string | null>;
  relevant_threat_actors: {
    attack_id: string;
    name: string;
    relevance: string;
  }[];
  recommendation: string;
  error?: string;
}

// ----------------------------------------------------------------------------
// Async enrichment job types
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
// MITRE ATT&CK types (Session 20)
// ----------------------------------------------------------------------------
export interface AttackGroupListItem {
  attack_id: string;
  stix_id: string;
  name: string;
  aliases: string[];
}

export interface AttackTechniqueRef {
  attack_id: string;
  name: string;
  is_subtechnique: boolean;
}

export interface AttackMalwareRef {
  attack_id: string;
  name: string;
}

export interface AttackGroupRef {
  attack_id: string;
  name: string;
}

export interface AttackExternalReference {
  url?: string;
  source_name?: string;
  external_id?: string;
  description?: string;
}

export interface AttackGroupDetail {
  attack_id: string;
  stix_id: string;
  name: string;
  description: string | null;
  aliases: string[];
  external_references: AttackExternalReference[];
  related_techniques: AttackTechniqueRef[];
  related_malware: AttackMalwareRef[];
}

export interface AttackTechniqueListItem {
  attack_id: string;
  stix_id: string;
  name: string;
  is_subtechnique: boolean;
  tactics: string[];
}

export interface AttackTechniqueDetail {
  attack_id: string;
  stix_id: string;
  name: string;
  description: string | null;
  is_subtechnique: boolean;
  tactics: string[];
  platforms: string[];
  data_sources: string[];
  detection: string | null;
  external_references: AttackExternalReference[];
  related_groups: AttackGroupRef[];
}

// ----------------------------------------------------------------------------
// Global stats (Session 20 polish)
// ----------------------------------------------------------------------------
export interface Stats {
  domains: number;
  indicators: number;
  enrichments: number;
  sources: number;
  attack_groups: number;
  attack_techniques: number;
}

// ----------------------------------------------------------------------------
// Fetch helper
// ----------------------------------------------------------------------------
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string> | undefined),
  };

  const apiKey = getApiKey();
  if (apiKey) headers['X-API-Key'] = apiKey;

  const response = await fetch(`/api${path}`, { ...init, headers });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch { /* not JSON */ }
    if (response.status === 401) {
      detail = `${detail} — open Settings (gear icon) to set your API key.`;
    }
    throw new ApiError(response.status, detail);
  }

  return response.json() as Promise<T>;
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------
export const api = {
  listDomains: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString();
    return request<DomainListItem[]>(`/domains?${qs}`);
  },

  getDomain: (name: string) =>
    request<Domain>(`/domains/${encodeURIComponent(name)}`),

  enrichDomainAsync: (name: string) =>
    request<EnrichJobDispatched>(
      `/domains/${encodeURIComponent(name)}/enrich`,
      { method: 'POST' }
    ),

  getEnrichJob: (name: string, jobId: number) =>
    request<EnrichJob>(`/domains/${encodeURIComponent(name)}/enrich/${jobId}`),

  listSources: () => request<SourceListItem[]>('/sources'),

  getStats: () => request<Stats>('/stats'),

  // MITRE ATT&CK catalog (Session 20)
  listAttackGroups: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString();
    return request<AttackGroupListItem[]>(`/attack/groups?${qs}`);
  },

  getAttackGroup: (attackId: string) =>
    request<AttackGroupDetail>(`/attack/groups/${encodeURIComponent(attackId)}`),

  listAttackTechniques: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString();
    return request<AttackTechniqueListItem[]>(`/attack/techniques?${qs}`);
  },

  getAttackTechnique: (attackId: string) =>
    request<AttackTechniqueDetail>(`/attack/techniques/${encodeURIComponent(attackId)}`),
// AI Summary (Session 22)
  getAiSummary: (domainName: string) =>
    request<AiSummaryResponse>(`/domains/${encodeURIComponent(domainName)}/ai-summary`, {
      method: 'POST',
    }),  
};
