/**
 * ReconMesh API client.
 *
 * Centralizes all backend calls. The Vite dev server proxies /api/* to the
 * backend container, so we always call relative URLs starting with /api.
 */

// ---------- Types ----------

export type IndicatorType =
  | 'ipv4' | 'ipv6' | 'url' | 'domain'
  | 'md5' | 'sha1' | 'sha256'
  | 'email' | 'asn' | 'bitcoin_address'
  | 'mutex' | 'file_path' | 'registry_key';

export type Confidence = 'low' | 'medium' | 'high' | 'confirmed';

export type TLP = 'clear' | 'green' | 'amber' | 'amber+strict' | 'red';

export interface Source {
  id: number;
  name: string;
  source_type: string;
  url: string | null;
  description: string | null;
}

export interface Indicator {
  id: number;
  indicator_type: IndicatorType;
  value: string;
  confidence: Confidence;
  tlp: TLP;
  tags: string[];
  first_seen: string | null;
  last_seen: string | null;
  ingested_at: string;
  is_active: boolean;
  source: Source;
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
}

export interface SourceListItem extends Source {
  indicator_count: number;
}

// ---------- API errors ----------

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// ---------- Helpers ----------

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, init);

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch {
      // body wasn't JSON; ignore
    }
    throw new ApiError(response.status, detail);
  }

  return response.json() as Promise<T>;
}

// ---------- Endpoint functions ----------

export const api = {
  /** Fetch a single domain with all its indicators. Throws ApiError on 404. */
  getDomain: (name: string) => request<Domain>(`/domains/${encodeURIComponent(name)}`),

  /** List all sources we've ingested from, with indicator counts. */
  listSources: () => request<SourceListItem[]>('/sources'),
};