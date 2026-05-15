/**
 * Query router — detects what the user typed in the search hero
 * and decides which page to navigate to.
 *
 * Pure function. No side effects. All regex-based detection.
 *
 * For the current phase, every kind routes to /domains/<value> because
 * that's the only investigation page that exists. The discriminated
 * union is set up so that when /ip/<value> and /indicator/<value> pages
 * land in later sessions, only the route mapping changes — call sites
 * stay the same.
 */

export type QueryKind = 'domain' | 'ipv4' | 'ipv6' | 'hash' | 'cidr' | 'unknown';

export interface RouteTarget {
  kind: QueryKind;
  /** Normalized value, ready to embed in a URL */
  value: string;
  /** The path to navigate to */
  path: string;
}

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_RE = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^:(?::[0-9a-fA-F]{1,4}){1,7}$/;
const CIDR_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;

const normalize = (input: string): string => input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

export function routeQuery(rawInput: string): RouteTarget {
  const value = normalize(rawInput);

  if (!value) {
    return { kind: 'unknown', value: '', path: '/' };
  }

  if (IPV4_RE.test(value)) {
    return { kind: 'ipv4', value, path: `/domains/${encodeURIComponent(value)}` };
  }

  if (IPV6_RE.test(value)) {
    return { kind: 'ipv6', value, path: `/domains/${encodeURIComponent(value)}` };
  }

  if (CIDR_RE.test(value)) {
    return { kind: 'cidr', value, path: `/domains/${encodeURIComponent(value)}` };
  }

  if (HASH_RE.test(value)) {
    return { kind: 'hash', value, path: `/domains/${encodeURIComponent(value)}` };
  }

  if (DOMAIN_RE.test(value)) {
    return { kind: 'domain', value, path: `/domains/${encodeURIComponent(value)}` };
  }

  return { kind: 'unknown', value, path: `/domains/${encodeURIComponent(value)}` };
}
