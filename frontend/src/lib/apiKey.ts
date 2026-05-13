/**
 * API key storage helpers.
 *
 * The backend's /enrich (and /feeds/mitre/refresh, and future protected
 * routes) require an X-API-Key header. We persist the key in localStorage
 * so the user only enters it once per browser. localStorage is fine for
 * dev / personal use; production deployment would use a real auth flow.
 */

const STORAGE_KEY = 'reconmesh.apiKey';

/** Returns the stored API key, or null if none is set. */
export function getApiKey(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    // localStorage can throw in some private-browsing modes
    return null;
  }
}

/** Persist an API key. Empty strings are treated as a clear. */
export function setApiKey(key: string): void {
  try {
    const trimmed = key.trim();
    if (trimmed) {
      localStorage.setItem(STORAGE_KEY, trimmed);
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // ignore quota / private-browsing errors
  }
}

/** Remove the stored API key. */
export function clearApiKey(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}

/** True if a non-empty API key is currently stored. */
export function hasApiKey(): boolean {
  const v = getApiKey();
  return v !== null && v.length > 0;
}
