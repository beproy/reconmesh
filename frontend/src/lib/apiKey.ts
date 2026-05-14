/**
 * API key storage helpers.
 *
 * The backend's /enrich (and future protected routes) require an
 * X-API-Key header. We keep the key in the browser so the user only
 * enters it once per session.
 *
 * SECURITY NOTE — why sessionStorage, not localStorage:
 * sessionStorage is scoped to the browser tab and is cleared when the
 * tab closes. localStorage persists on disk indefinitely. For an API
 * key, sessionStorage is the safer choice — it limits the exposure
 * window to the current session rather than leaving the key sitting
 * on disk between visits. The tradeoff is the user re-enters their
 * key when they open a fresh tab, which for a personal CTI tool is an
 * acceptable (and arguably more honest) tradeoff.
 *
 * This also resolves the CodeQL "clear-text storage of sensitive
 * information" alert — the key is no longer persisted to disk.
 */

const STORAGE_KEY = 'reconmesh.apiKey';

/** Returns the stored API key, or null if none is set. */
export function getApiKey(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY);
  } catch {
    // sessionStorage can throw in some locked-down browser configs
    return null;
  }
}

/** Persist an API key for this browser session. Empty strings clear it. */
export function setApiKey(key: string): void {
  try {
    const trimmed = key.trim();
    if (trimmed) {
      sessionStorage.setItem(STORAGE_KEY, trimmed);
    } else {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // ignore quota / locked-down-browser errors
  }
}

/** Remove the stored API key. */
export function clearApiKey(): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}

/** True if a non-empty API key is currently stored for this session. */
export function hasApiKey(): boolean {
  const v = getApiKey();
  return v !== null && v.length > 0;
}
