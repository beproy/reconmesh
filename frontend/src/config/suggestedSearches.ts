/**
 * Suggested searches shown below the search hero on the landing page.
 *
 * These are intentionally static and well-known. Four chips that:
 *   - communicate the input types ReconMesh accepts (domain, IP)
 *   - give the user a one-click path out of the blank-page state
 *   - act as reliable demo paths during showcases
 *
 * Verdict drives the dot color. We hand-set these because they're stable
 * benchmark domains — microsoft.com isn't going to start showing up in
 * URLhaus tomorrow. When recent-investigations history exists (Session 22+),
 * this list will be replaced with personalized data.
 */

export type Verdict = 'clean' | 'noteworthy' | 'suspicious' | 'malicious' | 'unknown';

export interface SuggestedSearch {
  value: string;
  verdict: Verdict;
}

export const SUGGESTED_SEARCHES: SuggestedSearch[] = [
  { value: 'microsoft.com',  verdict: 'clean' },
  { value: 'cloudflare.com', verdict: 'clean' },
  { value: '8.8.8.8',        verdict: 'clean' },
  { value: 'telegram.org',   verdict: 'noteworthy' },
];
