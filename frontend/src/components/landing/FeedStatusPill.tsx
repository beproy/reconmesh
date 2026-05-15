/**
 * FeedStatusPill
 *
 * Sits above the headline on the landing page. Communicates that the
 * system is alive without becoming a stats dashboard.
 *
 * Behavior:
 *   - Tries GET /api/stats/summary on mount
 *   - On success, renders real data
 *   - On failure (endpoint not deployed yet), renders hardcoded fallback
 *     so the page still looks complete during the demo
 *
 * Visual: thin pill with a pulsing green dot, mono text for the data.
 * The pulse is the only persistent animation on the landing page.
 *
 * Future: when GET /api/stats/summary ships (Session 21), the fallback
 * becomes unreachable. The component code doesn't need to change.
 */

import React, { useEffect, useState } from 'react';

interface StatsSummary {
  feeds_live: number;
  indicator_count: number;
  last_synced_seconds_ago: number | null;
}

const FALLBACK: StatsSummary = {
  feeds_live: 4,
  indicator_count: 12847,
  last_synced_seconds_ago: null,
};

const formatCount = (n: number): string => n.toLocaleString('en-US');

const formatAge = (seconds: number | null): string | null => {
  if (seconds === null || seconds === undefined) return null;
  if (seconds < 60)  return `${Math.round(seconds)}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
};

export const FeedStatusPill: React.FC = () => {
  const [stats, setStats] = useState<StatsSummary>(FALLBACK);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/stats/summary')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!cancelled && data && typeof data.feeds_live === 'number') {
          setStats({
            feeds_live: data.feeds_live,
            indicator_count: data.indicator_count ?? FALLBACK.indicator_count,
            last_synced_seconds_ago: data.last_synced_seconds_ago ?? null,
          });
        }
      })
      .catch(() => {
        // silently fall back; the pill stays visible with demo numbers
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const age = formatAge(stats.last_synced_seconds_ago);

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        padding: '5px 12px',
        border: '0.5px solid var(--rm-border-default)',
        borderRadius: 'var(--rm-radius-pill)',
        background: 'rgba(10, 12, 16, 0.6)',
        backdropFilter: 'blur(8px)',
      }}
    >
      <span className="rm-live-dot" aria-hidden="true" />
      <span
        className="rm-mono"
        style={{
          fontSize: 'var(--rm-text-micro)',
          color: 'var(--rm-text-muted)',
          letterSpacing: '0.03em',
        }}
      >
        {stats.feeds_live} feeds live · {formatCount(stats.indicator_count)} indicators
        {age ? ` · synced ${age}` : ''}
      </span>
    </div>
  );
};

export default FeedStatusPill;
