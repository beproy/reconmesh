import React from 'react';
import { ExternalLink } from 'lucide-react';

export type SourceStatus = 'healthy' | 'stale' | 'error' | 'unknown';

interface SourceCardProps {
  name: string;
  description: string;
  indicatorCount: number | null;
  lastIngested: string | null;
  status: SourceStatus;
  upstreamUrl: string;
}

const STATUS_CONFIG: Record<
  SourceStatus,
  { bg: string; text: string; dot: string; label: string }
> = {
  healthy: {
    bg: 'var(--rm-verdict-clean-bg)',
    text: 'var(--rm-verdict-clean-text)',
    dot: 'var(--rm-verdict-clean-dot)',
    label: 'healthy',
  },
  stale: {
    bg: 'var(--rm-verdict-noteworthy-bg)',
    text: 'var(--rm-verdict-noteworthy-text)',
    dot: 'var(--rm-verdict-noteworthy-dot)',
    label: 'stale',
  },
  error: {
    bg: 'var(--rm-verdict-malicious-bg)',
    text: 'var(--rm-verdict-malicious-text)',
    dot: 'var(--rm-verdict-malicious-dot)',
    label: 'error',
  },
  unknown: {
    bg: 'var(--rm-verdict-unknown-bg)',
    text: 'var(--rm-verdict-unknown-text)',
    dot: 'var(--rm-verdict-unknown-dot)',
    label: 'unknown',
  },
};

export const SourceCard: React.FC<SourceCardProps> = ({
  name,
  description,
  indicatorCount,
  lastIngested,
  status,
  upstreamUrl,
}) => {
  const cfg = STATUS_CONFIG[status];

  return (
    <div
      tabIndex={0}
      style={{
        padding: '16px 18px',
        borderRadius: '10px',
        backgroundColor: 'var(--rm-bg-surface)',
        border: '1px solid var(--rm-border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        outline: 'none',
        transition: 'background-color 120ms ease, border-color 200ms ease, box-shadow 200ms ease',
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLDivElement).style.backgroundColor =
          'var(--rm-bg-surface-hover)';
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLDivElement).style.backgroundColor =
          'var(--rm-bg-surface)';
      }}
      onFocus={(e) => {
        (e.currentTarget as HTMLDivElement).style.boxShadow =
          '0 0 0 4px var(--rm-accent-glow)';
        (e.currentTarget as HTMLDivElement).style.borderColor =
          'var(--rm-border-strong)';
      }}
      onBlur={(e) => {
        (e.currentTarget as HTMLDivElement).style.boxShadow = 'none';
        (e.currentTarget as HTMLDivElement).style.borderColor =
          'var(--rm-border-subtle)';
      }}
    >
      {/* Top Header Row: Name + Status Pill */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
        <h3
          style={{
            margin: 0,
            fontSize: '16px',
            fontWeight: 600,
            color: 'var(--rm-text-primary)',
          }}
        >
          {name}
        </h3>
        
        {/* Status Pill with Screen Reader Support */}
        <div
          role="status"
          aria-label={`Status: ${cfg.label}`}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 8px',
            borderRadius: '999px',
            backgroundColor: cfg.bg,
            color: cfg.text,
            fontSize: '11px',
            fontWeight: 500,
            textTransform: 'uppercase',
            letterSpacing: '0.04em',
          }}
        >
          <span
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              backgroundColor: cfg.dot,
            }}
          />
          {cfg.label}
        </div>
      </div>

      {/* Description */}
      <p
        style={{
          margin: 0,
          fontSize: '13px',
          lineHeight: '1.5',
          color: 'var(--rm-text-secondary)',
        }}
      >
        {description}
      </p>

      {/* Stats Section: Indicators + Ingestion Timestamp */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: '24px',
          paddingTop: '4px',
        }}
      >
        {/* Indicators Count */}
        <div>
          <div
            style={{
              fontSize: '10px',
              fontWeight: 500,
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color: 'var(--rm-text-muted)',
              marginBottom: '2px',
            }}
          >
            Indicators
          </div>
          <div
            className="rm-mono"
            style={{
              fontSize: '15px',
              fontWeight: 600,
              color: 'var(--rm-text-primary)',
            }}
          >
            {indicatorCount !== null ? indicatorCount.toLocaleString() : '—'}
          </div>
        </div>

        {/* Last Ingested Timestamp */}
        <div>
          <div
            style={{
              fontSize: '10px',
              fontWeight: 500,
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color: 'var(--rm-text-muted)',
              marginBottom: '2px',
            }}
          >
            Last Ingested
          </div>
          <div
            className="rm-mono"
            style={{
              fontSize: '13px',
              fontWeight: 500,
              color: 'var(--rm-text-secondary)',
            }}
          >
            {lastIngested !== null ? lastIngested : '—'}
          </div>
        </div>
      </div>

      {/* External Link */}
      <div style={{ display: 'flex', justifyContent: 'flex-start', marginTop: '4px' }}>
        <a
          href={upstreamUrl}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            fontSize: '11px',
            color: 'var(--rm-text-muted)',
            textDecoration: 'none',
            transition: 'color 120ms ease',
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLAnchorElement).style.color =
              'var(--rm-text-primary)';
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLAnchorElement).style.color =
              'var(--rm-text-muted)';
          }}
        >
          <ExternalLink size={12} />
          Feed Source
        </a>
      </div>
    </div>
  );
};
