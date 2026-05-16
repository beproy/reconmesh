/**
 * EvidenceRow.tsx
 *
 * Collapsible row primitive for the investigation page. Wraps one or more
 * existing section components (DnsSection, WhoisSection, etc.) under a
 * single collapsible header.
 *
 *   ┌─ ▸ Title ──────────────────── right summary text ─┐
 *   │   (children render here when open)                │
 *   └────────────────────────────────────────────────────┘
 *
 * Implementation uses native <details>/<summary> for built-in keyboard
 * accessibility and no JS state.
 */

import React from 'react';

interface EvidenceRowProps {
  title: string;
  /** Right-aligned summary text (e.g. "4 records", "strong · 100/100"). */
  summary?: string;
  /** Color hint for the summary text and left border. */
  status?: 'clean' | 'mixed' | 'investigate' | 'neutral';
  /** Whether the row starts expanded. */
  defaultOpen?: boolean;
  children: React.ReactNode;
}

const STATUS_BORDER: Record<NonNullable<EvidenceRowProps['status']>, string> = {
  clean: 'rgba(34, 197, 94, 0.4)',
  mixed: 'rgba(245, 158, 11, 0.4)',
  investigate: 'rgba(239, 68, 68, 0.4)',
  neutral: 'rgba(148, 163, 184, 0.2)',
};

const STATUS_SUMMARY: Record<NonNullable<EvidenceRowProps['status']>, string> = {
  clean: 'rgb(134, 239, 172)',
  mixed: 'rgb(252, 211, 77)',
  investigate: 'rgb(252, 165, 165)',
  neutral: 'rgb(148, 163, 184)',
};

export const EvidenceRow: React.FC<EvidenceRowProps> = ({
  title,
  summary,
  status = 'neutral',
  defaultOpen = false,
  children,
}) => {
  return (
    <details
      open={defaultOpen}
      style={{
        borderRadius: '10px',
        border: '1px solid rgba(255, 255, 255, 0.06)',
        borderLeft: `3px solid ${STATUS_BORDER[status]}`,
        backgroundColor: 'rgba(255, 255, 255, 0.02)',
        marginBottom: '10px',
        overflow: 'hidden',
      }}
    >
      <summary
        style={{
          padding: '14px 18px',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          listStyle: 'none',
          userSelect: 'none',
          transition: 'background-color 120ms ease',
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLElement).style.backgroundColor =
            'rgba(255, 255, 255, 0.02)';
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent';
        }}
      >
        {/* Caret — rotates via CSS based on parent <details open> */}
        <span
          aria-hidden="true"
          style={{
            display: 'inline-block',
            color: 'var(--rm-text-muted, rgb(148, 163, 184))',
            fontSize: '12px',
            width: '12px',
            transition: 'transform 150ms ease',
          }}
          className="rm-evidence-caret"
        >
          ▸
        </span>

        <span
          style={{
            fontSize: '14px',
            fontWeight: 500,
            color: 'var(--rm-text-primary, rgb(241, 245, 249))',
            flex: 1,
          }}
        >
          {title}
        </span>

        {summary && (
          <span
            style={{
              fontSize: '12px',
              color: STATUS_SUMMARY[status],
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {summary}
          </span>
        )}
      </summary>

      <div
        style={{
          padding: '0 18px 18px 18px',
          display: 'flex',
          flexDirection: 'column',
          gap: '12px',
        }}
      >
        {children}
      </div>

      {/* Inline style for the caret rotation when <details> is open.
          Scoped via the className above + the parent[open] selector. */}
      <style>{`
        details[open] > summary .rm-evidence-caret {
          transform: rotate(90deg);
        }
        details > summary::-webkit-details-marker {
          display: none;
        }
      `}</style>
    </details>
  );
};
