/**
 * MetricCell.tsx
 *
 * One cell in the investigation page's metric grid.
 *
 *   ┌─────────────────────────────┐
 *   │ LABEL (uppercase, small)    │
 *   │                             │
 *   │ Value (large, bold)         │
 *   │ subtext (small, muted)      │
 *   └─────────────────────────────┘
 *
 * The left border and value color tint by status:
 *   clean       → green
 *   mixed       → amber
 *   investigate → red
 *   neutral     → slate (no data / not run)
 */

import React from 'react';

export type CellStatus = 'clean' | 'mixed' | 'investigate' | 'neutral';

interface MetricCellProps {
  label: string;
  value: string;
  subtext?: string;
  status: CellStatus;
}

const STATUS_COLORS: Record<CellStatus, { border: string; value: string }> = {
  clean: {
    border: 'rgba(34, 197, 94, 0.5)',
    value: 'rgb(134, 239, 172)',
  },
  mixed: {
    border: 'rgba(245, 158, 11, 0.5)',
    value: 'rgb(252, 211, 77)',
  },
  investigate: {
    border: 'rgba(239, 68, 68, 0.5)',
    value: 'rgb(252, 165, 165)',
  },
  neutral: {
    border: 'rgba(148, 163, 184, 0.3)',
    value: 'rgb(203, 213, 225)',
  },
};

export const MetricCell: React.FC<MetricCellProps> = ({
  label,
  value,
  subtext,
  status,
}) => {
  const c = STATUS_COLORS[status];

  return (
    <div
      style={{
        padding: '16px 18px',
        borderRadius: '10px',
        backgroundColor: 'rgba(255, 255, 255, 0.02)',
        border: '1px solid rgba(255, 255, 255, 0.06)',
        borderLeft: `3px solid ${c.border}`,
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        minHeight: '90px',
      }}
    >
      <div
        style={{
          fontSize: '11px',
          fontWeight: 500,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          color: 'var(--rm-text-muted, rgb(148, 163, 184))',
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: '20px',
          fontWeight: 600,
          color: c.value,
          letterSpacing: '-0.01em',
          lineHeight: 1.2,
        }}
      >
        {value}
      </div>
      {subtext && (
        <div
          style={{
            fontSize: '12px',
            color: 'var(--rm-text-muted, rgb(148, 163, 184))',
            lineHeight: 1.4,
          }}
        >
          {subtext}
        </div>
      )}
    </div>
  );
};
