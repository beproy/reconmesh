/**
 * VerdictPill.tsx
 *
 * Renders the 3-state verdict as a colored pill in the header strip.
 *
 *   investigate  → amber  ("Worth investigating")
 *   mixed        → slate  ("Mixed signals")
 *   clean        → green  ("Looks clean")
 *
 * Hover shows the reasons (native title attribute, no tooltip lib needed).
 */

import React from 'react';
import type { Verdict } from '@/lib/verdict';

interface VerdictPillProps {
  verdict: Verdict;
}

const STYLES: Record<
  Verdict['state'],
  { bg: string; border: string; text: string; dot: string }
> = {
  investigate: {
    bg: 'rgba(245, 158, 11, 0.12)',   // amber-500 @ 12%
    border: 'rgba(245, 158, 11, 0.35)',
    text: 'rgb(252, 211, 77)',         // amber-300
    dot: 'rgb(245, 158, 11)',          // amber-500
  },
  mixed: {
    bg: 'rgba(148, 163, 184, 0.12)',  // slate-400 @ 12%
    border: 'rgba(148, 163, 184, 0.35)',
    text: 'rgb(203, 213, 225)',        // slate-300
    dot: 'rgb(148, 163, 184)',         // slate-400
  },
  clean: {
    bg: 'rgba(34, 197, 94, 0.12)',    // green-500 @ 12%
    border: 'rgba(34, 197, 94, 0.35)',
    text: 'rgb(134, 239, 172)',        // green-300
    dot: 'rgb(34, 197, 94)',           // green-500
  },
};

export const VerdictPill: React.FC<VerdictPillProps> = ({ verdict }) => {
  const s = STYLES[verdict.state];

  // Build a tooltip string from the reasons list, one per line.
  const tooltip = verdict.reasons.join('\n');

  return (
    <span
      title={tooltip}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        padding: '6px 12px',
        borderRadius: '999px',
        border: `1px solid ${s.border}`,
        backgroundColor: s.bg,
        color: s.text,
        fontSize: '13px',
        fontWeight: 500,
        letterSpacing: '0.01em',
        whiteSpace: 'nowrap',
        cursor: verdict.reasons.length > 0 ? 'help' : 'default',
      }}
    >
      <span
        style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          backgroundColor: s.dot,
          boxShadow: `0 0 6px ${s.dot}`,
        }}
      />
      {verdict.label}
    </span>
  );
};
