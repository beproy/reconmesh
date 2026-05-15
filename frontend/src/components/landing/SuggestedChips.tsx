/**
 * SuggestedChips
 *
 * Four clickable benchmark chips shown below the search hero.
 * Each chip displays the example value and a small verdict dot.
 *
 * On click: calls onPick(value), which the parent uses to populate
 * the search input. We deliberately do NOT navigate directly — the
 * user expects to see the value land in the search field before
 * pressing Investigate. This makes the chips feel like input shortcuts,
 * not like navigation links.
 */

import React from 'react';
import { SUGGESTED_SEARCHES, type Verdict } from '../../config/suggestedSearches';

interface SuggestedChipsProps {
  onPick: (value: string) => void;
}

const verdictDotColor = (verdict: Verdict): string => {
  switch (verdict) {
    case 'clean':       return 'var(--rm-verdict-clean-dot)';
    case 'noteworthy':  return 'var(--rm-verdict-noteworthy-dot)';
    case 'suspicious':  return 'var(--rm-verdict-suspicious-dot)';
    case 'malicious':   return 'var(--rm-verdict-malicious-dot)';
    case 'unknown':     return 'var(--rm-verdict-unknown-dot)';
  }
};

export const SuggestedChips: React.FC<SuggestedChipsProps> = ({ onPick }) => {
  return (
    <div
      style={{
        display: 'flex',
        gap: '8px',
        marginTop: '16px',
        flexWrap: 'wrap',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
      <span
        style={{
          fontSize: 'var(--rm-text-label)',
          color: 'var(--rm-text-faint)',
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
        }}
      >
        Suggested
      </span>
      {SUGGESTED_SEARCHES.map(({ value, verdict }) => (
        <button
          key={value}
          type="button"
          onClick={() => onPick(value)}
          aria-label={`Search for ${value}`}
          className="rm-mono"
          style={{
            fontSize: 'var(--rm-text-micro)',
            color: 'var(--rm-text-secondary)',
            background: 'var(--rm-bg-surface)',
            border: '0.5px solid var(--rm-border-subtle)',
            padding: '4px 10px',
            borderRadius: 'var(--rm-radius-sm)',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            cursor: 'pointer',
            transition: 'background 150ms ease, border-color 150ms ease',
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLButtonElement).style.background = 'var(--rm-bg-surface-hover)';
            (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--rm-border-default)';
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLButtonElement).style.background = 'var(--rm-bg-surface)';
            (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--rm-border-subtle)';
          }}
        >
          {value}
          <span
            style={{
              width: '4px',
              height: '4px',
              borderRadius: '50%',
              background: verdictDotColor(verdict),
            }}
            aria-hidden="true"
          />
        </button>
      ))}
    </div>
  );
};

export default SuggestedChips;
