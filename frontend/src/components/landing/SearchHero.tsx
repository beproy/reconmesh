/**
 * SearchHero
 *
 * The visual hero of the landing page. Large input, integrated submit
 * button, rotating placeholder text, focus glow.
 *
 * Owns:
 *   - Local focus state (drives the focus ring)
 *   - Placeholder rotation (4-second interval, cycles through example types)
 *
 * Receives:
 *   - value, onChange: controlled input (so SuggestedChips can populate it)
 *   - onSubmit: called with the current value when user submits
 *
 * Submission paths:
 *   - Enter key in the input
 *   - Click the "Investigate" button
 *
 * The actual routing (which page to navigate to) is the parent's
 * responsibility — this component just emits onSubmit(value).
 */

import React, { useEffect, useRef, useState } from 'react';

interface SearchHeroProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: (value: string) => void;
}

const PLACEHOLDERS = [
  'example.com',
  '8.8.8.8',
  'sha256:a1b2c3d4...',
  '192.168.0.0/16',
];

export const SearchHero: React.FC<SearchHeroProps> = ({ value, onChange, onSubmit }) => {
  const [focused, setFocused] = useState(false);
  const [placeholderIdx, setPlaceholderIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const id = window.setInterval(() => {
      setPlaceholderIdx((i) => (i + 1) % PLACEHOLDERS.length);
    }, 4000);
    return () => window.clearInterval(id);
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const trimmed = value.trim();
      if (trimmed) onSubmit(trimmed);
    }
  };

  const handleClick = () => {
    const trimmed = value.trim();
    if (trimmed) onSubmit(trimmed);
    else inputRef.current?.focus();
  };

  return (
    <div
      className={focused ? 'rm-focus-ring' : ''}
      style={{
        width: '100%',
        maxWidth: '580px',
        position: 'relative',
        background: 'rgba(15, 17, 22, 0.85)',
        backdropFilter: 'blur(12px)',
        border: '0.5px solid var(--rm-border-strong)',
        borderRadius: 'var(--rm-radius-xl)',
        padding: '4px 4px 4px 18px',
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
      }}
    >
      <i
        className="ti ti-search"
        style={{ fontSize: '18px', color: 'var(--rm-text-faint)' }}
        aria-hidden="true"
      />
      <input
        ref={inputRef}
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onKeyDown={handleKeyDown}
        placeholder={`Try ${PLACEHOLDERS[placeholderIdx]}`}
        aria-label="Search domain, IP address, or hash"
        spellCheck={false}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        style={{
          flex: 1,
          background: 'transparent',
          border: 0,
          outline: 0,
          color: 'var(--rm-text-primary)',
          fontSize: 'var(--rm-text-body)',
          padding: '14px 0',
          fontFamily: 'var(--rm-font-mono)',
          minWidth: 0,
        }}
      />
      <button
        type="button"
        onClick={handleClick}
        aria-label="Investigate"
        style={{
          background: '#f3f4f6',
          color: '#0a0c10',
          border: 0,
          borderRadius: '10px',
          padding: '11px 18px',
          fontSize: 'var(--rm-text-small)',
          fontWeight: 500,
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          flexShrink: 0,
        }}
      >
        Investigate
        <i className="ti ti-arrow-right" style={{ fontSize: '14px' }} aria-hidden="true" />
      </button>
    </div>
  );
};

export default SearchHero;
