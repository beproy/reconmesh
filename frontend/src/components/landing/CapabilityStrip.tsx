/**
 * CapabilityStrip
 *
 * Horizontal manifest of platform capabilities, rendered below the fold
 * on the landing page. Visual style: lowercase snake_case in mono,
 * separated by thin vertical rules. Reads as a system manifest, not
 * a marketing section.
 *
 * Capabilities are pulled from src/config/capabilities.ts. Capabilities
 * with `ready: false` are rendered greyed out to signal "shipping soon"
 * without making the strip feel incomplete.
 */

import React from 'react';
import { CAPABILITIES } from '../../config/capabilities';

export const CapabilityStrip: React.FC = () => {
  return (
    <div
      style={{
        borderTop: '0.5px solid var(--rm-border-subtle)',
        padding: '28px 28px 32px',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          marginBottom: '18px',
        }}
      >
        <span
          style={{
            width: '4px',
            height: '4px',
            borderRadius: '50%',
            background: 'var(--rm-accent-live)',
            opacity: 0.5,
          }}
          aria-hidden="true"
        />
        <span
          style={{
            fontSize: 'var(--rm-text-label)',
            color: 'var(--rm-text-faint)',
            letterSpacing: '0.18em',
            textTransform: 'uppercase',
          }}
        >
          Capabilities
        </span>
        <span
          style={{
            flex: 1,
            height: '0.5px',
            background: 'var(--rm-border-subtle)',
          }}
          aria-hidden="true"
        />
      </div>

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          fontFamily: 'var(--rm-font-mono)',
          fontSize: 'var(--rm-text-mono-data)',
        }}
      >
        {CAPABILITIES.map((cap, idx) => (
          <div
            key={cap.id}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: idx === 0 ? '6px 18px 6px 0' : '6px 18px',
              color: cap.ready ? 'var(--rm-text-secondary)' : 'var(--rm-text-faint)',
              borderLeft: idx === 0 ? 'none' : '0.5px solid var(--rm-border-subtle)',
              opacity: cap.ready ? 1 : 0.55,
            }}
            title={cap.ready ? undefined : 'coming soon'}
          >
            <i
              className={`ti ti-${cap.icon}`}
              style={{
                fontSize: '14px',
                color: cap.ready ? 'var(--rm-accent-info)' : 'var(--rm-text-faint)',
              }}
              aria-hidden="true"
            />
            {cap.label}
          </div>
        ))}
      </div>
    </div>
  );
};

export default CapabilityStrip;
