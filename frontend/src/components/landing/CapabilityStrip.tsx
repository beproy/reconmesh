/**
 * CapabilityStrip
 *
 * Grid of platform capabilities with icons, labels and descriptions.
 * Rendered below the fold on the landing page.
 */

import React from 'react';
import { CAPABILITIES } from '../../config/capabilities';

export const CapabilityStrip: React.FC = () => {
  return (
    <div
      style={{
        borderTop: '0.5px solid var(--rm-border-subtle)',
        padding: '28px 28px 40px',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          marginBottom: '24px',
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
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '20px',
        }}
      >
        {CAPABILITIES.map((cap) => (
          <div
            key={cap.id}
            style={{
              padding: '16px',
              borderRadius: '8px',
              border: '0.5px solid var(--rm-border-subtle)',
              opacity: cap.ready ? 1 : 0.45,
            }}
            title={cap.ready ? undefined : 'coming soon'}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                marginBottom: '8px',
              }}
            >
              <i
                className={`ti ti-${cap.icon}`}
                style={{
                  fontSize: '15px',
                  color: cap.ready ? 'var(--rm-accent-info)' : 'var(--rm-text-faint)',
                }}
                aria-hidden="true"
              />
              <span
                style={{
                  fontFamily: 'var(--rm-font-mono)',
                  fontSize: 'var(--rm-text-mono-data)',
                  color: cap.ready ? 'var(--rm-text-secondary)' : 'var(--rm-text-faint)',
                }}
              >
                {cap.label}
              </span>
            </div>
            <p
              style={{
                fontSize: '12px',
                lineHeight: 1.5,
                color: 'var(--rm-text-muted)',
                margin: 0,
              }}
            >
              {cap.description}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default CapabilityStrip;