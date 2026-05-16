/**
 * SummaryBlock.tsx
 *
 * The green-accented bulleted summary box on the investigation page.
 * Sits between HeaderStrip and MetricGrid.
 *
 *   ┌─────────────────────────────────────────────────┐
 *   │ › Registered 9,847 days ago to MarkMonitor.    │
 *   │ › Resolves to 14 IPs, hosted on Google LLC.    │
 *   │ › Strong email posture: SPF, DMARC, DKIM ok.   │
 *   │ › Clean across 94 VirusTotal engines.          │
 *   └─────────────────────────────────────────────────┘
 *
 * Sentences come from lib/summaryTemplate.ts (rule-based today; model-based
 * in Session 22+).
 */

import React from 'react';
import { buildSummary } from '@/lib/summaryTemplate';
import type { Domain } from '@/lib/api';

interface SummaryBlockProps {
  domain: Domain;
}

const ACCENT = 'rgb(74, 222, 128)'; // green-400

export const SummaryBlock: React.FC<SummaryBlockProps> = ({ domain }) => {
  const sentences = buildSummary(domain);

  // Empty state — no enrichments have run yet
  if (sentences.length === 0) {
    return (
      <div
        style={{
          padding: '16px 20px',
          borderRadius: '10px',
          border: '1px dashed rgba(148, 163, 184, 0.2)',
          backgroundColor: 'rgba(255, 255, 255, 0.01)',
          color: 'var(--rm-text-muted, rgb(148, 163, 184))',
          fontSize: '14px',
          marginBottom: '24px',
        }}
      >
        Click <strong style={{ color: 'rgb(241, 245, 249)' }}>Enrich</strong> to
        generate a summary from DNS, WHOIS, email security, reputation, and
        typosquat data.
      </div>
    );
  }

  return (
    <div
      style={{
        padding: '18px 22px',
        borderRadius: '10px',
        borderLeft: `3px solid ${ACCENT}`,
        backgroundColor: 'rgba(34, 197, 94, 0.04)',
        marginBottom: '24px',
      }}
    >
      <ul
        style={{
          margin: 0,
          padding: 0,
          listStyle: 'none',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
        }}
      >
        {sentences.map((sentence, idx) => (
          <li
            key={idx}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              color: 'var(--rm-text-primary, rgb(226, 232, 240))',
              fontSize: '14px',
              lineHeight: 1.55,
            }}
          >
            <span
              aria-hidden="true"
              style={{
                color: ACCENT,
                fontWeight: 600,
                fontSize: '16px',
                lineHeight: 1.4,
                flexShrink: 0,
              }}
            >
              ›
            </span>
            <span>{sentence}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};
