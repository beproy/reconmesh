/**
 * HeaderStrip.tsx
 *
 * The top strip of the investigation page. Visually:
 *
 *   ← back   example.com               [• Worth investigating]   [Enrich]
 *
 * This is purely presentational. The enrich action is owned by DomainDetail
 * (because it manages the activeJobId state and TanStack mutation), and
 * passed in as `onEnrich`.
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { VerdictPill } from './VerdictPill';
import type { Verdict } from '@/lib/verdict';

interface HeaderStripProps {
  domainName: string;
  verdict: Verdict;
  hasEnrichments: boolean;
  onEnrich: () => void;
  isEnriching: boolean;
}

export const HeaderStrip: React.FC<HeaderStripProps> = ({
  domainName,
  verdict,
  hasEnrichments,
  onEnrich,
  isEnriching,
}) => {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '24px',
        padding: '24px 0 20px 0',
        borderBottom: '1px solid var(--rm-border-subtle, rgba(255,255,255,0.06))',
        marginBottom: '24px',
      }}
    >
      {/* Left cluster: back arrow + domain name */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', minWidth: 0 }}>
        <Link
          to="/"
          aria-label="Back to search"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            color: 'var(--rm-text-muted, rgb(148, 163, 184))',
            textDecoration: 'none',
            transition: 'background-color 120ms ease, color 120ms ease',
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLAnchorElement).style.backgroundColor =
              'rgba(255,255,255,0.04)';
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLAnchorElement).style.backgroundColor = 'transparent';
          }}
        >
          <ArrowLeft size={18} />
        </Link>

        <h1
          style={{
            margin: 0,
            fontSize: '28px',
            fontWeight: 600,
            letterSpacing: '-0.01em',
            color: 'var(--rm-text-primary, rgb(241, 245, 249))',
            fontFamily:
              'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          title={domainName}
        >
          {domainName}
        </h1>

        <VerdictPill verdict={verdict} />
      </div>

      {/* Right cluster: enrich button */}
      <div style={{ flexShrink: 0 }}>
        <Button
          onClick={onEnrich}
          disabled={isEnriching}
          variant={hasEnrichments ? 'outline' : 'default'}
          size="sm"
        >
          {isEnriching ? (
            <>
              <RefreshCw className="h-4 w-4 animate-spin" />
              Enriching…
            </>
          ) : (
            <>
              <RefreshCw className="h-4 w-4" />
              {hasEnrichments ? 'Re-enrich' : 'Enrich'}
            </>
          )}
        </Button>
      </div>
    </div>
  );
};
