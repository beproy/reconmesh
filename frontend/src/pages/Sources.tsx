import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { api, type SourceListItem } from '@/lib/api';
import { SourceCard, type SourceStatus } from '@/components/sources/SourceCard';
import { Skeleton } from '@/components/ui/skeleton';

// ----------------------------------------------------------------------------
// Static Ingesters Metadata
// The names match character-for-character and case-sensitively with the keys
// returned by the backend.
// ----------------------------------------------------------------------------
interface StaticIngester {
  name: string;
  description: string;
  upstreamUrl: string;
}

const STATIC_INGESTERS: StaticIngester[] = [
  {
    name: 'URLhaus',
    description: 'Database of malicious URLs that are being used for malware distribution.',
    upstreamUrl: 'https://urlhaus.abuse.ch/',
  },
  {
    name: 'OTX',
    description: 'AlienVault Open Threat Exchange open-source collaborative threat intelligence feed.',
    upstreamUrl: 'https://otx.alienvault.com/',
  },
  {
    name: 'ThreatFox',
    description: 'Platform that shares indicator of compromise (IOCs) associated with malware.',
    upstreamUrl: 'https://threatfox.abuse.ch/',
  },
  {
    name: 'Ransomware.live',
    description: 'Ransomware activities monitoring feed capturing negotiation, publication, and victims leaks.',
    upstreamUrl: 'https://www.ransomware.live/',
  },
];

export function Sources() {
  const { data, isLoading, error } = useQuery<SourceListItem[], Error>({
    queryKey: ['sources'],
    queryFn: () => api.listSources(),
  });

  return (
    <div style={{ padding: '0 24px 24px 24px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* Header Strip — visually identical to HeaderStrip.tsx structure */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '24px',
          padding: '24px 0 20px 0',
          borderBottom: '1px solid var(--rm-border-subtle)',
          marginBottom: '24px',
        }}
      >
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
              color: 'var(--rm-text-muted)',
              textDecoration: 'none',
              transition: 'background-color 120ms ease, color 120ms ease',
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLAnchorElement).style.backgroundColor =
                'var(--rm-bg-surface-hover)';
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
              color: 'var(--rm-text-primary)',
            }}
          >
            Sources
          </h1>
        </div>
      </div>

      {/* Description Paragraph */}
      <p
        style={{
          margin: '0 0 24px 0',
          fontSize: '14px',
          lineHeight: '1.6',
          color: 'var(--rm-text-secondary)',
        }}
      >
        Threat intelligence feeds and ingesters configured in the ReconMesh pipeline.
        Data is dynamically parsed and loaded into the database on regular schedules.
      </p>

      {/* Error notification block (does not break the rest of the page layout) */}
      {error && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '10px',
            backgroundColor: 'var(--rm-verdict-malicious-bg)',
            border: '1px solid var(--rm-border-subtle)',
            color: 'var(--rm-verdict-malicious-text)',
            fontSize: '13px',
            marginBottom: '24px',
          }}
        >
          Failed to fetch current ingestion states: {error.message}. Displaying cached structure.
        </div>
      )}

      {/* Loading Skeletons — uses shadcn <Skeleton> which has animate-pulse built in */}
      {isLoading && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '16px',
          }}
        >
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              style={{
                borderRadius: '10px',
                border: '1px solid var(--rm-border-subtle)',
                padding: '16px 18px',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
              }}
            >
              <Skeleton className="h-5 w-3/5" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-8 w-4/5" />
            </div>
          ))}
        </div>
      )}

      {/* Main Grid — 2x2 layout on desktop, responsive wrapper */}
      {!isLoading && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '16px',
          }}
        >
          {STATIC_INGESTERS.map((ingester) => {
            // Match the static metadata item with active API data
            const matchedApiSource = (data ?? []).find(
              (x) => x.name === ingester.name
            );

            const count = matchedApiSource ? matchedApiSource.indicator_count : null;
            
            // Healthy if the source is ingested and has more than 0 indicators.
            // If it is missing or has 0, render it as unknown / not yet run.
            const status: SourceStatus =
              count !== null && count > 0 ? 'healthy' : 'unknown';

            // TODO: Replace null with matchedApiSource.last_successful_ingestion_timestamp once
            // backend ingestion logs database tables/columns or endpoint fields are fully implemented.
            const lastIngested = null;

            return (
              <SourceCard
                key={ingester.name}
                name={ingester.name}
                description={ingester.description}
                indicatorCount={count}
                lastIngested={lastIngested}
                status={status}
                upstreamUrl={ingester.upstreamUrl}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
