/**
 * Landing — the search-first investigation entrypoint.
 *
 * Composition (top to bottom):
 *   - Top nav: brand mark, version pill, sparse links
 *   - Hero section:
 *       - TopologyBackdrop (static SVG, behind everything)
 *       - Soft radial glow centered behind the search
 *       - FeedStatusPill
 *       - Headline + sub
 *       - SearchHero
 *       - SuggestedChips
 *   - CapabilityStrip (below the fold)
 *   - Footer: source list + repo link, both quiet
 *
 * State:
 *   - searchValue is lifted to this component because SuggestedChips
 *     needs to write to it (clicking a chip populates the input)
 *
 * Routing:
 *   - On submit, queryRouter decides the destination. Every kind
 *     currently maps to /domain/<value> because that's the only
 *     investigation page that exists.
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { TopologyBackdrop } from '../components/landing/TopologyBackdrop';
import { FeedStatusPill } from '../components/landing/FeedStatusPill';
import { SearchHero } from '../components/landing/SearchHero';
import { SuggestedChips } from '../components/landing/SuggestedChips';
import { SettingsDialog } from '../components/SettingsDialog';
import { CapabilityStrip } from '../components/landing/CapabilityStrip';
import { routeQuery } from '../lib/queryRouter';

export const Landing: React.FC = () => {
  const [searchValue, setSearchValue] = useState('');
  const navigate = useNavigate();

  const handleSubmit = (value: string) => {
    const target = routeQuery(value);
    navigate(target.path);
  };

  return (
    <div
      className="rm-canvas"
      style={{
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
      }}
    >
      <nav
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '16px 28px',
          borderBottom: '0.5px solid var(--rm-border-subtle)',
          position: 'relative',
          zIndex: 3,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <img
            src="/brand/favicon-192.png"
            alt="ReconMesh"
            style={{ width: '22px', height: '22px' }}
          />
          <span
            style={{
              fontSize: 'var(--rm-text-small)',
              fontWeight: 500,
              color: 'var(--rm-text-primary)',
              letterSpacing: '0.02em',
            }}
          >
            ReconMesh
          </span>
        </div>
        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          <a
            href="/domains"
            style={{
              fontSize: '12px',
              color: 'var(--rm-text-muted)',
              textDecoration: 'none',
            }}
          >
            Recent
          </a>
          <a
            href="/sources"
            style={{
              fontSize: '12px',
              color: 'var(--rm-text-muted)',
              textDecoration: 'none',
            }}
          >
            Sources
          </a>
          <a
            href="https://github.com/beproy/reconmesh"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              fontSize: '12px',
              color: 'var(--rm-text-muted)',
              textDecoration: 'none',
            }}
          >
            Docs
          </a>
          <SettingsDialog />
        </div>
      </nav>

      <main style={{ flex: 1 }}>
        <section
          style={{
            padding: '80px 28px 50px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            position: 'relative',
            minHeight: '460px',
          }}
        >
          <TopologyBackdrop />

          <div
            aria-hidden="true"
            style={{
              position: 'absolute',
              left: '50%',
              top: '45%',
              width: '600px',
              height: '400px',
              transform: 'translate(-50%, -50%)',
              background:
                'radial-gradient(circle, var(--rm-accent-glow) 0%, transparent 60%)',
              pointerEvents: 'none',
            }}
          />

          <div
            style={{
              position: 'relative',
              zIndex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              width: '100%',
            }}
          >
            <div style={{ marginBottom: '28px' }}>
              <FeedStatusPill />
            </div>

            <h1
              style={{
                fontSize: 'var(--rm-text-hero)',
                fontWeight: 500,
                color: 'var(--rm-text-primary)',
                margin: '0 0 14px',
                letterSpacing: '-0.025em',
                textAlign: 'center',
                lineHeight: 1.1,
              }}
            >
              Investigate any domain.
            </h1>
            <p
              style={{
                fontSize: 'var(--rm-text-body)',
                color: 'var(--rm-text-muted)',
                margin: '0 0 36px',
                textAlign: 'center',
                maxWidth: '480px',
                lineHeight: 1.5,
              }}
            >
              One search across malware feeds, ransomware leaks, certificate transparency,
              and DNS intelligence.
            </p>

            <SearchHero
              value={searchValue}
              onChange={setSearchValue}
              onSubmit={handleSubmit}
            />

            <SuggestedChips onPick={setSearchValue} />
          </div>
        </section>

        <div style={{ position: 'relative', zIndex: 2 }}>
          <CapabilityStrip />
        </div>
      </main>

      <footer
        style={{
          borderTop: '0.5px solid var(--rm-border-subtle)',
          padding: '14px 28px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <span
          className="rm-mono"
          style={{
            fontSize: 'var(--rm-text-label)',
            color: 'var(--rm-text-faint)',
            letterSpacing: '0.05em',
          }}
        >
          sources: urlhaus · otx · threatfox · ransomware.live
        </span>
        <a
          href="https://github.com/beproy/reconmesh"
          target="_blank"
          rel="noopener noreferrer"
          className="rm-mono"
          style={{
            fontSize: 'var(--rm-text-label)',
            color: 'var(--rm-text-faint)',
            textDecoration: 'none',
          }}
        >
          github.com/beproy/reconmesh
        </a>
      </footer>
    </div>
  );
};

export default Landing;
