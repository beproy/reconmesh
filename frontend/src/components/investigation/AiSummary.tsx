/**
 * AiSummary — AI-powered investigation summary panel.
 *
 * Calls the backend AI summary endpoint on-demand (user clicks a button),
 * then renders the structured response: sector assessment, risk summary,
 * enrichment highlights, relevant threat actors, and recommendation.
 */

import React, { useState } from 'react';
import { api } from '@/lib/api';
import type { AiSummaryResponse } from '@/lib/api';

interface AiSummaryProps {
  domainName: string;
  hasEnrichments: boolean;
}

const RISK_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  informational: '#64748b',
};

export const AiSummary: React.FC<AiSummaryProps> = ({ domainName, hasEnrichments }) => {
  const [data, setData] = useState<AiSummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.getAiSummary(domainName);
      if (result.error) {
        setError(result.error);
      } else {
        setData(result);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to generate AI summary';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  if (!hasEnrichments) return null;

  // Not yet generated — show the trigger button
  if (!data && !loading && !error) {
    return (
      <div style={{
        border: '0.5px solid var(--rm-border-subtle)',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '16px',
        background: 'var(--rm-bg-card, transparent)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <i className="ti ti-sparkles" style={{ fontSize: '16px', color: 'var(--rm-accent-info)' }} />
              <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--rm-text-primary)' }}>
                AI Analysis
              </span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--rm-text-muted)', margin: 0 }}>
              Generate a threat intelligence summary powered by AI.
            </p>
          </div>
          <button
            onClick={handleGenerate}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: '0.5px solid var(--rm-border-default)',
              background: 'transparent',
              color: 'var(--rm-text-primary)',
              fontSize: '12px',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <i className="ti ti-sparkles" style={{ fontSize: '13px' }} />
            Generate
          </button>
        </div>
      </div>
    );
  }

  // Loading state
  if (loading) {
    return (
      <div style={{
        border: '0.5px solid var(--rm-border-subtle)',
        borderRadius: '8px',
        padding: '24px',
        marginBottom: '16px',
        textAlign: 'center',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
          <i className="ti ti-sparkles" style={{
            fontSize: '16px',
            color: 'var(--rm-accent-info)',
            animation: 'pulse 1.5s infinite',
          }} />
          <span style={{ fontSize: '13px', color: 'var(--rm-text-muted)' }}>
            Analyzing enrichment data with AI...
          </span>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div style={{
        border: '0.5px solid #ef4444',
        borderRadius: '8px',
        padding: '16px',
        marginBottom: '16px',
      }}>
        <p style={{ fontSize: '13px', color: '#ef4444', margin: '0 0 8px' }}>
          AI summary failed: {error}
        </p>
        <button
          onClick={handleGenerate}
          style={{
            padding: '6px 12px',
            borderRadius: '4px',
            border: '0.5px solid var(--rm-border-default)',
            background: 'transparent',
            color: 'var(--rm-text-primary)',
            fontSize: '12px',
            cursor: 'pointer',
          }}
        >
          Retry
        </button>
      </div>
    );
  }

  if (!data) return null;

  const riskColor = RISK_COLORS[data.risk_summary.overall_risk] || '#64748b';

  return (
    <div style={{
      border: '0.5px solid var(--rm-border-subtle)',
      borderRadius: '8px',
      padding: '20px',
      marginBottom: '16px',
      background: 'var(--rm-bg-card, transparent)',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
        <i className="ti ti-sparkles" style={{ fontSize: '16px', color: 'var(--rm-accent-info)' }} />
        <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--rm-text-primary)' }}>
          AI Analysis
        </span>
        <span style={{
          fontSize: '11px',
          padding: '2px 8px',
          borderRadius: '4px',
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          color: riskColor,
          border: `1px solid ${riskColor}`,
        }}>
          {data.risk_summary.overall_risk} risk
        </span>
      </div>

      {/* Sector Assessment */}
      {data.sector_assessment.likely_sector && (
        <div style={{
          padding: '12px',
          borderRadius: '6px',
          border: '0.5px solid var(--rm-border-subtle)',
          marginBottom: '14px',
          fontSize: '13px',
        }}>
          <span style={{ color: 'var(--rm-text-muted)' }}>Sector: </span>
          <span style={{ color: 'var(--rm-text-primary)', fontWeight: 500 }}>
            {data.sector_assessment.likely_sector}
          </span>
          <span style={{ color: 'var(--rm-text-faint)', fontSize: '11px', marginLeft: '8px' }}>
            ({data.sector_assessment.confidence} confidence)
          </span>
          <p style={{ color: 'var(--rm-text-muted)', margin: '6px 0 0', fontSize: '12px' }}>
            {data.sector_assessment.reasoning}
          </p>
        </div>
      )}

      {/* Key Findings */}
      {data.risk_summary.key_findings.length > 0 && (
        <div style={{ marginBottom: '14px' }}>
          <h4 style={{ fontSize: '12px', fontWeight: 500, color: 'var(--rm-text-muted)', margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Key Findings
          </h4>
          {data.risk_summary.key_findings.map((f, i) => (
            <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '6px', fontSize: '12px', color: 'var(--rm-text-secondary)' }}>
              <span style={{ color: 'var(--rm-accent-info)', flexShrink: 0 }}>•</span>
              {f}
            </div>
          ))}
        </div>
      )}

      {/* Concerns & Positives side by side */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '14px' }}>
        {data.risk_summary.concerns.length > 0 && (
          <div>
            <h4 style={{ fontSize: '12px', fontWeight: 500, color: '#f97316', margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Concerns
            </h4>
            {data.risk_summary.concerns.map((c, i) => (
              <div key={i} style={{ fontSize: '12px', color: 'var(--rm-text-secondary)', marginBottom: '6px', display: 'flex', gap: '8px' }}>
                <span style={{ color: '#f97316', flexShrink: 0 }}>▲</span>
                {c}
              </div>
            ))}
          </div>
        )}
        {data.risk_summary.positives.length > 0 && (
          <div>
            <h4 style={{ fontSize: '12px', fontWeight: 500, color: '#22c55e', margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Positives
            </h4>
            {data.risk_summary.positives.map((p, i) => (
              <div key={i} style={{ fontSize: '12px', color: 'var(--rm-text-secondary)', marginBottom: '6px', display: 'flex', gap: '8px' }}>
                <span style={{ color: '#22c55e', flexShrink: 0 }}>✓</span>
                {p}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Relevant Threat Actors */}
      {data.relevant_threat_actors.length > 0 && (
        <div style={{ marginBottom: '14px' }}>
          <h4 style={{ fontSize: '12px', fontWeight: 500, color: 'var(--rm-text-muted)', margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Relevant Threat Actors ({data.relevant_threat_actors.length})
          </h4>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
            {data.relevant_threat_actors.map((actor) => (
              <a
                key={actor.attack_id}
                href={`/groups/${actor.attack_id}`}
                style={{
                  padding: '10px',
                  borderRadius: '6px',
                  border: '0.5px solid var(--rm-border-subtle)',
                  fontSize: '12px',
                  textDecoration: 'none',
                  color: 'inherit',
                  display: 'block',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                  <span style={{
                    fontFamily: 'var(--rm-font-mono)',
                    fontSize: '11px',
                    color: 'var(--rm-accent-info)',
                  }}>
                    {actor.attack_id}
                  </span>
                  <span style={{ fontWeight: 500, color: 'var(--rm-text-primary)' }}>
                    {actor.name}
                  </span>
                </div>
                <p style={{ margin: 0, color: 'var(--rm-text-muted)', fontSize: '11px', lineHeight: 1.4 }}>
                  {actor.relevance}
                </p>
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Recommendation */}
      {data.recommendation && (
        <div style={{
          padding: '12px',
          borderRadius: '6px',
          borderLeft: `3px solid var(--rm-accent-info)`,
          background: 'rgba(34, 211, 238, 0.05)',
          fontSize: '12px',
          color: 'var(--rm-text-secondary)',
          lineHeight: 1.5,
        }}>
          <strong style={{ color: 'var(--rm-text-primary)' }}>Recommendation: </strong>
          {data.recommendation}
        </div>
      )}
    </div>
  );
};
