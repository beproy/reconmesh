import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  RefreshCw,
  Globe,
  Shield,
  FileText,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Clock,
  Search,
} from 'lucide-react';
import {
  api,
  type Domain,
  type Enrichment,
  type DnsData,
  type EmailSecurityData,
  type WhoisData,
} from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';

// ----------------------------------------------------------------------------
// Helper: format a date string nicely, or '—' if null
// ----------------------------------------------------------------------------
function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ----------------------------------------------------------------------------
// Helper: status icon for enrichments
// ----------------------------------------------------------------------------
function StatusIcon(props: { status: string }) {
  if (props.status === 'ok') {
    return <CheckCircle2 className="h-4 w-4 text-green-500" />;
  }
  if (props.status === 'not_found') {
    return <Search className="h-4 w-4 text-muted-foreground" />;
  }
  if (props.status === 'timeout' || props.status === 'rate_limited') {
    return <Clock className="h-4 w-4 text-yellow-500" />;
  }
  return <XCircle className="h-4 w-4 text-destructive" />;
}

// ----------------------------------------------------------------------------
// Helper: confidence/TLP badge colors
// ----------------------------------------------------------------------------
function confidenceColor(c: string): string {
  switch (c) {
    case 'CONFIRMED':
      return 'bg-red-500/20 text-red-300 border-red-500/40';
    case 'HIGH':
      return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
    case 'MEDIUM':
      return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
    case 'LOW':
      return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
    default:
      return 'bg-muted text-muted-foreground border-border';
  }
}

function tlpColor(tlp: string): string {
  switch (tlp) {
    case 'RED':
      return 'bg-red-500/20 text-red-300 border-red-500/40';
    case 'AMBER_STRICT':
    case 'AMBER':
      return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    case 'GREEN':
      return 'bg-green-500/20 text-green-300 border-green-500/40';
    case 'CLEAR':
      return 'bg-muted text-muted-foreground border-border';
    default:
      return 'bg-muted text-muted-foreground border-border';
  }
}

function postureTierColor(tier: string): string {
  switch (tier) {
    case 'strong':
      return 'bg-green-500/20 text-green-300 border-green-500/40';
    case 'partial':
      return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
    case 'weak':
      return 'bg-red-500/20 text-red-300 border-red-500/40';
    default:
      return 'bg-muted text-muted-foreground border-border';
  }
}

// ----------------------------------------------------------------------------
// DNS section
// ----------------------------------------------------------------------------
function DnsSection(props: { enrichment: Enrichment }) {
  const [showAllTxt, setShowAllTxt] = useState(false);
  const data = props.enrichment.data as DnsData;

  if (props.enrichment.status === 'not_found') {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Globe className="h-4 w-4 text-muted-foreground" />
            DNS Records
            <StatusIcon status={props.enrichment.status} />
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Domain does not resolve (NXDOMAIN).
        </CardContent>
      </Card>
    );
  }

  const records = data.records || {};
  const txtRecords = records.TXT || [];
  const visibleTxt = showAllTxt ? txtRecords : txtRecords.slice(0, 3);

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Globe className="h-4 w-4 text-muted-foreground" />
          DNS Records
          <StatusIcon status={props.enrichment.status} />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 pt-0 text-sm">
        {(['A', 'AAAA', 'MX', 'NS', 'CNAME'] as const).map((rtype) => {
          const recs = records[rtype] || [];
          if (recs.length === 0) return null;
          return (
            <div key={rtype}>
              <div className="mb-1 text-xs font-medium uppercase text-muted-foreground">
                {rtype}
              </div>
              <div className="space-y-1">
                {recs.map((r, idx) => (
                  <div key={idx} className="font-mono text-xs">
                    {rtype === 'MX' ? `${r.preference} ${r.exchange}` : r.value}
                  </div>
                ))}
              </div>
            </div>
          );
        })}

        {txtRecords.length > 0 && (
          <div>
            <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase text-muted-foreground">
              TXT
              <span className="font-mono normal-case text-muted-foreground">
                ({txtRecords.length})
              </span>
            </div>
            <div className="space-y-1">
              {visibleTxt.map((r, idx) => (
                <div key={idx} className="break-all font-mono text-xs">
                  {r.text || r.value}
                </div>
              ))}
            </div>
            {txtRecords.length > 3 && (
              <button
                onClick={() => setShowAllTxt(!showAllTxt)}
                className="mt-2 text-xs text-muted-foreground hover:text-foreground"
              >
                {showAllTxt ? 'Show less' : `Show all ${txtRecords.length}`}
              </button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Email security section
// ----------------------------------------------------------------------------
function EmailSecuritySection(props: { enrichment: Enrichment }) {
  const data = props.enrichment.data as EmailSecurityData;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Shield className="h-4 w-4 text-muted-foreground" />
          Email Security
          <StatusIcon status={props.enrichment.status} />
          <span className="ml-auto">
            <Badge className={postureTierColor(data.posture?.tier || 'weak')}>
              {data.posture?.tier || 'unknown'} · {data.posture?.score || 0}/100
            </Badge>
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 pt-0 text-sm">
        {/* SPF */}
        <div>
          <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase text-muted-foreground">
            SPF
            {data.spf?.present ? (
              <Badge className="bg-green-500/20 text-green-300 border-green-500/40">
                present
              </Badge>
            ) : (
              <Badge className="bg-red-500/20 text-red-300 border-red-500/40">
                absent
              </Badge>
            )}
          </div>
          {data.spf?.raw && (
            <div className="break-all font-mono text-xs text-foreground">
              {data.spf.raw}
            </div>
          )}
        </div>

        {/* DMARC */}
        <div>
          <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase text-muted-foreground">
            DMARC
            {data.dmarc?.present ? (
              <Badge className="bg-green-500/20 text-green-300 border-green-500/40">
                present
              </Badge>
            ) : (
              <Badge className="bg-red-500/20 text-red-300 border-red-500/40">
                absent
              </Badge>
            )}
            {data.dmarc?.parsed?.policy && (
              <Badge className="bg-muted text-foreground border-border">
                p={data.dmarc.parsed.policy}
              </Badge>
            )}
          </div>
          {data.dmarc?.raw && (
            <div className="break-all font-mono text-xs text-foreground">
              {data.dmarc.raw}
            </div>
          )}
        </div>

        {/* DKIM */}
        <div>
          <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase text-muted-foreground">
            DKIM
            {data.dkim?.present ? (
              <Badge className="bg-green-500/20 text-green-300 border-green-500/40">
                {data.dkim.selectors_found.length} selector
                {data.dkim.selectors_found.length === 1 ? '' : 's'}
              </Badge>
            ) : (
              <Badge className="bg-muted text-muted-foreground border-border">
                none at common selectors
              </Badge>
            )}
          </div>
          {data.dkim?.selectors_found && data.dkim.selectors_found.length > 0 && (
            <div className="font-mono text-xs">
              {data.dkim.selectors_found.join(', ')}
            </div>
          )}
        </div>

        {/* Posture notes */}
        {data.posture?.notes && data.posture.notes.length > 0 && (
          <div className="rounded border border-border/50 bg-muted/30 p-3">
            <div className="mb-1 text-xs font-medium uppercase text-muted-foreground">
              Notes
            </div>
            <ul className="space-y-1 text-xs">
              {data.posture.notes.map((note, idx) => (
                <li key={idx} className="text-muted-foreground">
                  · {note}
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ----------------------------------------------------------------------------
// WHOIS section
// ----------------------------------------------------------------------------
function WhoisSection(props: { enrichment: Enrichment }) {
  const [showStatusFlags, setShowStatusFlags] = useState(false);
  const data = props.enrichment.data as WhoisData;

  if (props.enrichment.status !== 'ok') {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <FileText className="h-4 w-4 text-muted-foreground" />
            WHOIS
            <StatusIcon status={props.enrichment.status} />
            <Badge className="ml-auto bg-muted text-muted-foreground border-border text-xs">
              {props.enrichment.status}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          {props.enrichment.status === 'not_found'
            ? 'No WHOIS record available for this domain.'
            : props.enrichment.status === 'rate_limited'
            ? 'WHOIS server rate-limited the request. Try again later.'
            : 'WHOIS lookup did not succeed.'}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <FileText className="h-4 w-4 text-muted-foreground" />
          WHOIS
          <StatusIcon status={props.enrichment.status} />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 pt-0 text-sm">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <div className="text-xs uppercase text-muted-foreground">Registrar</div>
            <div className="text-foreground">{data.registrar || '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase text-muted-foreground">
              Registrant org
            </div>
            <div className="text-foreground">{data.registrant_org || '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase text-muted-foreground">
              Registered
            </div>
            <div className="text-foreground">{fmtDate(data.creation_date)}</div>
          </div>
          <div>
            <div className="text-xs uppercase text-muted-foreground">Expires</div>
            <div className="text-foreground">{fmtDate(data.expiration_date)}</div>
          </div>
          <div>
            <div className="text-xs uppercase text-muted-foreground">Country</div>
            <div className="text-foreground">{data.registrant_country || '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase text-muted-foreground">DNSSEC</div>
            <div className="text-foreground">{data.dnssec || '—'}</div>
          </div>
        </div>

        {data.name_servers && data.name_servers.length > 0 && (
          <div>
            <div className="mb-1 text-xs uppercase text-muted-foreground">
              Name servers
            </div>
            <div className="space-y-0.5 font-mono text-xs">
              {data.name_servers.map((ns, idx) => (
                <div key={idx}>{ns}</div>
              ))}
            </div>
          </div>
        )}

        {data.status && data.status.length > 0 && (
          <div>
            <button
              onClick={() => setShowStatusFlags(!showStatusFlags)}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              {showStatusFlags ? 'Hide' : 'Show'} {data.status.length} status flag
              {data.status.length === 1 ? '' : 's'}
            </button>
            {showStatusFlags && (
              <div className="mt-2 space-y-0.5 font-mono text-xs text-muted-foreground">
                {data.status.map((s, idx) => (
                  <div key={idx} className="break-all">
                    {s}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Main page component
// ----------------------------------------------------------------------------
export function DomainDetail() {
  const { name } = useParams<{ name: string }>();
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<Domain>({
    queryKey: ['domain', name],
    queryFn: () => api.getDomain(name!),
    enabled: !!name,
  });

  const enrichMutation = useMutation({
    mutationFn: () => api.enrichDomain(name!),
    onSuccess: () => {
      // Refetch the domain to pick up the new enrichments
      queryClient.invalidateQueries({ queryKey: ['domain', name] });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <Link
          to="/"
          className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Back to search
        </Link>
        <Card>
          <CardContent className="py-12 text-center">
            <AlertCircle className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
            <div className="text-sm text-muted-foreground">
              {(error as Error).message || 'Domain not found'}
            </div>
            <Button
              onClick={() => enrichMutation.mutate()}
              disabled={enrichMutation.isPending}
              className="mt-4"
              size="sm"
            >
              {enrichMutation.isPending ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  Running enrichers...
                </>
              ) : (
                <>
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Enrich {name}
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!data) return null;

  const dnsEnrichment = data.enrichments.find((e) => e.enrichment_type === 'dns');
  const emailSecEnrichment = data.enrichments.find(
    (e) => e.enrichment_type === 'email_security'
  );
  const whoisEnrichment = data.enrichments.find((e) => e.enrichment_type === 'whois');

  return (
    <div>
      <Link
        to="/"
        className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back to search
      </Link>

      {/* Header row: domain name + indicator count + enrich button */}
      <div className="flex items-center gap-4">
        <div className="flex items-baseline gap-3">
          <h1 className="font-mono text-3xl font-semibold tracking-tight">
            {data.name}
          </h1>
          <span className="text-sm text-muted-foreground">
            {data.indicators.length} indicator
            {data.indicators.length === 1 ? '' : 's'}
          </span>
        </div>
        <div className="ml-auto">
          <Button
            onClick={() => enrichMutation.mutate()}
            disabled={enrichMutation.isPending}
            size="sm"
          >
            {enrichMutation.isPending ? (
              <>
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                Running enrichers...
              </>
            ) : (
              <>
                <RefreshCw className="mr-2 h-4 w-4" />
                {data.enrichments.length > 0 ? 'Re-enrich' : 'Enrich'}
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Overview card */}
      <Card className="mt-6">
        <CardHeader>
          <CardTitle className="text-base">Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-3">
            <div>
              <div className="text-xs uppercase text-muted-foreground">TLD</div>
              <div className="font-mono">{data.tld || '—'}</div>
            </div>
            <div>
              <div className="text-xs uppercase text-muted-foreground">First seen</div>
              <div>{fmtDate(data.first_seen)}</div>
            </div>
            <div>
              <div className="text-xs uppercase text-muted-foreground">Last seen</div>
              <div>{fmtDate(data.last_seen)}</div>
            </div>
            <div>
              <div className="text-xs uppercase text-muted-foreground">Registrar</div>
              <div>{data.registrar || '—'}</div>
            </div>
            <div>
              <div className="text-xs uppercase text-muted-foreground">Risk score</div>
              <div>{data.risk_score ?? '—'}</div>
            </div>
            <div>
              <div className="text-xs uppercase text-muted-foreground">
                Indicators
              </div>
              <div>{data.indicators.length}</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Enrichment error display */}
      {enrichMutation.isError && (
        <Card className="mt-4 border-destructive/50">
          <CardContent className="py-3 text-sm text-destructive">
            Enrichment failed: {(enrichMutation.error as Error).message}
          </CardContent>
        </Card>
      )}

      {/* Enrichment sections */}
      {data.enrichments.length === 0 ? (
        <Card className="mt-6">
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No enrichment data yet. Click Enrich to run DNS, email security, and
            WHOIS lookups.
          </CardContent>
        </Card>
      ) : (
        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
          {dnsEnrichment && <DnsSection enrichment={dnsEnrichment} />}
          {emailSecEnrichment && (
            <EmailSecuritySection enrichment={emailSecEnrichment} />
          )}
          {whoisEnrichment && (
            <div className="lg:col-span-2">
              <WhoisSection enrichment={whoisEnrichment} />
            </div>
          )}
        </div>
      )}

      {/* Indicators section */}
      {data.indicators.length > 0 && (
        <div className="mt-8">
          <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Indicators
          </h2>
          <div className="space-y-3">
            {data.indicators.map((ind) => (
              <Card key={ind.id}>
                <CardContent className="py-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className="bg-muted text-foreground border-border font-mono text-xs uppercase">
                      {ind.indicator_type}
                    </Badge>
                    <span className="break-all font-mono text-sm">{ind.value}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-1">
                    <Badge className={`${confidenceColor(ind.confidence)} text-xs`}>
                      confidence: {ind.confidence.toLowerCase()}
                    </Badge>
                    <Badge className={`${tlpColor(ind.tlp)} text-xs`}>
                      tlp: {ind.tlp.toLowerCase().replace('_', ' ')}
                    </Badge>
                    <Badge className="bg-muted text-muted-foreground border-border text-xs">
                      {ind.is_active ? 'active' : 'inactive'}
                    </Badge>
                  </div>
                  {ind.tags.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {ind.tags.map((tag, idx) => (
                        <Badge
                          key={idx}
                          className="bg-muted/50 text-muted-foreground border-border font-mono text-xs"
                        >
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  )}
                  <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <span>
                      Source:{' '}
                      <span className="text-foreground">{ind.source.name}</span>
                    </span>
                    <span>First seen: {fmtDate(ind.first_seen)}</span>
                    <span>Last seen: {fmtDate(ind.last_seen)}</span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
