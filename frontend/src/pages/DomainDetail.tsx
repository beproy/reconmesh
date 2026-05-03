import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, AlertCircle, FileQuestion } from 'lucide-react';
import { api, ApiError, type Indicator, type Domain as DomainData } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function confidenceColor(c: Indicator['confidence']): string {
  switch (c) {
    case 'confirmed': return 'bg-red-600/20 text-red-300 border-red-600/40';
    case 'high':      return 'bg-orange-600/20 text-orange-300 border-orange-600/40';
    case 'medium':    return 'bg-yellow-600/20 text-yellow-300 border-yellow-600/40';
    case 'low':       return 'bg-slate-600/20 text-slate-300 border-slate-600/40';
  }
}

function tlpColor(t: Indicator['tlp']): string {
  switch (t) {
    case 'red':          return 'bg-red-600/20 text-red-300 border-red-600/40';
    case 'amber+strict': return 'bg-amber-700/20 text-amber-200 border-amber-700/40';
    case 'amber':        return 'bg-amber-600/20 text-amber-300 border-amber-600/40';
    case 'green':        return 'bg-green-600/20 text-green-300 border-green-600/40';
    case 'clear':        return 'bg-slate-700/30 text-slate-300 border-slate-700/40';
  }
}

export function DomainDetail() {
  const { name = '' } = useParams<{ name: string }>();
  const decoded = decodeURIComponent(name);

  const { data, isLoading, error } = useQuery({
    queryKey: ['domain', decoded],
    queryFn: () => api.getDomain(decoded),
    retry: false,
  });

  return (
    <div>
      <Link
        to="/"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to search
      </Link>

      <div className="mt-4 flex items-baseline gap-3">
        <h1 className="font-mono text-3xl font-semibold tracking-tight text-foreground">
          {decoded}
        </h1>
        {data && (
          <span className="text-sm text-muted-foreground">
            {data.indicators.length} indicator{data.indicators.length === 1 ? '' : 's'}
          </span>
        )}
      </div>

      <div className="mt-8">
        {isLoading && <DomainSkeleton />}
        {error && <DomainError error={error} />}
        {data && <DomainBody data={data} />}
      </div>
    </div>
  );
}

function DomainSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-32 w-full" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-24 w-full" />
    </div>
  );
}

function DomainError({ error }: { error: Error }) {
  if (error instanceof ApiError && error.status === 404) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
          <FileQuestion className="h-10 w-10 text-muted-foreground" />
          <h2 className="text-lg font-semibold">No data on this domain yet</h2>
          <p className="max-w-md text-sm text-muted-foreground">
            ReconMesh hasn't seen this domain in any of the threat feeds it's
            ingested. That doesn't mean it's safe — just that there's nothing to
            report.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <AlertCircle className="h-10 w-10 text-destructive" />
        <h2 className="text-lg font-semibold">Something went wrong</h2>
        <p className="max-w-md text-sm text-muted-foreground">
          {error.message}
        </p>
        <Button asChild variant="outline" size="sm" className="mt-2">
          <Link to="/">Back to search</Link>
        </Button>
      </CardContent>
    </Card>
  );
}

function DomainBody({ data }: { data: DomainData }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Overview</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-3">
          <Field label="TLD" value={data.tld ?? '—'} />
          <Field label="First seen" value={formatDate(data.first_seen)} />
          <Field label="Last seen" value={formatDate(data.last_seen)} />
          <Field label="Registrar" value={data.registrar ?? '—'} />
          <Field label="Risk score" value={data.risk_score?.toString() ?? '—'} />
          <Field label="Indicators" value={data.indicators.length.toString()} />
        </CardContent>
      </Card>

      {data.indicators.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            This domain is in our database but has no indicators linked to it yet.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
            Indicators
          </h2>
          {data.indicators.map((ind) => (
            <IndicatorCard key={ind.id} indicator={ind} />
          ))}
        </div>
      )}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 text-foreground">{value}</div>
    </div>
  );
}

function IndicatorCard({ indicator }: { indicator: Indicator }) {
  return (
    <Card>
      <CardContent className="space-y-3 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="font-mono uppercase">
            {indicator.indicator_type}
          </Badge>
          <span className="break-all font-mono text-sm text-foreground">
            {indicator.value}
          </span>
        </div>

        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className={confidenceColor(indicator.confidence)}>
            confidence: {indicator.confidence}
          </Badge>
          <Badge variant="outline" className={tlpColor(indicator.tlp)}>
            tlp: {indicator.tlp}
          </Badge>
          {!indicator.is_active && (
            <Badge variant="outline" className="bg-slate-700/30 text-slate-400">
              inactive
            </Badge>
          )}
        </div>

        {indicator.tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {indicator.tags.map((tag) => (
              <Badge key={tag} variant="secondary" className="font-mono text-xs">
                {tag}
              </Badge>
            ))}
          </div>
        )}

        <div className="flex flex-wrap gap-x-6 gap-y-1 pt-2 text-xs text-muted-foreground">
          <span>Source: <span className="text-foreground">{indicator.source.name}</span></span>
          <span>First seen: {formatDate(indicator.first_seen)}</span>
          <span>Last seen: {formatDate(indicator.last_seen)}</span>
        </div>
      </CardContent>
    </Card>
  );
}