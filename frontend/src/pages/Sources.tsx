import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Database,
  ExternalLink,
  Rss,
  FileText,
  User,
  ShieldAlert,
  Layers,
} from 'lucide-react';
import { api, type SourceListItem } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';

// Map source_type strings to icons + display labels.
// Source types come from the SourceType enum in models.py.
const SOURCE_TYPE_META: Record<string, { icon: typeof Database; label: string }> = {
  feed: { icon: Rss, label: 'Feed' },
  report: { icon: FileText, label: 'Report' },
  manual: { icon: User, label: 'Manual' },
  misp_event: { icon: ShieldAlert, label: 'MISP event' },
  stix_bundle: { icon: Layers, label: 'STIX bundle' },
};

function getMeta(sourceType: string) {
  return SOURCE_TYPE_META[sourceType] || { icon: Database, label: sourceType };
}

// ----------------------------------------------------------------------------
// One source card
// ----------------------------------------------------------------------------
function SourceCard(props: { source: SourceListItem }) {
  const s = props.source;
  const meta = getMeta(s.source_type);
  const Icon = meta.icon;

  return (
    <Card className="transition-colors hover:border-primary/40">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-start gap-3 text-base">
          <Icon className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" />
          <div className="flex-1 min-w-0">
            <div className="flex items-baseline gap-2">
              <span className="font-medium text-foreground">{s.name}</span>
              <Badge className="bg-muted text-muted-foreground border-border text-xs">
                {meta.label}
              </Badge>
            </div>
          </div>
          <div className="shrink-0 text-right">
            <div className="font-mono text-lg font-semibold text-foreground">
              {s.indicator_count.toLocaleString()}
            </div>
            <div className="text-xs text-muted-foreground">indicators</div>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 pt-0">
        {s.description && (
          <p className="text-sm text-muted-foreground">{s.description}</p>
        )}
        {s.url && (
          <a
            href={s.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <ExternalLink className="h-3 w-3" />
            <span className="break-all">{s.url}</span>
          </a>
        )}
      </CardContent>
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Page
// ----------------------------------------------------------------------------
export function Sources() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['sources'],
    queryFn: () => api.listSources(),
  });

  // Group sources by source_type for cleaner presentation when there are many.
  // For each group we precompute the total indicator count.
  const grouped = (data ?? []).reduce<Record<string, SourceListItem[]>>(
    (acc, src) => {
      const key = src.source_type;
      if (!acc[key]) acc[key] = [];
      acc[key].push(src);
      return acc;
    },
    {}
  );

  // Order: feed first, then stix_bundle (MITRE), then the rest by name.
  const typeOrder = ['feed', 'stix_bundle', 'misp_event', 'report', 'manual'];
  const orderedKeys = Object.keys(grouped).sort((a, b) => {
    const ai = typeOrder.indexOf(a);
    const bi = typeOrder.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });

  const totalIndicators = (data ?? []).reduce(
    (sum, s) => sum + s.indicator_count,
    0
  );

  return (
    <div>
      <div className="flex items-baseline justify-between">
        <h1 className="text-3xl font-semibold tracking-tight">Sources</h1>
        <Link
          to="/"
          className="text-sm text-muted-foreground hover:text-foreground"
        >
          Back to search
        </Link>
      </div>

      <p className="mt-2 text-sm text-muted-foreground">
        Threat intelligence feeds and other inputs ReconMesh has ingested data from.
        {data && data.length > 0 && (
          <span>
            {' '}
            <span className="font-mono text-foreground">
              {data.length}
            </span>{' '}
            source{data.length === 1 ? '' : 's'} ·{' '}
            <span className="font-mono text-foreground">
              {totalIndicators.toLocaleString()}
            </span>{' '}
            indicators total.
          </span>
        )}
      </p>

      <div className="mt-8 space-y-6">
        {isLoading && (
          <div className="space-y-3">
            <Skeleton className="h-28 w-full" />
            <Skeleton className="h-28 w-full" />
          </div>
        )}

        {error && (
          <Card>
            <CardContent className="py-8 text-center text-sm text-destructive">
              Failed to load sources: {(error as Error).message}
            </CardContent>
          </Card>
        )}

        {data && data.length === 0 && (
          <Card>
            <CardContent className="py-12 text-center text-sm text-muted-foreground">
              No sources ingested yet.
            </CardContent>
          </Card>
        )}

        {data &&
          data.length > 0 &&
          orderedKeys.map((key) => {
            const sources = grouped[key];
            const meta = getMeta(key);
            return (
              <div key={key}>
                <h2 className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  <meta.icon className="h-3.5 w-3.5" />
                  {meta.label}
                  <span className="font-mono normal-case">
                    ({sources.length})
                  </span>
                </h2>
                <div className="space-y-3">
                  {sources.map((src) => (
                    <SourceCard key={src.id} source={src} />
                  ))}
                </div>
              </div>
            );
          })}
      </div>
    </div>
  );
}
