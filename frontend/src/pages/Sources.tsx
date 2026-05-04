import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Database, ExternalLink } from 'lucide-react';
import { api, type SourceListItem } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

function SourceCard(props: { source: SourceListItem }) {
  const s = props.source;
  const count = s.indicator_count.toLocaleString();
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Database className="h-4 w-4 text-muted-foreground" />
          {s.name}
          <span className="ml-auto font-mono text-sm font-normal text-muted-foreground">
            {count} indicators
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 pt-0">
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>
            Type: <span className="text-foreground">{s.source_type}</span>
          </span>
          {s.url ? (
            <a
              href={s.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-foreground hover:underline"
            >
              Feed URL
              <ExternalLink className="h-3 w-3" />
            </a>
          ) : null}
        </div>
        {s.description ? (
          <p className="text-sm text-muted-foreground">{s.description}</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function Sources() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['sources'],
    queryFn: () => api.listSources(),
  });

  return (
    <div>
      <div className="flex items-baseline justify-between">
        <h1 className="text-3xl font-semibold tracking-tight">Sources</h1>
        <Link to="/" className="text-sm text-muted-foreground hover:text-foreground">
          Back to search
        </Link>
      </div>

      <p className="mt-2 text-sm text-muted-foreground">
        Threat intelligence feeds and other inputs ReconMesh has ingested data from.
      </p>

      <div className="mt-8 space-y-3">
        {isLoading ? (
          <>
            <Skeleton className="h-28 w-full" />
            <Skeleton className="h-28 w-full" />
          </>
        ) : null}

        {error ? (
          <Card>
            <CardContent className="py-8 text-center text-sm text-destructive">
              Failed to load sources: {error.message}
            </CardContent>
          </Card>
        ) : null}

        {data && data.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center text-sm text-muted-foreground">
              No sources ingested yet.
            </CardContent>
          </Card>
        ) : null}

        {data ? data.map((src) => <SourceCard key={src.id} source={src} />) : null}
      </div>
    </div>
  );
}
