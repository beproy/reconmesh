import { useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Search, ChevronLeft, ChevronRight, Users, ArrowLeft, ExternalLink, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  api,
  type AttackGroupListItem,
  type AttackGroupDetail,
} from '@/lib/api';

const PAGE_SIZE = 25;

// ============================================================================
// LIST VIEW — /groups
// ============================================================================
function GroupsList() {
  const navigate = useNavigate();
  const [searchInput, setSearchInput] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [page, setPage] = useState(1);

  const queryParams: Record<string, string> = {
    page: String(page),
    page_size: String(PAGE_SIZE),
  };
  if (activeSearch) queryParams.search = activeSearch;

  const { data: groups, isLoading } = useQuery<AttackGroupListItem[]>({
    queryKey: ['attack-groups', queryParams],
    queryFn: () => api.listAttackGroups(queryParams),
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setActiveSearch(searchInput.trim());
    setPage(1);
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">
          MITRE ATT&CK Groups
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Threat actor groups from the MITRE ATT&CK Enterprise framework.
        </p>
      </div>

      <form onSubmit={handleSearch} className="mb-6">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search by name, alias, or ATT&CK ID (e.g. APT29, G0016, Cozy Bear)"
              className="h-10 pl-10 text-sm"
              autoFocus
            />
          </div>
          <Button type="submit" size="default" className="h-10 px-5">
            Search
          </Button>
          {activeSearch && (
            <Button
              type="button"
              variant="ghost"
              size="default"
              className="h-10"
              onClick={() => {
                setSearchInput('');
                setActiveSearch('');
                setPage(1);
              }}
            >
              Clear
            </Button>
          )}
        </div>
      </form>

      {activeSearch && (
        <div className="mb-4">
          <Badge className="bg-primary/10 text-primary border-primary/20 text-xs">
            Searching: {activeSearch}
          </Badge>
        </div>
      )}

      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-muted-foreground">
                    ID
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-muted-foreground">
                    Name
                  </th>
                  <th className="hidden px-4 py-3 text-left text-xs font-medium uppercase text-muted-foreground md:table-cell">
                    Aliases
                  </th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i} className="border-b border-border/50">
                      <td colSpan={3} className="px-4 py-3">
                        <div className="h-4 w-full animate-pulse rounded bg-muted" />
                      </td>
                    </tr>
                  ))
                ) : !groups || groups.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-4 py-12 text-center text-muted-foreground">
                      {activeSearch ? `No groups matching "${activeSearch}"` : 'No groups found.'}
                    </td>
                  </tr>
                ) : (
                  groups.map((g) => (
                    <tr
                      key={g.attack_id}
                      className="cursor-pointer border-b border-border/50 transition-colors hover:bg-muted/30"
                      onClick={() => navigate(`/groups/${g.attack_id}`)}
                    >
                      <td className="px-4 py-3">
                        <Badge className="bg-primary/10 text-primary border-primary/20 font-mono text-xs">
                          {g.attack_id}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 font-medium text-foreground">
                        {g.name}
                      </td>
                      <td className="hidden px-4 py-3 text-xs text-muted-foreground md:table-cell">
                        {g.aliases && g.aliases.length > 1
                          ? g.aliases.filter((a) => a !== g.name).slice(0, 4).join(', ') +
                            (g.aliases.length > 5 ? ` +${g.aliases.length - 5} more` : '')
                          : '—'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {groups && groups.length > 0 && (
            <div className="flex items-center justify-between border-t border-border px-4 py-3">
              <span className="text-xs text-muted-foreground">
                Page {page}
                {groups.length < PAGE_SIZE && page === 1
                  ? ` · ${groups.length} groups`
                  : ''}
              </span>
              <div className="flex gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage(page - 1)}
                >
                  <ChevronLeft className="h-4 w-4" />
                  Prev
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!groups || groups.length < PAGE_SIZE}
                  onClick={() => setPage(page + 1)}
                >
                  Next
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// DETAIL VIEW — /groups/:attackId
// ============================================================================
function GroupDetail() {
  const { attackId } = useParams<{ attackId: string }>();

  const { data, isLoading, error } = useQuery<AttackGroupDetail>({
    queryKey: ['attack-group', attackId],
    queryFn: () => api.getAttackGroup(attackId!),
    enabled: !!attackId,
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

  if (error || !data) {
    return (
      <div>
        <Link
          to="/groups"
          className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Back to groups
        </Link>
        <Card>
          <CardContent className="py-12 text-center">
            <AlertCircle className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
            <div className="text-sm text-muted-foreground">
              {(error as Error)?.message || 'Group not found'}
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const mitreUrl = data.external_references.find(
    (r) => r.source_name === 'mitre-attack'
  )?.url;

  return (
    <div>
      <Link
        to="/groups"
        className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back to groups
      </Link>

      <div className="flex flex-wrap items-baseline gap-3">
        <Badge className="bg-primary/10 text-primary border-primary/20 font-mono">
          {data.attack_id}
        </Badge>
        <h1 className="text-3xl font-semibold tracking-tight">{data.name}</h1>
        {mitreUrl && (
          <a
            href={mitreUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            View on MITRE
            <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>

      {/* Aliases */}
      {data.aliases && data.aliases.length > 1 && (
        <Card className="mt-6">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Aliases</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-1.5">
            {data.aliases
              .filter((a) => a !== data.name)
              .map((alias) => (
                <Badge
                  key={alias}
                  className="bg-muted text-foreground border-border text-xs"
                >
                  {alias}
                </Badge>
              ))}
          </CardContent>
        </Card>
      )}

      {/* Description */}
      {data.description && (
        <Card className="mt-4">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Description</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-line text-sm leading-relaxed text-foreground">
              {data.description}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Related techniques */}
      <Card className="mt-4">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Users className="h-4 w-4 text-muted-foreground" />
            Techniques used
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {data.related_techniques.length}{' '}
              {data.related_techniques.length === 1 ? 'technique' : 'techniques'}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {data.related_techniques.length === 0 ? (
            <div className="text-sm text-muted-foreground">
              No techniques attributed to this group.
            </div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {data.related_techniques.map((t) => (
                <Link
                  key={t.attack_id}
                  to={`/techniques/${t.attack_id}`}
                  className="inline-flex items-center gap-1.5 rounded border border-border bg-muted/30 px-2 py-1 text-xs hover:border-primary hover:bg-primary/10"
                >
                  <span className="font-mono text-muted-foreground">
                    {t.attack_id}
                  </span>
                  <span className="text-foreground">{t.name}</span>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Related malware */}
      <Card className="mt-4">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            Malware used
            <span className="ml-2 text-xs font-normal text-muted-foreground">
              {data.related_malware.length}{' '}
              {data.related_malware.length === 1 ? 'family' : 'families'}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {data.related_malware.length === 0 ? (
            <div className="text-sm text-muted-foreground">
              No malware attributed to this group.
            </div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {data.related_malware.map((m) => (
                <span
                  key={m.attack_id}
                  className="inline-flex items-center gap-1.5 rounded border border-border bg-muted/30 px-2 py-1 text-xs"
                >
                  <span className="font-mono text-muted-foreground">
                    {m.attack_id}
                  </span>
                  <span className="text-foreground">{m.name}</span>
                </span>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// EXPORTS — one for each route
// ============================================================================
export function Groups() {
  return <GroupsList />;
}

export function Group() {
  return <GroupDetail />;
}
