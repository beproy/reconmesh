import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Search, ChevronLeft, ChevronRight, ArrowUpDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { api, type DomainListItem } from '@/lib/api';

const PAGE_SIZE = 25;

type SortField = 'name' | 'indicator_count' | 'enrichment_count' | 'first_seen' | 'last_seen';

export function Home() {
  const navigate = useNavigate();

  // Search / filter / sort / pagination state
  const [searchInput, setSearchInput] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [filterIndicators, setFilterIndicators] = useState<string>('all');
  const [filterEnrichments, setFilterEnrichments] = useState<string>('all');
  const [sortBy, setSortBy] = useState<SortField>('indicator_count');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);

  // Build query params
  const queryParams: Record<string, string> = {
    page: String(page),
    page_size: String(PAGE_SIZE),
    sort_by: sortBy,
    sort_dir: sortDir,
  };
  if (activeSearch) queryParams.search = activeSearch;
  if (filterIndicators === 'yes') queryParams.has_indicators = 'true';
  if (filterIndicators === 'no') queryParams.has_indicators = 'false';
  if (filterEnrichments === 'yes') queryParams.has_enrichments = 'true';
  if (filterEnrichments === 'no') queryParams.has_enrichments = 'false';

  const { data: domains, isLoading } = useQuery<DomainListItem[]>({
    queryKey: ['domains', queryParams],
    queryFn: () => api.listDomains(queryParams),
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = searchInput.trim().toLowerCase();
    // If it looks like an exact domain (has a dot), navigate to dossier
    if (trimmed && trimmed.includes('.')) {
      navigate(`/domains/${encodeURIComponent(trimmed)}`);
      return;
    }
    // Otherwise, filter the list
    setActiveSearch(trimmed);
    setPage(1);
  };

  const toggleSort = (field: SortField) => {
    if (sortBy === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortDir(field === 'name' ? 'asc' : 'desc');
    }
    setPage(1);
  };

  const SortHeader = (props: { field: SortField; label: string; className?: string }) => (
    <button
      onClick={() => toggleSort(props.field)}
      className={`flex items-center gap-1 text-xs font-medium uppercase text-muted-foreground hover:text-foreground ${props.className || ''}`}
    >
      {props.label}
      {sortBy === props.field && (
        <ArrowUpDown className="h-3 w-3" />
      )}
    </button>
  );

  return (
    <div>
      {/* Hero + search */}
      <div className="mb-8 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">
          Domain-centric threat intelligence
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Search a specific domain or browse all domains below.
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
              placeholder="Search domains (e.g. paypal) or enter exact domain (e.g. evil.example.com)"
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

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-4 text-sm">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Indicators:</span>
          <select
            value={filterIndicators}
            onChange={(e) => { setFilterIndicators(e.target.value); setPage(1); }}
            className="rounded border border-border bg-background px-2 py-1 text-xs"
          >
            <option value="all">All</option>
            <option value="yes">Has indicators</option>
            <option value="no">No indicators</option>
          </select>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Enrichments:</span>
          <select
            value={filterEnrichments}
            onChange={(e) => { setFilterEnrichments(e.target.value); setPage(1); }}
            className="rounded border border-border bg-background px-2 py-1 text-xs"
          >
            <option value="all">All</option>
            <option value="yes">Enriched</option>
            <option value="no">Not enriched</option>
          </select>
        </div>
        {activeSearch && (
          <Badge className="bg-primary/10 text-primary border-primary/20 text-xs">
            Searching: {activeSearch}
          </Badge>
        )}
      </div>

      {/* Domain table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 py-3 text-left">
                    <SortHeader field="name" label="Domain" />
                  </th>
                  <th className="px-4 py-3 text-left">
                    <span className="text-xs font-medium uppercase text-muted-foreground">TLD</span>
                  </th>
                  <th className="px-4 py-3 text-right">
                    <SortHeader field="indicator_count" label="Indicators" className="justify-end" />
                  </th>
                  <th className="px-4 py-3 text-right">
                    <SortHeader field="enrichment_count" label="Enrichments" className="justify-end" />
                  </th>
                  <th className="hidden px-4 py-3 text-left md:table-cell">
                    <SortHeader field="first_seen" label="First seen" />
                  </th>
                  <th className="hidden px-4 py-3 text-left lg:table-cell">
                    <SortHeader field="last_seen" label="Last seen" />
                  </th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i} className="border-b border-border/50">
                      <td colSpan={6} className="px-4 py-3">
                        <div className="h-4 w-full animate-pulse rounded bg-muted" />
                      </td>
                    </tr>
                  ))
                ) : !domains || domains.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-12 text-center text-muted-foreground">
                      {activeSearch
                        ? `No domains matching "${activeSearch}"`
                        : 'No domains in the database yet. Ingest a feed to get started.'}
                    </td>
                  </tr>
                ) : (
                  domains.map((d) => (
                    <tr
                      key={d.id}
                      className="border-b border-border/50 transition-colors hover:bg-muted/30 cursor-pointer"
                      onClick={() => navigate(`/domains/${encodeURIComponent(d.name)}`)}
                    >
                      <td className="px-4 py-3">
                        <Link
                          to={`/domains/${encodeURIComponent(d.name)}`}
                          className="font-mono text-sm text-foreground hover:text-primary"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {d.name}
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <Badge className="bg-muted text-muted-foreground border-border text-xs">
                          {d.tld || '—'}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-sm">
                        {d.indicator_count > 0 ? (
                          <span className="text-foreground">{d.indicator_count}</span>
                        ) : (
                          <span className="text-muted-foreground">0</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {d.enrichment_count > 0 ? (
                          <Badge className="bg-green-500/20 text-green-300 border-green-500/40 text-xs">
                            {d.enrichment_count}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="hidden px-4 py-3 text-xs text-muted-foreground md:table-cell">
                        {d.first_seen
                          ? new Date(d.first_seen).toLocaleDateString()
                          : '—'}
                      </td>
                      <td className="hidden px-4 py-3 text-xs text-muted-foreground lg:table-cell">
                        {d.last_seen
                          ? new Date(d.last_seen).toLocaleDateString()
                          : '—'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {domains && domains.length > 0 && (
            <div className="flex items-center justify-between border-t border-border px-4 py-3">
              <span className="text-xs text-muted-foreground">
                Page {page}
                {domains.length < PAGE_SIZE && page === 1
                  ? ` · ${domains.length} domains`
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
                  disabled={!domains || domains.length < PAGE_SIZE}
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

      <p className="mt-4 text-center text-xs text-muted-foreground">
        Tip: click any domain row to see its full dossier. Use the Sources page to see ingested feeds.
      </p>
    </div>
  );
}