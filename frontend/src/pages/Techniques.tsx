import { useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Search, ChevronLeft, ChevronRight, Target, ArrowLeft, ExternalLink, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  api,
  type AttackTechniqueListItem,
  type AttackTechniqueDetail,
} from '@/lib/api';

const PAGE_SIZE = 25;

// Display labels for the ATT&CK tactic phase names
const TACTIC_LABELS: Record<string, string> = {
  'reconnaissance': 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command and Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

function formatTactic(t: string): string {
  return TACTIC_LABELS[t] || t;
}

// ============================================================================
// LIST VIEW — /techniques
// ============================================================================
function TechniquesList() {
  const navigate = useNavigate();
  const [searchInput, setSearchInput] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [page, setPage] = useState(1);

  const queryParams: Record<string, string> = {
    page: String(page),
    page_size: String(PAGE_SIZE),
  };
  if (activeSearch) queryParams.search = activeSearch;

  const { data: techniques, isLoading } = useQuery<AttackTechniqueListItem[]>({
    queryKey: ['attack-techniques', queryParams],
    queryFn: () => api.listAttackTechniques(queryParams),
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
          MITRE ATT&CK Techniques
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Techniques and sub-techniques from the MITRE ATT&CK Enterprise framework.
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
              placeholder="Search by name or ATT&CK ID (e.g. Phishing, T1566, T1566.001)"
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
                    Tactics
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
                ) : !techniques || techniques.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-4 py-12 text-center text-muted-foreground">
                      {activeSearch ? `No techniques matching "${activeSearch}"` : 'No techniques found.'}
                    </td>
                  </tr>
                ) : (
                  techniques.map((t) => (
                    <tr
                      key={t.attack_id}
                      className="cursor-pointer border-b border-border/50 transition-colors hover:bg-muted/30"
                      onClick={() => navigate(`/techniques/${t.attack_id}`)}
                    >
                      <td className="px-4 py-3">
                        <Badge
                          className={
                            t.is_subtechnique
                              ? 'bg-muted text-muted-foreground border-border font-mono text-xs'
                              : 'bg-primary/10 text-primary border-primary/20 font-mono text-xs'
                          }
                        >
                          {t.attack_id}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-foreground">
                          {t.is_subtechnique && (
                            <span className="text-muted-foreground">↳ </span>
                          )}
                          {t.name}
                        </div>
                      </td>
                      <td className="hidden px-4 py-3 md:table-cell">
                        <div className="flex flex-wrap gap-1">
                          {t.tactics.slice(0, 3).map((tac) => (
                            <Badge
                              key={tac}
                              className="bg-muted/50 text-muted-foreground border-border text-xs"
                            >
                              {formatTactic(tac)}
                            </Badge>
                          ))}
                          {t.tactics.length > 3 && (
                            <span className="text-xs text-muted-foreground">
                              +{t.tactics.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {techniques && techniques.length > 0 && (
            <div className="flex items-center justify-between border-t border-border px-4 py-3">
              <span className="text-xs text-muted-foreground">
                Page {page}
                {techniques.length < PAGE_SIZE && page === 1
                  ? ` · ${techniques.length} techniques`
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
                  disabled={!techniques || techniques.length < PAGE_SIZE}
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
// DETAIL VIEW — /techniques/:attackId
// ============================================================================
function TechniqueDetail() {
  const { attackId } = useParams<{ attackId: string }>();

  const { data, isLoading, error } = useQuery<AttackTechniqueDetail>({
    queryKey: ['attack-technique', attackId],
    queryFn: () => api.getAttackTechnique(attackId!),
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
          to="/techniques"
          className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Back to techniques
        </Link>
        <Card>
          <CardContent className="py-12 text-center">
            <AlertCircle className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
            <div className="text-sm text-muted-foreground">
              {(error as Error)?.message || 'Technique not found'}
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
        to="/techniques"
        className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back to techniques
      </Link>

      <div className="flex flex-wrap items-baseline gap-3">
        <Badge
          className={
            data.is_subtechnique
              ? 'bg-muted text-muted-foreground border-border font-mono'
              : 'bg-primary/10 text-primary border-primary/20 font-mono'
          }
        >
          {data.attack_id}
        </Badge>
        <h1 className="text-3xl font-semibold tracking-tight">{data.name}</h1>
        {data.is_subtechnique && (
          <Badge className="bg-muted/50 text-muted-foreground border-border text-xs">
            Sub-technique
          </Badge>
        )}
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

      {/* Overview */}
      <Card className="mt-6">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div>
              <div className="text-xs uppercase text-muted-foreground">Tactics</div>
              <div className="mt-1 flex flex-wrap gap-1">
                {data.tactics.length === 0 ? (
                  <span className="text-sm text-muted-foreground">—</span>
                ) : (
                  data.tactics.map((t) => (
                    <Badge
                      key={t}
                      className="bg-muted/50 text-muted-foreground border-border text-xs"
                    >
                      {formatTactic(t)}
                    </Badge>
                  ))
                )}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase text-muted-foreground">Platforms</div>
              <div className="mt-1 flex flex-wrap gap-1">
                {data.platforms.length === 0 ? (
                  <span className="text-sm text-muted-foreground">—</span>
                ) : (
                  data.platforms.map((p) => (
                    <Badge
                      key={p}
                      className="bg-muted/50 text-muted-foreground border-border text-xs"
                    >
                      {p}
                    </Badge>
                  ))
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

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

      {/* Detection guidance */}
      {data.detection && (
        <Card className="mt-4">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Detection</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-line text-sm leading-relaxed text-foreground">
              {data.detection}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Data sources */}
      {data.data_sources && data.data_sources.length > 0 && (
        <Card className="mt-4">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Data sources</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-1.5">
            {data.data_sources.map((s) => (
              <Badge
                key={s}
                className="bg-muted text-foreground border-border text-xs"
              >
                {s}
              </Badge>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Groups that use this technique */}
      <Card className="mt-4">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Target className="h-4 w-4 text-muted-foreground" />
            Used by groups
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {data.related_groups.length}{' '}
              {data.related_groups.length === 1 ? 'group' : 'groups'}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {data.related_groups.length === 0 ? (
            <div className="text-sm text-muted-foreground">
              No groups attributed to using this technique.
            </div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {data.related_groups.map((g) => (
                <Link
                  key={g.attack_id}
                  to={`/groups/${g.attack_id}`}
                  className="inline-flex items-center gap-1.5 rounded border border-border bg-muted/30 px-2 py-1 text-xs hover:border-primary hover:bg-primary/10"
                >
                  <span className="font-mono text-muted-foreground">
                    {g.attack_id}
                  </span>
                  <span className="text-foreground">{g.name}</span>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// EXPORTS
// ============================================================================
export function Techniques() {
  return <TechniquesList />;
}

export function Technique() {
  return <TechniqueDetail />;
}
