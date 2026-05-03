import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

export function Home() {
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = query.trim().toLowerCase();
    if (!trimmed) return;
    navigate(`/domains/${encodeURIComponent(trimmed)}`);
  };

  return (
    <div className="flex flex-col items-center justify-center py-16">
      <div className="w-full max-w-2xl text-center">
        <h1 className="text-4xl font-bold tracking-tight text-foreground">
          Domain-centric threat intelligence
        </h1>
        <p className="mt-3 text-base text-muted-foreground">
          Look up any domain to see what the open threat intel ecosystem knows about it.
        </p>

        <form onSubmit={handleSubmit} className="mt-10">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter a domain (e.g. evil.example.com)"
                className="h-12 pl-10 text-base"
                autoFocus
              />
            </div>
            <Button type="submit" size="lg" className="h-12 px-6">
              Search
            </Button>
          </div>
        </form>

        <p className="mt-6 text-xs text-muted-foreground">
          Tip: try a domain we have data on. See the Sources page for what feeds we ingest from.
        </p>
      </div>
    </div>
  );
}