import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';

export function Header() {
  return (
    <header className="border-b bg-background">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link to="/" className="flex items-center gap-2 text-foreground">
          <Shield className="h-6 w-6 text-primary" />
          <span className="text-lg font-semibold tracking-tight">
            ReconMesh
          </span>
        </Link>
        <nav className="flex items-center gap-4">
          <Link
            to="/sources"
            className="text-sm text-muted-foreground hover:text-foreground"
          >
            Sources
          </Link>
        </nav>
      </div>
    </header>
  );
}