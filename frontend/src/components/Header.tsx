import { Link, NavLink } from 'react-router-dom';
import { SettingsDialog } from '@/components/SettingsDialog';

// Helper for nav link styling — shows a primary color when active
function navLinkClass({ isActive }: { isActive: boolean }) {
  return isActive
    ? 'text-sm text-foreground font-medium'
    : 'text-sm text-muted-foreground hover:text-foreground';
}

export function Header() {
  return (
    <header className="border-b bg-background">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link to="/" className="flex items-center gap-2 text-foreground">
          <img src="/brand/favicon-192.png" alt="ReconMesh" className="h-6 w-6" />
          <span className="text-lg font-semibold tracking-tight">
            ReconMesh
          </span>
        </Link>
        <nav className="flex items-center gap-4">
          <NavLink to="/groups" className={navLinkClass}>
            Groups
          </NavLink>
          <NavLink to="/techniques" className={navLinkClass}>
            Techniques
          </NavLink>
          <NavLink to="/sources" className={navLinkClass}>
            Sources
          </NavLink>
          <SettingsDialog />
        </nav>
      </div>
    </header>
  );
}
