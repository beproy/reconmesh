import { useState, useEffect } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { Settings, X, Check, Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { getApiKey, setApiKey, clearApiKey, hasApiKey } from '@/lib/apiKey';

/**
 * Settings dialog — currently only the API key.
 *
 * Trigger is a gear icon button (rendered by the Header). The dialog is a
 * Radix overlay so we don't need to add the shadcn Dialog component.
 *
 * Behaviour:
 *   - Input is type="password" by default. Eye toggle reveals.
 *   - Save button updates localStorage and closes the dialog.
 *   - Clear button removes the key.
 *   - Status badge shows whether a key is currently saved.
 */
export function SettingsDialog() {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState('');
  const [reveal, setReveal] = useState(false);
  const [keyPresent, setKeyPresent] = useState(hasApiKey());

  // Re-hydrate from localStorage every time the dialog opens
  useEffect(() => {
    if (open) {
      setValue(getApiKey() ?? '');
      setReveal(false);
      setKeyPresent(hasApiKey());
    }
  }, [open]);

  function handleSave() {
    setApiKey(value);
    setKeyPresent(hasApiKey());
    setOpen(false);
  }

  function handleClear() {
    clearApiKey();
    setValue('');
    setKeyPresent(false);
  }

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <button
          aria-label="Settings"
          className="inline-flex items-center gap-1.5 rounded-md px-2 py-1.5 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
        >
          <Settings className="h-4 w-4" />
          <span
            className={`inline-block h-1.5 w-1.5 rounded-full ${
              keyPresent ? 'bg-green-500' : 'bg-red-500'
            }`}
            aria-hidden
          />
        </button>
      </Dialog.Trigger>

      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-background p-6 shadow-xl focus:outline-none">
          <div className="flex items-start justify-between">
            <div>
              <Dialog.Title className="text-base font-semibold text-foreground">
                Settings
              </Dialog.Title>
              <Dialog.Description className="mt-1 text-xs text-muted-foreground">
                Configure your ReconMesh API key. The key is stored only in this
                browser's localStorage.
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <button
                aria-label="Close"
                className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            </Dialog.Close>
          </div>

          <div className="mt-5 space-y-2">
            <div className="flex items-center justify-between">
              <label
                htmlFor="apikey-input"
                className="text-xs font-medium uppercase text-muted-foreground"
              >
                API key
              </label>
              {keyPresent ? (
                <Badge className="bg-green-500/20 text-green-300 border-green-500/40 text-xs">
                  <Check className="mr-1 h-3 w-3" /> Saved
                </Badge>
              ) : (
                <Badge className="bg-muted text-muted-foreground border-border text-xs">
                  Not set
                </Badge>
              )}
            </div>
            <div className="flex gap-2">
              <input
                id="apikey-input"
                type={reveal ? 'text' : 'password'}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="rm_..."
                className="flex-1 rounded-md border border-border bg-muted/30 px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
                autoComplete="off"
                spellCheck={false}
              />
              <button
                type="button"
                onClick={() => setReveal((v) => !v)}
                aria-label={reveal ? 'Hide key' : 'Show key'}
                className="rounded-md border border-border bg-muted/30 px-2 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                {reveal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <p className="text-xs text-muted-foreground">
              Mint a key from the backend with{' '}
              <code className="rounded bg-muted px-1 font-mono">POST /admin/keys</code>{' '}
              (admin-token protected).
            </p>
          </div>

          <div className="mt-6 flex justify-between gap-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={handleClear}
              disabled={!keyPresent}
            >
              Clear
            </Button>
            <div className="flex gap-2">
              <Dialog.Close asChild>
                <Button type="button" variant="ghost" size="sm">
                  Cancel
                </Button>
              </Dialog.Close>
              <Button type="button" size="sm" onClick={handleSave}>
                Save
              </Button>
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
