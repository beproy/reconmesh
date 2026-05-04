# Seed data

This folder contains optional CSVs that pre-populate ReconMesh's `domains`
table with a starting list of domains relevant to your operating context
(e.g., your employer's public-facing properties).

## Why this is gitignored

Most files in this folder are deliberately gitignored so that:

- Org-specific domain lists never enter the public repo
- Anyone forking ReconMesh gets a clean tool with no embedded assumptions
  about who they work for

What IS committed: this README, `example.csv` (the format reference), and
`.gitkeep` so the folder structure exists in fresh clones.

## CSV format

A simple two-column CSV with a header row:

    name,notes
    example.com,Primary corporate site
    api.example.com,Public API gateway

- `name`  (required) — the domain name. Lowercased + stripped on load.
- `notes` (optional) — short free-text. Not stored in the DB; for your reference.

Both columns are read by `backend/scripts/seed_domains.py`.

## Loading a CSV

From the project root:

    docker compose exec backend python scripts/seed_domains.py /app/seed_data/<your-file>.csv

The loader is idempotent: existing domains are left alone, new ones are
inserted. No deletions, no overwrites of metadata.

## Where to put your file

Drop your local CSV into this folder. It will not be picked up by git.
Common name: `<your-org>.csv`. Run the loader command above with the path.