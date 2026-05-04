# ReconMesh

A domain-centric OSINT aggregator for cyber threat intelligence.

## What it does

Type a domain name (e.g., `example.com`) and ReconMesh consolidates everything the open threat intel ecosystem knows about it: associated IPs, malware/phishing/C2 mentions, ransomware leak references, dark web mentions via Ahmia, and any analyst-added context. Each piece of information is linked to its primary source, with first/last seen dates and confidence levels.

## Optional: pre-loading domains from a CSV

ReconMesh can read a CSV and pre-create `domains` table rows. Useful when
you want to enrich a known list of domains as a starting point.

The `seed_data/` folder is gitignored except for `README.md` and `example.csv`,
so any CSVs you drop there stay local. See `seed_data/README.md` for the
format and `backend/scripts/seed_domains.py` for the loader.

Quick example:

    docker compose exec backend python scripts/seed_domains.py /app/seed_data/example.csv

## Status

Early development. Built in the open as a learning project and a useful tool.

## Stack

- **Backend:** Python (FastAPI), PostgreSQL, Redis, Celery
- **Frontend:** React + TypeScript + Vite
- **Deployment:** Docker Compose
- **Standards:** STIX 2.1 export, MITRE ATT&CK references

## Getting started

Coming soon — full setup instructions will be added once the MVP is functional.

## Inspired by

The broader open-source CTI community. ReconMesh is not a replacement for those, it's a focused, lightweight complement that prioritizes the `one domain, all the intel` workflow.

## License

MIT — see [LICENSE](./LICENSE).

## Security & privacy

- No telemetry, no analytics, no phoning home.
- Secrets stay in `.env` (gitignored). The repo ships `.env.example` with placeholders.
- All threat feed data is treated as untrusted input. Never executed, never rendered as HTML without sanitization.

## Contributing

ReconMesh is in early development. Issues and suggestions welcome via GitHub Issues.
