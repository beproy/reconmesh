# ReconMesh

A domain-centric OSINT aggregator for cyber threat intelligence.

## What it does

Type a domain name (e.g., `example.com`) and ReconMesh consolidates everything the open threat intel ecosystem knows about it: associated IPs, malware/phishing/C2 mentions, ransomware leak references, dark web mentions via Ahmia, and any analyst-added context. Each piece of information is linked to its primary source, with first/last seen dates and confidence levels.

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

OpenCTI, MISP, and the broader open-source CTI community. ReconMesh is not a replacement for those — it's a focused, lightweight complement that prioritizes the `one domain, all the intel` workflow.

## License

MIT — see [LICENSE](./LICENSE).

## Security & privacy

- No telemetry, no analytics, no phoning home.
- Secrets stay in `.env` (gitignored). The repo ships `.env.example` with placeholders.
- All threat feed data is treated as untrusted input. Never executed, never rendered as HTML without sanitization.

## Contributing

ReconMesh is in early development. Issues and suggestions welcome via GitHub Issues.
