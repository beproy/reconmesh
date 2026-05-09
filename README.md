# ReconMesh

A domain-centric OSINT aggregator for cyber threat intelligence. Type a domain name and get a consolidated dossier: threat intel from open feeds, DNS records, email security posture, WHOIS data, certificate transparency logs, and typo-squat lookalike detection — all in one view.

Built as a learning project and a genuinely useful tool for individual analysts and small security teams.

## What it does

Search any domain and ReconMesh builds a **domain dossier** by pulling data from multiple sources:

**Threat intelligence ingestion**
- **URLhaus** (abuse.ch) — malware distribution URLs, with confidence levels and TLP markings

**Enrichment suite** (5 enrichers, all run in parallel via Celery)
- **DNS records** — A, AAAA, MX, NS, TXT, CNAME with per-type status and NXDOMAIN detection
- **Email security posture** — SPF, DMARC, DKIM analysis with a scored posture tier (strong / partial / weak)
- **WHOIS** — registrar, registration dates, name servers, registrant country, DNSSEC status
- **Certificate transparency** — queries crt.sh for all certificates issued for a domain, extracts subdomains, caps at 200 by recency
- **Typo-squat detection** — uses dnstwist to generate up to 250 lookalike permutations (bitsquatting, homoglyphs, insertion, transposition, etc.), resolves A records concurrently, reports which lookalikes are live

**Async job system**
- Enrichment runs in background workers via Celery + Redis
- The UI dispatches a job, polls for progress, and shows results as they arrive
- Failed enrichments retry automatically with exponential backoff (5s → 15s → 45s)
- Each enricher runs in its own Celery task — all five execute in parallel

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Frontend   │────▶│   Backend   │────▶│  PostgreSQL  │
│  React/Vite  │◀────│   FastAPI   │◀────│   (data)     │
│  :5173       │     │   :8000     │     │              │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                    ┌──────▼──────┐     ┌─────────────┐
                    │    Redis     │◀───▶│   Worker     │
                    │  (broker)    │     │  Celery x4   │
                    └─────────────┘     └─────────────┘
```

Five containers orchestrated by Docker Compose:
- **frontend** — React 19 + TypeScript + Vite + Tailwind v4 + shadcn/ui
- **backend** — FastAPI with SQLAlchemy ORM, Alembic migrations
- **worker** — Celery worker (4 prefork processes) sharing the backend image
- **db** — PostgreSQL 16
- **redis** — Redis 7 (Celery broker + result backend)

All services communicate over an internal Docker network. Only the backend API (localhost:8000) and frontend dev server (localhost:5173) are exposed to the host.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows, macOS, or Linux)
- [Git](https://git-scm.com/)
- ~2 GB free disk space (Docker images + database)

No local Python or Node.js installation needed — everything runs in containers.

## Getting started

**1. Clone the repository**

```bash
git clone https://github.com/beproy/reconmesh.git
cd reconmesh
```

**2. Create the environment file**

```bash
cp .env.example .env
```

Edit `.env` and set secure values for `POSTGRES_PASSWORD` and `BACKEND_SECRET_KEY`. The defaults in `.env.example` are placeholders — do not use them in any shared environment.

**3. Start the stack**

```bash
docker compose up -d --build
```

First run takes 2-3 minutes (downloading images, installing dependencies). Subsequent starts take ~10 seconds.

**4. Verify everything is healthy**

```bash
docker compose ps
```

All five services should show `healthy` status.

**5. Ingest threat data**

```bash
# Pull ~30,000+ indicators from URLhaus (takes ~60 seconds)
curl -X POST http://localhost:8000/feeds/urlhaus/refresh
```

**6. Open the UI**

Navigate to [http://localhost:5173](http://localhost:5173). Search for any domain that appears in URLhaus data, or type any domain and click **Enrich** to run the full enrichment suite.

## Running tests

```bash
docker compose exec backend pytest tests/ -v
```

Runs 4 smoke tests covering the health endpoint, URLhaus ingester, DNS NXDOMAIN handling, and typo-squat zero-alive path.

## Pre-loading domains from a CSV

ReconMesh can bulk-create domain rows from a CSV file. Useful when you want to enrich a known list of domains.

The `seed_data/` folder is gitignored (except `README.md` and `example.csv`), so any CSVs you add stay local.

```bash
docker compose exec backend python scripts/seed_domains.py /app/seed_data/your_file.csv
```

See `seed_data/README.md` for the CSV format and `seed_data/example.csv` for an example.

## Project structure

```
reconmesh/
├── backend/
│   ├── main.py                 # FastAPI app, all endpoints
│   ├── models.py               # SQLAlchemy models (domains, indicators, enrichments, jobs)
│   ├── schemas.py              # Pydantic request/response schemas
│   ├── database.py             # DB engine + session factory
│   ├── celery_app.py           # Celery instance configuration
│   ├── ingesters/              # Threat feed ingesters
│   │   ├── base.py             #   BaseIngester ABC
│   │   └── urlhaus.py          #   URLhaus CSV ingester
│   ├── enrichers/              # Domain enrichment modules
│   │   ├── base.py             #   BaseEnricher ABC
│   │   ├── dns_records.py      #   DNS A/AAAA/MX/NS/TXT/CNAME
│   │   ├── email_security.py   #   SPF/DMARC/DKIM + posture scoring
│   │   ├── whois_lookup.py     #   WHOIS registration data
│   │   ├── cert_transparency.py#   crt.sh certificate transparency
│   │   └── typo_squat.py       #   dnstwist lookalike detection
│   ├── tasks/                  # Celery task definitions
│   │   └── enrichment_tasks.py #   One task per enricher + dispatch map
│   ├── migrations/             # Alembic database migrations
│   ├── scripts/                # Utility scripts (seed loader)
│   └── tests/                  # Smoke tests
├── frontend/
│   └── src/
│       ├── pages/              # Home (search), DomainDetail (dossier), Sources
│       ├── components/         # Header, Layout, shadcn/ui components
│       └── lib/api.ts          # Typed API client
├── seed_data/                  # Gitignored folder for local domain lists
├── docker-compose.yml          # Full stack orchestration
└── .env                        # Secrets (gitignored)
```

## Roadmap

Currently at **v0.4** (Session 10 of active development). Planned for v1.0:

- [ ] Search and filtering on the home page (browse domains, filter by TLD/posture/indicator count)
- [ ] Additional ingesters: ThreatFox, MalwareBazaar (abuse.ch family), AlienVault OTX
- [ ] Bring-your-own-key integrations: VirusTotal, Shodan, GreyNoise
- [ ] Dark web mention detection via Ahmia
- [ ] API key authentication and rate limiting
- [ ] Temporary public exposure via Cloudflare Tunnel for team testing

## Security and privacy

- **No telemetry, no analytics, no phoning home.** The application makes outbound requests only to the threat feeds and enrichment APIs you explicitly trigger.
- **Secrets stay in `.env`** (gitignored). Never committed to the repository.
- **All threat feed data is treated as untrusted input.** Never executed, never rendered as raw HTML.
- **Database and Redis are not exposed** to the host network. Only the backend API and frontend dev server bind to localhost.
- **The backend binds to `127.0.0.1` only** — not accessible from other machines on your network without explicit tunneling.

## Limitations (honest list)

- **Single-user tool.** No authentication, no multi-tenancy. Designed for individual analysts or small-team demos.
- **Not production-hardened.** No TLS termination, no secrets management beyond `.env`, no backup automation. Use Docker Compose for development and demos, not internet-facing deployment.
- **Rate limits are upstream-dependent.** crt.sh, WHOIS servers, and DNS resolvers may rate-limit or block heavy use. The enrichers handle this gracefully (retry or report the error), but sustained bulk enrichment may hit limits.
- **Typo-squat results are capped at 250 permutations** to stay within reasonable time/resource budgets. Long domain names may generate thousands of homoglyph variants that aren't all checked.

## License

MIT — see [LICENSE](./LICENSE).

## Acknowledgements

Built with data from the open-source CTI community:
- [URLhaus](https://urlhaus.abuse.ch/) by abuse.ch
- [crt.sh](https://crt.sh/) certificate transparency search
- [dnstwist](https://github.com/elceef/dnstwist) by Marcin Ulikowski
