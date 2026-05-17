<p align="center">
  <img src="frontend/public/brand/logo-black-bg.png" alt="ReconMesh" width="380" />
</p>

<h3 align="center">Domain-centric OSINT &amp; threat intelligence aggregator</h3>

<p align="center">
  One search across malware feeds, ransomware leaks, certificate transparency, dark web mentions, and DNS intelligence.
</p>

---

## What it does

Search any domain and ReconMesh builds a **domain investigation dossier** by pulling data from multiple open-source intelligence sources in parallel.

### Threat intelligence ingestion (4 feeds)

| Feed | What it pulls | Indicators |
|------|--------------|------------|
| **URLhaus** (abuse.ch) | Malware distribution URLs with confidence levels and TLP markings | ~32K |
| **AlienVault OTX** | Pulse-based threat indicators across multiple types | ~10K |
| **ThreatFox** (abuse.ch) | IOCs associated with malware families | ~1K |
| **Ransomware.live** | Ransomware group leak site references | ~93 |

### Enrichment suite (13 enrichers, all parallel via Celery)

| Enricher | What it checks |
|----------|---------------|
| **DNS records** | A, AAAA, MX, NS, TXT, CNAME with per-type status and NXDOMAIN detection |
| **Email security** | SPF, DMARC, DKIM analysis with scored posture tier (strong / partial / weak) |
| **WHOIS** | Registrar, registration dates, name servers, registrant country, DNSSEC status |
| **Certificate transparency** | Queries crt.sh for all certificates issued, extracts subdomains, caps at 200 |
| **Typo-squat detection** | dnstwist generates up to 250 lookalike permutations, resolves A records concurrently |
| **VirusTotal** | Domain reputation, detection ratios, community votes (BYOK) |
| **Shodan** | Open ports, services, banners, vulnerabilities (BYOK) |
| **AbuseIPDB** | IP abuse confidence score and report history (BYOK) |
| **Dark web (Ahmia)** | Searches Tor hidden services for domain mentions |
| **URLScan.io** | Screenshot and analysis of live pages (BYOK) |
| **HackerTarget** | Reverse IP lookup for co-hosted domains |
| **Mnemonic Passive DNS** | Historical DNS resolution data |
| **ThreatMiner** | Passive DNS, subdomains, and related malware samples |

### AI-powered analysis

ReconMesh includes an optional **AI Analysis** panel powered by Google Gemini. When triggered, it:

- Summarizes all enrichment findings into a structured risk assessment
- Identifies the domain's likely industry sector
- Maps relevant **MITRE ATT&CK threat groups** from the 174 groups in the database that target that sector
- Provides actionable recommendations for security teams

The AI is strictly constrained to only reference data that exists in the enrichment results — no hallucination.

### MITRE ATT&CK integration

- 174 threat groups with descriptions, aliases, and external references
- Full technique catalog with kill chain phases and platforms
- Browseable Groups and Techniques pages with search and pagination
- AI summary cross-references groups against the investigated domain's sector

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

Edit `.env` and set secure values for `POSTGRES_PASSWORD`, `BACKEND_SECRET_KEY`, and `ADMIN_BOOTSTRAP_TOKEN`. The defaults in `.env.example` are placeholders — do not use them in any shared environment.

**3. Start the stack**

```bash
docker compose up -d --build
```

First run takes 2–3 minutes (downloading images, installing dependencies). Subsequent starts take ~10 seconds.

**4. Verify everything is healthy**

```bash
docker compose ps
```

All five services should show `healthy` status.

**5. Ingest threat data**

```bash
# Pull indicators from all feeds
curl -X POST http://localhost:8000/feeds/urlhaus/refresh
curl -X POST http://localhost:8000/feeds/threatfox/refresh
curl -X POST http://localhost:8000/feeds/otx/refresh
curl -X POST http://localhost:8000/feeds/ransomware-live/refresh

# Ingest MITRE ATT&CK groups and techniques
curl -X POST http://localhost:8000/attack/refresh
```

**6. Open the UI**

Navigate to [http://localhost:5173](http://localhost:5173). Search for any domain, click **Investigate**, then click **Enrich** to run the full enrichment suite.

## Optional API keys

Some enrichers work without API keys. Others require a free or paid key. Add them to your `.env` file:

| Key | Enricher | Free tier |
|-----|----------|-----------|
| `VIRUSTOTAL_API_KEY` | VirusTotal reputation | Free (4 req/min) |
| `SHODAN_API_KEY` | Shodan port scan | Free (limited) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB reports | Free (1000 req/day) |
| `URLSCAN_API_KEY` | URLScan.io | Free (limited) |
| `OTX_API_KEY` | AlienVault OTX ingester | Free |
| `GEMINI_API_KEY` | AI Analysis panel | Free (15 req/min) |

Get a Gemini API key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey).

## Pre-loading domains from a CSV

ReconMesh can bulk-create domain rows from a CSV file. Useful when you want to enrich a known list of domains.

The `seed_data/` folder is gitignored (except `README.md` and `example.csv`), so any CSVs you add stay local.

```bash
docker compose exec backend python scripts/seed_domains.py /app/seed_data/your_file.csv
```

See `seed_data/README.md` for the CSV format.

## Project structure

```
reconmesh/
├── backend/
│   ├── main.py                 # FastAPI app, all endpoints
│   ├── models.py               # SQLAlchemy models
│   ├── schemas.py              # Pydantic request/response schemas
│   ├── ai_summary.py           # AI-powered investigation summary (Gemini)
│   ├── auth.py                 # API key authentication
│   ├── database.py             # DB engine + session factory
│   ├── celery_app.py           # Celery instance configuration
│   ├── ingesters/              # Threat feed ingesters (4)
│   ├── enrichers/              # Domain enrichment modules (13)
│   ├── tasks/                  # Celery task definitions
│   ├── migrations/             # Alembic database migrations
│   ├── scripts/                # Utility scripts (seed loader)
│   └── tests/                  # Smoke tests
├── frontend/
│   └── src/
│       ├── pages/              # Landing, DomainDetail, Sources, Groups, Techniques
│       ├── components/         # Investigation UI, Landing, shadcn/ui
│       ├── config/             # Capabilities, suggested searches
│       └── lib/                # API client, verdict engine, summary templates
├── seed_data/                  # Gitignored folder for local domain lists
├── docker-compose.yml          # Full stack orchestration
└── .env                        # Secrets (gitignored)
```

## Security and privacy

- **No telemetry, no analytics, no phoning home.** The application makes outbound requests only to the threat feeds and enrichment APIs you explicitly trigger.
- **Secrets stay in `.env`** (gitignored). Never committed to the repository.
- **All threat feed data is treated as untrusted input.** Never executed, never rendered as raw HTML.
- **Database and Redis are not exposed** to the host network. Only the backend API and frontend dev server bind to localhost.
- **The backend binds to `127.0.0.1` only** — not accessible from other machines on your network without explicit tunneling.

## Limitations

- **Single-user tool.** No multi-tenancy. Designed for individual analysts or small-team demos.
- **Not production-hardened.** No TLS termination, no secrets management beyond `.env`. Use Docker Compose for development and demos, not internet-facing deployment.
- **Rate limits are upstream-dependent.** crt.sh, WHOIS servers, and DNS resolvers may rate-limit heavy use. Enrichers handle this gracefully (retry or report the error).
- **AI summary requires a Gemini API key.** Without it, the AI Analysis panel is hidden. The feature degrades gracefully.

## License

MIT — see [LICENSE](./LICENSE).

## Acknowledgements

Built with data from the open-source CTI community:

- [URLhaus](https://urlhaus.abuse.ch/) and [ThreatFox](https://threatfox.abuse.ch/) by abuse.ch
- [AlienVault OTX](https://otx.alienvault.com/) by AT&T Cybersecurity
- [Ransomware.live](https://www.ransomware.live/) ransomware group tracker
- [MITRE ATT&CK](https://attack.mitre.org/) threat group and technique catalog
- [Ahmia](https://ahmia.fi/) Tor hidden service search
- [crt.sh](https://crt.sh/) certificate transparency search
- [dnstwist](https://github.com/elceef/dnstwist) by Marcin Ulikowski
- [Mnemonic](https://passivedns.mnemonic.no/) passive DNS
- [HackerTarget](https://hackertarget.com/) reverse IP lookup
- [ThreatMiner](https://www.threatminer.org/) threat intelligence portal
