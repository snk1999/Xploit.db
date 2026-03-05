# XPLOIT.DB 🔴
### The Most Complete Public Exploit Intelligence Platform

A self-hostable backend that aggregates CVE data from every major public
source, finds public exploits for each CVE, and scores them by real-world
priority — not just CVSS severity.

---

## What Makes This Different

Most CVE tools show you **severity**. XPLOIT.DB shows you **exploitability**.

| Feature | NVD | Shodan | CVEDetails | **XPLOIT.DB** |
|---|---|---|---|---|
| CVE data | ✅ | ✅ | ✅ | ✅ |
| EPSS scores | ❌ | ❌ | ❌ | ✅ |
| CISA KEV tags | ❌ | ❌ | partial | ✅ |
| GitHub PoC links | ❌ | ❌ | partial | ✅ |
| Metasploit mapping | ❌ | ❌ | partial | ✅ |
| Nuclei template flag | ❌ | ❌ | ❌ | ✅ |
| Combined XPLOIT Score | ❌ | ❌ | ❌ | ✅ |
| Self-hostable | ✅ | ❌ | ❌ | ✅ |
| Free & open source | ✅ | ❌ | ❌ | ✅ |

---

## Data Sources

| Source | What it provides | Sync interval |
|---|---|---|
| **NVD/NIST API 2.0** | All CVEs, CVSS, affected products, CWEs | Every 2h |
| **CISA KEV Catalog** | Confirmed-exploited-in-wild flag | Every 6h |
| **EPSS (FIRST.org)** | ML exploit probability (0–100%) | Daily |
| **Exploit-DB** | 50,000+ public exploits via official CSV | Daily |
| **nomi-sec/PoC-in-GitHub** | GitHub PoC repos indexed by CVE ID | Every 4h |
| **Metasploit Framework** | Weaponized exploit module mapping | Daily |
| **Nuclei Templates** | Scanner-verified CVE templates | Daily |
| **PacketStorm Security** | RSS exploit release feed | Every 6h |

---

## XPLOIT Score Formula

Every CVE receives an **XPLOIT Score** (0–100) that combines all signals:

```
XPLOIT Score =
  min(cvss_score × 4,  40)   # CVSS severity       (max 40pts)
  + epss_score × 20          # Exploit probability  (max 20pts)
  + 20 if kev                # Confirmed in wild    (max 20pts)
  + 10 if has_metasploit     # Weaponized exploit   (max 10pts)
  + 5  if has_nuclei         # Scanner-verified     (max 5pts)
  + 5  if has_any_poc        # Any public PoC       (max 5pts)
```

A CVE with CVSS 9.5 + in KEV + Metasploit module = **~88 points**.
A CVE with CVSS 9.5 but no exploit anywhere = **~38 points**.

This is the difference between "patch this eventually" and "patch this now."

---

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/yourname/xploitdb
cd xploitdb
# Edit .env — add your NVD_API_KEY and GITHUB_TOKEN (both free)

# 2. Start the stack
docker-compose up -d

# 3. Initialize DB and run first sync (this runs automatically via 'init' service)
docker-compose logs -f init

# 4. Open the API
open http://localhost:8000/docs

# 5. Open the frontend
open http://localhost:3000
```

The `init` container will:
1. Create database tables
2. Run an initial NVD sync (recent CVEs)
3. Run all enrichment syncs (KEV, EPSS, Exploit-DB, etc.)

For a **full historical backfill** (all 200k+ CVEs — takes 1–2 hours):
```bash
docker-compose exec api python manage.py backfill
```

---

## API Endpoints

### CVEs
```
GET /api/v1/cves/                     List CVEs with filters
GET /api/v1/cves/{cve_id}             Full CVE detail + all exploits

# Filter examples:
?severity=CRITICAL,HIGH
?kev_only=true
?has_exploit=true
?has_metasploit=true
?min_cvss=9.0
?min_epss=0.5
?min_xploit=70
?days=7                               # Published in last 7 days
?vendor=microsoft
?sort=xploit_score&order=desc
```

### Exploits
```
GET /api/v1/exploits/                 List all exploits
GET /api/v1/exploits/{id}             Single exploit detail
?source=metasploit|exploitdb|github_poc|nuclei|packetstorm
?cve_id=CVE-2024-1234
```

### Search
```
GET /api/v1/search/?q=apache+rce      Full-text search
GET /api/v1/search/?q=CVE-2024-1234
GET /api/v1/search/?q=log4j
```

### Feed
```
GET /api/v1/feed/latest               Recent CVEs (last 24h by default)
GET /api/v1/feed/hotlist              Top-priority CVEs (XPLOIT score ≥ 70)
?hours=48&severity=CRITICAL&exploit_only=true
```

### Stats
```
GET /api/v1/stats/summary             Dashboard statistics
GET /api/v1/stats/sync-health         Sync job history
```

---

## Manual Sync Commands

```bash
# Run from inside the API container or directly with Python
python manage.py sync-nvd         # Incremental NVD (last 2 days)
python manage.py sync-kev         # CISA KEV catalog
python manage.py sync-epss        # EPSS scores
python manage.py sync-exploitdb   # Exploit-DB CSV
python manage.py sync-github      # GitHub PoCs
python manage.py sync-metasploit  # Metasploit modules
python manage.py sync-nuclei      # Nuclei templates
python manage.py sync-packetstorm # PacketStorm RSS
python manage.py sync-all         # All enrichment sources
python manage.py stats            # Print DB stats
```

---

## Project Structure

```
xploitdb/
├── app/
│   ├── main.py                  # FastAPI app, lifespan, routers
│   ├── api/
│   │   ├── cves.py              # CVE listing, detail, filters
│   │   ├── exploits.py          # Exploit listing
│   │   ├── search.py            # Full-text search
│   │   ├── feed.py              # Live feed + hotlist
│   │   └── stats.py             # Dashboard stats
│   ├── core/
│   │   ├── config.py            # All settings via env vars
│   │   ├── database.py          # Async SQLAlchemy engine
│   │   └── scheduler.py         # APScheduler job registration
│   ├── ingestion/
│   │   ├── nvd.py               # NVD API sync (incremental + full)
│   │   └── kev_epss.py          # CISA KEV + EPSS
│   ├── enrichment/
│   │   └── exploits.py          # Exploit-DB, GitHub PoC, MSF, Nuclei, PacketStorm
│   └── models/
│       └── models.py            # SQLAlchemy ORM models
├── manage.py                    # CLI for manual ops
├── docker-compose.yml
├── docker/Dockerfile
├── requirements.txt
└── .env.example
```

---

## Phase 2 — Scanner Module (Planned)

The scanner module will:
1. Accept a target IP/range or URL
2. Run port scan + service fingerprinting
3. Map detected software versions to CVEs in the database
4. Generate a prioritized vulnerability report

The existing database and API are already designed to support this — 
the `affected_products` field on CVEs maps directly to scanner output.

---

## Contributing

This is built on 100% free, open public data sources. If you know of another
valuable exploit feed or CVE enrichment source, open an issue or PR.

