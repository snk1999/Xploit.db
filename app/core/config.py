"""
XPLOIT.DB — Configuration
All settings via environment variables with safe defaults.
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────────────────────────
    APP_NAME: str = "XPLOIT.DB"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production"

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://xploitdb:xploitdb@localhost:5432/xploitdb"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL_SECONDS: int = 300  # 5 min default cache

    # ── CORS ─────────────────────────────────────────────────────────────────
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080", "*"]

    # ── NVD API ──────────────────────────────────────────────────────────────
    NVD_API_KEY: str = ""  # Optional — increases rate limit 40x
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT_SLEEP: float = 0.6   # seconds between requests (no key)
    NVD_RATE_LIMIT_SLEEP_KEY: float = 0.05  # with API key

    # ── CISA KEV ─────────────────────────────────────────────────────────────
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # ── EPSS ─────────────────────────────────────────────────────────────────
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    EPSS_CSV_URL: str = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"

    # ── Exploit-DB ───────────────────────────────────────────────────────────
    EXPLOITDB_CSV_URL: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    EXPLOITDB_BASE_URL: str = "https://www.exploit-db.com/exploits"
    EXPLOITDB_RAW_URL: str = "https://github.com/offensive-security/exploit-database/raw/master/exploits"

    # ── GitHub PoC (nomi-sec) ────────────────────────────────────────────────
    NOMISEC_API_URL: str = "https://poc-in-github.motikan2010.net/api/v1/"
    NOMISEC_GITHUB_URL: str = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/contents"
    GITHUB_TOKEN: str = ""  # Needed to avoid rate limiting

    # ── Metasploit ───────────────────────────────────────────────────────────
    # dogasantos/msfcve — daily updated JSON of CVE→MSF module mappings
    MSF_CVE_JSON_URL: str = "https://raw.githubusercontent.com/dogasantos/msfcve/main/metasploit_cves.json"
    # Full Metasploit module metadata
    MSF_MODULES_JSON_URL: str = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

    # ── Nuclei Templates ─────────────────────────────────────────────────────
    NUCLEI_TEMPLATES_API: str = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves"
    NUCLEI_TEMPLATES_RAW: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves"

    # ── PacketStorm ───────────────────────────────────────────────────────────
    PACKETSTORM_RSS: str = "https://rss.packetstormsecurity.com/files/tags/exploit/"

    # ── Sync Schedule ────────────────────────────────────────────────────────
    SYNC_NVD_HOURS: int = 2
    SYNC_KEV_HOURS: int = 6
    SYNC_EPSS_HOURS: int = 24
    SYNC_EXPLOITDB_HOURS: int = 24
    SYNC_GITHUB_POC_HOURS: int = 4
    SYNC_MSF_HOURS: int = 24
    SYNC_NUCLEI_HOURS: int = 24
    SYNC_PACKETSTORM_HOURS: int = 6

    # ── Pagination ───────────────────────────────────────────────────────────
    DEFAULT_PAGE_SIZE: int = 25
    MAX_PAGE_SIZE: int = 100

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
