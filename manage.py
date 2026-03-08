#!/usr/bin/env python3
"""
XPLOIT.DB — Management CLI

Usage:
  python manage.py init-db          # Create tables
  python manage.py backfill         # Full NVD backfill (ALL CVEs ever)
  python manage.py sync-nvd         # Incremental NVD sync (last 24h)
  python manage.py sync-kev         # Sync CISA KEV
  python manage.py sync-epss        # Sync EPSS scores
  python manage.py sync-exploitdb   # Sync Exploit-DB CSV
  python manage.py sync-github      # Sync GitHub PoCs
  python manage.py sync-metasploit  # Sync Metasploit modules
  python manage.py sync-nuclei      # Sync Nuclei templates
  python manage.py sync-packetstorm # Sync PacketStorm RSS
  python manage.py sync-all         # Run all enrichment syncs
  python manage.py cleanup-rejected # Remove rejected CVEs from database
  python manage.py stats            # Print database statistics
"""

import asyncio
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("manage")


async def init_db():
    from app.core.database import engine, Base
    from app.models import models  # ensure models are registered
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables created")


async def backfill():
    """Full NVD backfill — WARNING: takes 30–60 min, fetches 200k+ CVEs."""
    logger.warning("⚠️  Starting FULL NVD backfill. This will take a while...")
    from app.ingestion.nvd import sync_nvd
    result = await sync_nvd(full=True)
    logger.info(f"Backfill complete: {result}")


async def sync_nvd_incremental():
    from app.ingestion.nvd import sync_nvd
    result = await sync_nvd(full=False, days_back=2)
    logger.info(f"NVD incremental: {result}")


async def sync_kev():
    from app.ingestion.kev_epss import sync_cisa_kev
    result = await sync_cisa_kev()
    logger.info(f"KEV: {result}")


async def sync_epss():
    from app.ingestion.kev_epss import sync_epss_full_csv
    result = await sync_epss_full_csv()
    logger.info(f"EPSS: {result}")


async def sync_exploitdb():
    from app.enrichment.exploits import sync_exploitdb as _sync
    result = await _sync()
    logger.info(f"Exploit-DB: {result}")


async def sync_github():
    from app.enrichment.exploits import sync_github_poc
    result = await sync_github_poc()
    logger.info(f"GitHub PoC: {result}")


async def sync_metasploit():
    from app.enrichment.exploits import sync_metasploit as _sync
    result = await _sync()
    logger.info(f"Metasploit: {result}")


async def sync_nuclei():
    from app.enrichment.exploits import sync_nuclei as _sync
    result = await _sync()
    logger.info(f"Nuclei: {result}")


async def sync_packetstorm():
    from app.enrichment.exploits import sync_packetstorm as _sync
    result = await _sync()
    logger.info(f"PacketStorm: {result}")


async def sync_all():
    """Run all enrichment sources — failures are logged but non-fatal."""
    logger.info("🔄 Running all enrichment syncs...")
    jobs = [
        ("kev",         sync_kev),
        ("epss",        sync_epss),
        ("exploitdb",   sync_exploitdb),
        ("github",      sync_github),
        ("metasploit",  sync_metasploit),
        ("nuclei",      sync_nuclei),
        ("packetstorm", sync_packetstorm),
    ]
    for name, fn in jobs:
        try:
            await fn()
        except Exception as e:
            logger.error(f"⚠️  {name} failed (skipping): {e}")
    logger.info("✅ All syncs complete")


async def cleanup_rejected():
    """Remove CVEs with rejection strings from the database."""
    from app.ingestion.nvd import _cleanup_rejected_cves
    await _cleanup_rejected_cves()
    logger.info("Rejected CVE cleanup complete")


COMMANDS = {
    "init-db":         init_db,
    "backfill":        backfill,
    "sync-nvd":        sync_nvd_incremental,
    "sync-kev":        sync_kev,
    "sync-epss":       sync_epss,
    "sync-exploitdb":  sync_exploitdb,
    "sync-github":     sync_github,
    "sync-metasploit": sync_metasploit,
    "sync-nuclei":     sync_nuclei,
    "sync-packetstorm":sync_packetstorm,
    "sync-all":        sync_all,
    "cleanup-rejected": cleanup_rejected,
    "stats":           print_stats,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    logger.info(f"Running: {cmd}")
    asyncio.run(COMMANDS[cmd]())
