"""
XPLOIT.DB — Background Scheduler

Orchestrates all data sync jobs using APScheduler.
Each job runs on its own interval and logs to SyncLog table.
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)
_scheduler = AsyncIOScheduler(timezone="UTC")


async def _run_nvd_incremental():
    from app.ingestion.nvd import sync_nvd
    try:
        await sync_nvd(full=False, days_back=1)
    except Exception as e:
        logger.error(f"Scheduled NVD sync failed: {e}")


async def _run_cisa_kev():
    from app.ingestion.kev_epss import sync_cisa_kev
    try:
        await sync_cisa_kev()
    except Exception as e:
        logger.error(f"Scheduled KEV sync failed: {e}")


async def _run_epss():
    from app.ingestion.kev_epss import sync_epss_full_csv
    try:
        await sync_epss_full_csv()
    except Exception as e:
        logger.error(f"Scheduled EPSS sync failed: {e}")


async def _run_exploitdb():
    from app.enrichment.exploits import sync_exploitdb
    try:
        await sync_exploitdb()
    except Exception as e:
        logger.error(f"Scheduled Exploit-DB sync failed: {e}")


async def _run_github_poc():
    from app.enrichment.exploits import sync_github_poc
    try:
        await sync_github_poc()
    except Exception as e:
        logger.error(f"Scheduled GitHub PoC sync failed: {e}")


async def _run_metasploit():
    from app.enrichment.exploits import sync_metasploit
    try:
        await sync_metasploit()
    except Exception as e:
        logger.error(f"Scheduled Metasploit sync failed: {e}")


async def _run_nuclei():
    from app.enrichment.exploits import sync_nuclei
    try:
        await sync_nuclei()
    except Exception as e:
        logger.error(f"Scheduled Nuclei sync failed: {e}")


async def _run_packetstorm():
    from app.enrichment.exploits import sync_packetstorm
    try:
        await sync_packetstorm()
    except Exception as e:
        logger.error(f"Scheduled PacketStorm sync failed: {e}")


async def start_scheduler():
    """Register all jobs and start the scheduler."""

    jobs = [
        (_run_nvd_incremental, settings.SYNC_NVD_HOURS,        "nvd_incremental"),
        (_run_cisa_kev,        settings.SYNC_KEV_HOURS,        "cisa_kev"),
        (_run_epss,            settings.SYNC_EPSS_HOURS,       "epss"),
        (_run_exploitdb,       settings.SYNC_EXPLOITDB_HOURS,  "exploitdb"),
        (_run_github_poc,      settings.SYNC_GITHUB_POC_HOURS, "github_poc"),
        (_run_metasploit,      settings.SYNC_MSF_HOURS,        "metasploit"),
        (_run_nuclei,          settings.SYNC_NUCLEI_HOURS,     "nuclei"),
        (_run_packetstorm,     settings.SYNC_PACKETSTORM_HOURS,"packetstorm"),
    ]

    for func, interval_hours, job_id in jobs:
        _scheduler.add_job(
            func,
            trigger=IntervalTrigger(hours=interval_hours),
            id=job_id,
            replace_existing=True,
            max_instances=1,         # prevent overlapping runs
            coalesce=True,
        )
        logger.info(f"Scheduled [{job_id}] every {interval_hours}h")

    _scheduler.start()
    logger.info("✅ Scheduler started with all sync jobs")


async def stop_scheduler():
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
