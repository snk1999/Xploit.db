"""
XPLOIT.DB — CISA KEV & EPSS Enrichment

CISA KEV: Tags CVEs confirmed exploited in the wild.
EPSS:     Adds ML-based exploit probability scores from FIRST.org.
"""

import asyncio
import aiohttp
import csv
import gzip
import io
import logging
from datetime import datetime, timezone, date, timedelta
from sqlalchemy import update, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.models import CVE, SyncLog, SyncStatusEnum

logger = logging.getLogger(__name__)


# ─── CISA KEV ────────────────────────────────────────────────────────────────

async def sync_cisa_kev() -> dict:
    """
    Fetch CISA Known Exploited Vulnerabilities catalog and tag CVEs.
    
    Free JSON feed from CISA. Every CVE in this list has been confirmed
    exploited in the wild — this is the strongest signal we have.
    """
    log_start = datetime.now(timezone.utc)
    tagged = 0

    logger.info("🔒 Starting CISA KEV sync...")

    async with aiohttp.ClientSession() as http:
        async with http.get(
            settings.CISA_KEV_URL,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            resp.raise_for_status()
            data = await resp.json(content_type=None)

    vulns = data.get("vulnerabilities", [])
    logger.info(f"CISA KEV contains {len(vulns)} entries")

    def parse_date(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s)
        except Exception:
            try:
                return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except Exception:
                return None

    async with AsyncSessionLocal() as db:
        for v in vulns:
            cve_id = v.get("cveID")
            if not cve_id:
                continue

            # Only update CVEs we have in our database
            await db.execute(
                update(CVE)
                .where(CVE.id == cve_id)
                .values(
                    kev=True,
                    kev_date_added=parse_date(v.get("dateAdded")),
                    kev_due_date=v.get("dueDate"),
                    kev_ransomware=v.get("knownRansomwareCampaignUse"),
                )
            )
            tagged += 1

        await db.commit()

    # Recompute xploit scores for KEV entries (KEV adds +20pts)
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(CVE).where(CVE.kev == True))
        kev_cves = result.scalars().all()
        for cve in kev_cves:
            cve.compute_xploit_score()
        await db.commit()

    duration = (datetime.now(timezone.utc) - log_start).total_seconds()
    result = {
        "source": "cisa_kev",
        "status": "success",
        "total_in_kev": len(vulns),
        "tagged_in_db": tagged,
        "duration_secs": round(duration, 2),
    }
    logger.info(f"✅ CISA KEV sync: {result}")
    return result


# ─── EPSS ────────────────────────────────────────────────────────────────────

async def sync_epss(batch_size: int = 2000) -> dict:
    """
    Fetch EPSS scores from FIRST.org API for all CVEs in our database.
    
    Strategy:
    1. Get all CVE IDs from our DB that need EPSS scores.
    2. Query EPSS API in batches of up to 2000 CVEs per request.
    3. Update the epss_score and epss_percentile columns.
    
    Alternative for full refresh: download the daily CSV (~20MB gzip)
    which contains all CVE scores at once.
    """
    log_start = datetime.now(timezone.utc)
    updated = 0

    logger.info("📊 Starting EPSS sync...")

    # Get all CVE IDs from our database
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(CVE.id))
        all_cve_ids = [row[0] for row in result.fetchall()]

    logger.info(f"Fetching EPSS scores for {len(all_cve_ids)} CVEs")

    # Query in batches
    score_map = {}
    async with aiohttp.ClientSession() as http:
        for i in range(0, len(all_cve_ids), batch_size):
            batch = all_cve_ids[i:i + batch_size]
            cve_param = ",".join(batch)

            for attempt in range(3):
                try:
                    async with http.get(
                        settings.EPSS_API_URL,
                        params={"cve": cve_param, "envelope": "true"},
                        timeout=aiohttp.ClientTimeout(total=60),
                    ) as resp:
                        resp.raise_for_status()
                        data = await resp.json()

                    for entry in data.get("data", []):
                        cve_id = entry.get("cve")
                        if cve_id:
                            score_map[cve_id] = {
                                "epss_score": float(entry.get("epss", 0)),
                                "epss_percentile": float(entry.get("percentile", 0)),
                                "epss_updated_at": datetime.now(timezone.utc),
                            }
                    break
                except Exception as e:
                    if attempt == 2:
                        logger.error(f"EPSS batch {i} failed: {e}")
                    else:
                        await asyncio.sleep(2 ** attempt)

            logger.info(f"  EPSS batch {i}–{i+len(batch)}/{len(all_cve_ids)}: got {len(score_map)} scores so far")
            await asyncio.sleep(0.5)  # Be nice to FIRST.org

    # Write scores to DB
    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        for cve_id, scores in score_map.items():
            await db.execute(
                update(CVE)
                .where(CVE.id == cve_id)
                .values(**scores)
            )
            updated += 1

        # Commit in one shot
        await db.commit()

    # Recompute xploit scores (EPSS affects the formula)
    async with AsyncSessionLocal() as db:
        # Only recompute where EPSS changed — fetch those CVEs
        result = await db.execute(
            select(CVE).where(CVE.id.in_(list(score_map.keys())))
        )
        cves = result.scalars().all()
        for cve in cves:
            cve.compute_xploit_score()
        await db.commit()

    duration = (datetime.now(timezone.utc) - log_start).total_seconds()
    result_data = {
        "source": "epss",
        "status": "success",
        "cves_queried": len(all_cve_ids),
        "scores_received": len(score_map),
        "updated": updated,
        "duration_secs": round(duration, 2),
    }
    logger.info(f"✅ EPSS sync: {result_data}")
    return result_data


async def sync_epss_full_csv() -> dict:
    """
    Alternative: Download the full daily EPSS CSV (all CVEs at once).
    More efficient when you have many CVEs. Use this for daily bulk refresh.
    
    URL: https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz
    """
    log_start = datetime.now(timezone.utc)
    today = date.today().strftime("%Y-%m-%d")
    url = settings.EPSS_CSV_URL.format(date=today)

    logger.info(f"📥 Downloading full EPSS CSV from {url}")

    async with aiohttp.ClientSession() as http:
        async with http.get(url, timeout=aiohttp.ClientTimeout(total=120)) as resp:
            resp.raise_for_status()
            compressed = await resp.read()

    # Decompress
    with gzip.open(io.BytesIO(compressed), "rt") as f:
        reader = csv.reader(f)
        next(reader)  # skip header comment line
        headers = next(reader)  # actual headers: cve, epss, percentile
        rows = list(reader)

    logger.info(f"EPSS CSV: {len(rows)} entries")

    # Get our CVE IDs
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(CVE.id))
        our_ids = set(row[0] for row in result.fetchall())

    now = datetime.now(timezone.utc)
    updates = []
    for row in rows:
        if len(row) < 3:
            continue
        cve_id, epss, percentile = row[0], row[1], row[2]
        if cve_id in our_ids:
            updates.append({
                "id": cve_id,
                "epss_score": float(epss),
                "epss_percentile": float(percentile),
                "epss_updated_at": now,
            })

    # Batch update
    async with AsyncSessionLocal() as db:
        for i in range(0, len(updates), 1000):
            batch = updates[i:i+1000]
            for rec in batch:
                await db.execute(
                    update(CVE)
                    .where(CVE.id == rec["id"])
                    .values(
                        epss_score=rec["epss_score"],
                        epss_percentile=rec["epss_percentile"],
                        epss_updated_at=rec["epss_updated_at"],
                    )
                )
            await db.commit()

    # Recompute xploit scores
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(CVE))
        cves = result.scalars().all()
        for cve in cves:
            cve.compute_xploit_score()
        await db.commit()

    duration = (datetime.now(timezone.utc) - log_start).total_seconds()
    result = {
        "source": "epss_csv",
        "status": "success",
        "total_in_csv": len(rows),
        "our_cves_updated": len(updates),
        "duration_secs": round(duration, 2),
    }
    logger.info(f"✅ EPSS CSV sync: {result}")
    return result
