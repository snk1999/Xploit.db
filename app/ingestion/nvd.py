"""
XPLOIT.DB — NVD Ingestion Pipeline

Fetches CVEs from NIST NVD API 2.0 with:
- Incremental sync (only new/modified since last run)
- Automatic retry + backoff on rate limits
- Full initial backfill support
- CVSS v2/v3.0/v3.1 normalization
"""

import asyncio
import aiohttp
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.models import CVE, SyncLog, SeverityEnum, SyncStatusEnum

logger = logging.getLogger(__name__)

NVD_PAGE_SIZE = 2000  # NVD max per request


def _parse_severity(score: Optional[float]) -> SeverityEnum:
    if score is None:
        return SeverityEnum.UNKNOWN
    if score >= 9.0:
        return SeverityEnum.CRITICAL
    if score >= 7.0:
        return SeverityEnum.HIGH
    if score >= 4.0:
        return SeverityEnum.MEDIUM
    if score > 0.0:
        return SeverityEnum.LOW
    return SeverityEnum.NONE


def _extract_cvss(metrics: dict) -> dict:
    """Extract best-available CVSS score from NVD metrics block."""
    result = {
        "cvss_v31_score": None, "cvss_v31_vector": None,
        "cvss_v30_score": None,
        "cvss_v2_score": None,
        "cvss_score": None,
    }

    v31 = metrics.get("cvssMetricV31", [{}])
    v30 = metrics.get("cvssMetricV30", [{}])
    v2  = metrics.get("cvssMetricV2",  [{}])

    if v31:
        d = v31[0].get("cvssData", {})
        result["cvss_v31_score"]  = d.get("baseScore")
        result["cvss_v31_vector"] = d.get("vectorString")

    if v30:
        d = v30[0].get("cvssData", {})
        result["cvss_v30_score"] = d.get("baseScore")

    if v2:
        d = v2[0].get("cvssData", {})
        result["cvss_v2_score"] = d.get("baseScore")

    # Best score priority: v3.1 > v3.0 > v2
    result["cvss_score"] = (
        result["cvss_v31_score"]
        or result["cvss_v30_score"]
        or result["cvss_v2_score"]
    )
    return result


def _extract_cwe(weaknesses: list) -> list:
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return list(set(cwes))


def _extract_products(configurations: list) -> list:
    """Pull affected vendor/product/version tuples from CPE configs."""
    products = []
    seen = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable"):
                    continue
                uri = cpe_match.get("criteria", "")
                parts = uri.split(":")
                if len(parts) >= 5:
                    vendor  = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if len(parts) > 5 else "*"
                    key = f"{vendor}:{product}"
                    if key not in seen:
                        seen.add(key)
                        products.append({
                            "vendor": vendor,
                            "product": product,
                            "version": version,
                        })
    return products[:50]  # cap to avoid huge JSON blobs


def _build_cve_record(vuln_data: dict) -> dict:
    """Transform NVD API response into our CVE model dict."""
    cve = vuln_data.get("cve", vuln_data)  # handle both wrapper formats

    cve_id = cve.get("id")
    descriptions = cve.get("descriptions", [])
    en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

    metrics = cve.get("metrics", {})
    cvss    = _extract_cvss(metrics)
    severity = _parse_severity(cvss["cvss_score"])

    weaknesses     = cve.get("weaknesses", [])
    cwe_ids        = _extract_cwe(weaknesses)
    configurations = cve.get("configurations", [])
    products       = _extract_products(configurations)

    references = [
        {"url": r.get("url"), "tags": r.get("tags", [])}
        for r in cve.get("references", [])
    ]

    published = cve.get("published")
    modified  = cve.get("lastModified")

    def parse_dt(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None

    return {
        "id":                  cve_id,
        "description":         en_desc,
        "published_at":        parse_dt(published),
        "modified_at":         parse_dt(modified),
        **cvss,
        "severity":            severity,
        "cwe_ids":             cwe_ids,
        "affected_products":   products,
        "references":          references,
        "nvd_raw":             None,  # omit to save space; re-fetch if needed
        "updated_at":          datetime.now(timezone.utc),
    }


async def _fetch_nvd_page(
    session: aiohttp.ClientSession,
    start_index: int,
    params: dict,
) -> dict:
    """Fetch a single NVD results page with retry logic."""
    rate_sleep = (
        settings.NVD_RATE_LIMIT_SLEEP_KEY
        if settings.NVD_API_KEY
        else settings.NVD_RATE_LIMIT_SLEEP
    )
    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    request_params = {
        **params,
        "startIndex": start_index,
        "resultsPerPage": NVD_PAGE_SIZE,
    }

    for attempt in range(5):
        try:
            async with session.get(
                settings.NVD_BASE_URL,
                params=request_params,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status == 429:
                    wait = 30 * (attempt + 1)
                    logger.warning(f"NVD rate limit hit, sleeping {wait}s")
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()
                await asyncio.sleep(rate_sleep)
                return await resp.json()
        except aiohttp.ClientError as e:
            if attempt == 4:
                raise
            wait = 5 * (2 ** attempt)
            logger.warning(f"NVD fetch error (attempt {attempt+1}): {e}. Retry in {wait}s")
            await asyncio.sleep(wait)

    raise RuntimeError("NVD fetch failed after 5 attempts")


async def _upsert_cves(db: AsyncSession, records: list[dict]) -> tuple[int, int]:
    """Upsert a batch of CVE records. Returns (added, updated)."""
    if not records:
        return 0, 0

    stmt = pg_insert(CVE).values(records)
    stmt = stmt.on_conflict_do_update(
        index_elements=["id"],
        set_={
            "description":       stmt.excluded.description,
            "modified_at":       stmt.excluded.modified_at,
            "cvss_v31_score":    stmt.excluded.cvss_v31_score,
            "cvss_v31_vector":   stmt.excluded.cvss_v31_vector,
            "cvss_v30_score":    stmt.excluded.cvss_v30_score,
            "cvss_v2_score":     stmt.excluded.cvss_v2_score,
            "cvss_score":        stmt.excluded.cvss_score,
            "severity":          stmt.excluded.severity,
            "cwe_ids":           stmt.excluded.cwe_ids,
            "affected_products": stmt.excluded.affected_products,
            "references":        stmt.excluded.references,
            "updated_at":        stmt.excluded.updated_at,
        }
    )
    result = await db.execute(stmt)
    await db.commit()

    # SQLAlchemy doesn't directly expose added vs updated count cleanly here,
    # so we return total as added for simplicity.
    return len(records), 0


async def sync_nvd(
    full: bool = False,
    days_back: int = 1,
) -> dict:
    """
    Main NVD sync function.

    Args:
        full:      If True, fetch ALL CVEs ever (initial backfill).
        days_back: If not full, fetch CVEs modified in last N days.

    Returns:
        Summary dict with counts and status.
    """
    log_start = datetime.now(timezone.utc)
    total_fetched = 0
    total_added   = 0
    source_name   = "nvd_full" if full else "nvd_incremental"

    async with AsyncSessionLocal() as db:
        # Create sync log entry
        sync_log = SyncLog(source=source_name, status=SyncStatusEnum.RUNNING)
        db.add(sync_log)
        await db.commit()
        await db.refresh(sync_log)
        sync_id = sync_log.id

    try:
        params = {}
        if not full:
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=days_back)
            params["modStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
            params["modEndDate"]   = now.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

        async with aiohttp.ClientSession() as http:
            # First page to get total count
            logger.info(f"Starting NVD sync (full={full}, params={params})")
            first_page = await _fetch_nvd_page(http, 0, params)
            total_results = first_page.get("totalResults", 0)
            logger.info(f"NVD total results: {total_results}")

            all_pages = [first_page]

            # Fetch remaining pages concurrently (but throttled)
            for start_index in range(NVD_PAGE_SIZE, total_results, NVD_PAGE_SIZE):
                page = await _fetch_nvd_page(http, start_index, params)
                all_pages.append(page)
                logger.info(f"  Fetched page starting at {start_index}/{total_results}")

        # Process all pages
        async with AsyncSessionLocal() as db:
            for page in all_pages:
                vulns = page.get("vulnerabilities", [])
                records = []
                for v in vulns:
                    try:
                        rec = _build_cve_record(v)
                        if rec.get("id"):
                            records.append(rec)
                    except Exception as e:
                        logger.warning(f"Failed to parse CVE: {e}")

                total_fetched += len(records)

                # Batch upsert in chunks of 500
                for i in range(0, len(records), 500):
                    batch = records[i:i+500]
                    added, _ = await _upsert_cves(db, batch)
                    total_added += added

        # After CVE insert, recompute xploit scores for new records
        await _recompute_xploit_scores_batch()

        # Update sync log
        duration = (datetime.now(timezone.utc) - log_start).total_seconds()
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(SyncLog)
                .where(SyncLog.id == sync_id)
                .values(
                    status=SyncStatusEnum.SUCCESS,
                    finished_at=datetime.now(timezone.utc),
                    duration_secs=duration,
                    records_fetched=total_fetched,
                    records_added=total_added,
                )
            )
            await db.commit()

        result = {
            "source": source_name,
            "status": "success",
            "fetched": total_fetched,
            "added": total_added,
            "duration_secs": round(duration, 2),
        }
        logger.info(f"✅ NVD sync complete: {result}")
        return result

    except Exception as e:
        logger.error(f"❌ NVD sync failed: {e}", exc_info=True)
        duration = (datetime.now(timezone.utc) - log_start).total_seconds()
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(SyncLog)
                .where(SyncLog.id == sync_id)
                .values(
                    status=SyncStatusEnum.FAILED,
                    finished_at=datetime.now(timezone.utc),
                    duration_secs=duration,
                    error_message=str(e),
                )
            )
            await db.commit()
        raise


async def _recompute_xploit_scores_batch():
    """Recompute xploit_score for all CVEs where it may be stale."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(CVE))
        cves = result.scalars().all()
        for cve in cves:
            cve.compute_xploit_score()
        await db.commit()
        logger.info(f"Recomputed xploit scores for {len(cves)} CVEs")
