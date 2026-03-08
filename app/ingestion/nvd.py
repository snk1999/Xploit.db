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

NVD_PAGE_SIZE = 2000


# ─── Helpers ─────────────────────────────────────────────────────────────────

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
    result = {
        "cvss_v31_score": None,
        "cvss_v31_vector": None,
        "cvss_v30_score": None,
        "cvss_v2_score": None,
        "cvss_score": None,
    }

    v31 = metrics.get("cvssMetricV31", [])
    v30 = metrics.get("cvssMetricV30", [])
    v2  = metrics.get("cvssMetricV2",  [])

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
    return products[:50]


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _build_cve_record(vuln_data: dict) -> dict:
    cve = vuln_data.get("cve", vuln_data)

    cve_id       = cve.get("id")
    descriptions = cve.get("descriptions", [])
    en_desc      = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

    metrics  = cve.get("metrics", {})
    cvss     = _extract_cvss(metrics)
    severity = _parse_severity(cvss["cvss_score"])

    cwe_ids  = _extract_cwe(cve.get("weaknesses", []))
    products = _extract_products(cve.get("configurations", []))

    references = [
        {"url": r.get("url"), "tags": r.get("tags", [])}
        for r in cve.get("references", [])
    ]

    return {
        "id":                cve_id,
        "description":       en_desc,
        "published_at":      _parse_dt(cve.get("published")),
        "modified_at":       _parse_dt(cve.get("lastModified")),
        **cvss,
        "severity":          severity,
        "cwe_ids":           cwe_ids,
        "affected_products": products,
        "references":        references,
        "updated_at":        datetime.now(timezone.utc),
    }


def _is_rejected_cve(description: Optional[str]) -> bool:
    """
    Check if a CVE should be rejected based on its description containing
    specific rejection strings.
    """
    if not description:
        return False

    rejected_patterns = [
        "Rejected reason: This CVE ID was rejected because it was reserved but not used for a vulnerability disclosure.",
        "Rejected reason: ** REJECT ** DO NOT USE THIS CVE RECORD. ConsultIDs: none. Reason: This record was in a CNA pool that was not assigned to any issues during",
        "Rejected reason: Not used"
    ]

    return any(pattern in description for pattern in rejected_patterns)


async def _cleanup_rejected_cves():
    """
    Remove any CVEs from the database that contain rejection strings in their descriptions.
    This cleans up CVEs that were ingested before the rejection filtering was implemented.
    """
    from sqlalchemy import delete

    async with AsyncSessionLocal() as db:
        # Get all CVEs
        result = await db.execute(select(CVE))
        cves = result.scalars().all()

        rejected_ids = []
        for cve in cves:
            if _is_rejected_cve(cve.description):
                rejected_ids.append(cve.id)

        if rejected_ids:
            # Delete rejected CVEs
            await db.execute(delete(CVE).where(CVE.id.in_(rejected_ids)))
            await db.commit()
            logger.info(f"Cleaned up {len(rejected_ids)} rejected CVEs: {rejected_ids}")
        else:
            logger.debug("No rejected CVEs found to clean up")


# ─── NVD Fetch ───────────────────────────────────────────────────────────────

async def _fetch_nvd_page(
    session: aiohttp.ClientSession,
    start_index: int,
    date_params: dict,
) -> dict:
    """
    Fetch one page from NVD API.
    Builds the URL as a plain string to avoid aiohttp encoding
    the date parameters (+ sign gets mangled).
    """
    rate_sleep = (
        settings.NVD_RATE_LIMIT_SLEEP_KEY
        if settings.NVD_API_KEY
        else settings.NVD_RATE_LIMIT_SLEEP
    )

    headers = {"User-Agent": "XPLOIT.DB/1.0"}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    # Build query string manually — do NOT use aiohttp params= argument
    # because it URL-encodes the date strings and NVD rejects them
    parts = []
    for k, v in date_params.items():
        parts.append(f"{k}={v}")
    parts.append(f"startIndex={start_index}")
    parts.append(f"resultsPerPage={NVD_PAGE_SIZE}")
    url = settings.NVD_BASE_URL + "?" + "&".join(parts)

    for attempt in range(5):
        try:
            logger.debug(f"GET {url}")
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status == 429:
                    wait = 30 * (attempt + 1)
                    logger.warning(f"NVD rate limit — sleeping {wait}s")
                    await asyncio.sleep(wait)
                    continue
                if resp.status == 404:
                    body = await resp.text()
                    logger.error(f"NVD 404. URL={url} Body={body[:300]}")
                    raise RuntimeError(f"NVD returned 404: {body[:200]}")
                resp.raise_for_status()
                await asyncio.sleep(rate_sleep)
                return await resp.json()

        except RuntimeError:
            raise
        except Exception as e:
            if attempt == 4:
                raise
            wait = 5 * (2 ** attempt)
            logger.warning(f"NVD error attempt {attempt+1}: {e} — retry in {wait}s")
            await asyncio.sleep(wait)

    raise RuntimeError("NVD fetch failed after 5 attempts")


# ─── Upsert ──────────────────────────────────────────────────────────────────

async def _upsert_cves(db: AsyncSession, records: list) -> int:
    if not records:
        return 0
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
    await db.execute(stmt)
    await db.commit()
    return len(records)


# ─── Main Sync ───────────────────────────────────────────────────────────────

async def sync_nvd(full: bool = False, days_back: int = 2) -> dict:
    """
    Main NVD sync entry point.

    Args:
        full:      Fetch ALL CVEs ever (initial backfill ~200k).
        days_back: For incremental — fetch CVEs published in last N days.

    Returns:
        Summary dict.
    """
    log_start = datetime.now(timezone.utc)
    total_fetched = 0
    total_added   = 0
    source_name   = "nvd_full" if full else "nvd_incremental"

    # Create sync log entry
    async with AsyncSessionLocal() as db:
        sync_log = SyncLog(source=source_name, status=SyncStatusEnum.RUNNING)
        db.add(sync_log)
        await db.commit()
        await db.refresh(sync_log)
        sync_id = sync_log.id

    try:
        # Build date params — plain strings, NO timezone suffix
        date_params = {}
        if not full:
            now   = datetime.now(timezone.utc)
            start = now - timedelta(days=days_back)
            date_params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            date_params["pubEndDate"]   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        logger.info(f"Starting NVD sync (full={full}, params={date_params})")

        async with aiohttp.ClientSession() as http:
            # Fetch first page to get total count
            first = await _fetch_nvd_page(http, 0, date_params)
            total_results = first.get("totalResults", 0)
            logger.info(f"NVD total results: {total_results}")

            all_pages = [first]

            # Fetch remaining pages sequentially (respect rate limits)
            for start_idx in range(NVD_PAGE_SIZE, total_results, NVD_PAGE_SIZE):
                page = await _fetch_nvd_page(http, start_idx, date_params)
                all_pages.append(page)
                logger.info(f"  Page {start_idx}/{total_results}")

        # Parse and upsert all pages
        async with AsyncSessionLocal() as db:
            for page in all_pages:
                vulns = page.get("vulnerabilities", [])
                records = []
                for v in vulns:
                    try:
                        rec = _build_cve_record(v)
                        if rec.get("id") and not _is_rejected_cve(rec.get("description")):
                            records.append(rec)
                        elif rec.get("id") and _is_rejected_cve(rec.get("description")):
                            logger.debug(f"Skipping rejected CVE: {rec['id']}")
                    except Exception as e:
                        logger.warning(f"Parse error: {e}")

                total_fetched += len(records)

                # Batch upsert in chunks of 500
                for i in range(0, len(records), 500):
                    batch = records[i:i+500]
                    added = await _upsert_cves(db, batch)
                    total_added += added
                    logger.info(f"  Upserted {total_added}/{total_fetched}")

        # Recompute xploit scores
        await _recompute_scores()

        # Clean up any rejected CVEs that may have been previously ingested
        await _cleanup_rejected_cves()

        # Update sync log
        duration = (datetime.now(timezone.utc) - log_start).total_seconds()
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(SyncLog).where(SyncLog.id == sync_id).values(
                    status=SyncStatusEnum.SUCCESS,
                    finished_at=datetime.now(timezone.utc),
                    duration_secs=duration,
                    records_fetched=total_fetched,
                    records_added=total_added,
                )
            )
            await db.commit()

        result = {
            "source":       source_name,
            "status":       "success",
            "fetched":      total_fetched,
            "added":        total_added,
            "duration_secs": round(duration, 2),
        }
        logger.info(f"NVD sync complete: {result}")
        return result

    except Exception as e:
        logger.error(f"NVD sync failed: {e}", exc_info=True)
        duration = (datetime.now(timezone.utc) - log_start).total_seconds()
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(SyncLog).where(SyncLog.id == sync_id).values(
                    status=SyncStatusEnum.FAILED,
                    finished_at=datetime.now(timezone.utc),
                    duration_secs=duration,
                    error_message=str(e),
                )
            )
            await db.commit()
        raise


async def _recompute_scores():
    """Recompute xploit_score for all CVEs."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(CVE))
        cves = result.scalars().all()
        for cve in cves:
            cve.compute_xploit_score()
        await db.commit()
        logger.info(f"Recomputed scores for {len(cves)} CVEs")
