"""
XPLOIT.DB — API Routes: CVEs
"""

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc
from typing import Optional
from datetime import datetime, timezone, timedelta

from app.core.database import get_db
from app.core.config import settings
from app.models.models import CVE, Exploit, SeverityEnum

router = APIRouter()


def _build_filters(
    severity: Optional[str] = None,
    kev_only: bool = False,
    has_exploit: bool = False,
    has_metasploit: bool = False,
    has_nuclei: bool = False,
    min_cvss: Optional[float] = None,
    max_cvss: Optional[float] = None,
    min_epss: Optional[float] = None,
    min_xploit: Optional[float] = None,
    days: Optional[int] = None,
    vendor: Optional[str] = None,
    cwe: Optional[str] = None,
):
    filters = []
    if severity:
        sevs = [s.strip().upper() for s in severity.split(",")]
        filters.append(CVE.severity.in_(sevs))
    if kev_only:
        filters.append(CVE.kev == True)
    if has_exploit:
        filters.append(CVE.has_any_exploit == True)
    if has_metasploit:
        filters.append(CVE.has_metasploit == True)
    if has_nuclei:
        filters.append(CVE.has_nuclei == True)
    if min_cvss is not None:
        filters.append(CVE.cvss_score >= min_cvss)
    if max_cvss is not None:
        filters.append(CVE.cvss_score <= max_cvss)
    if min_epss is not None:
        filters.append(CVE.epss_score >= min_epss)
    if min_xploit is not None:
        filters.append(CVE.xploit_score >= min_xploit)
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        filters.append(CVE.published_at >= cutoff)
    if vendor:
        # Search in affected_products JSON array
        filters.append(
            CVE.affected_products.cast(str).ilike(f"%{vendor}%")
        )
    if cwe:
        filters.append(CVE.cwe_ids.cast(str).ilike(f"%{cwe}%"))
    return filters


@router.get("/")
async def list_cves(
    # Pagination
    page: int = Query(1, ge=1),
    size: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    # Sorting
    sort: str = Query("published_at", description="Field to sort by: published_at, cvss_score, xploit_score, epss_score"),
    order: str = Query("desc", description="asc or desc"),
    # Filters
    severity:       Optional[str]   = Query(None, description="CRITICAL,HIGH,MEDIUM,LOW (comma-separated)"),
    kev_only:       bool             = Query(False),
    has_exploit:    bool             = Query(False),
    has_metasploit: bool             = Query(False),
    has_nuclei:     bool             = Query(False),
    min_cvss:       Optional[float]  = Query(None, ge=0, le=10),
    max_cvss:       Optional[float]  = Query(None, ge=0, le=10),
    min_epss:       Optional[float]  = Query(None, ge=0, le=1),
    min_xploit:     Optional[float]  = Query(None, ge=0, le=100),
    days:           Optional[int]    = Query(None, description="Published within last N days"),
    vendor:         Optional[str]    = Query(None),
    cwe:            Optional[str]    = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    List CVEs with rich filtering and sorting.
    
    This is the main exploration endpoint. Supports every combination of:
    - Severity filtering
    - KEV / exploit presence flags
    - CVSS, EPSS, XPLOIT score thresholds
    - Time windows (last N days)
    - Vendor / CWE filtering
    - Sorting by any score
    """
    filters = _build_filters(
        severity=severity, kev_only=kev_only,
        has_exploit=has_exploit, has_metasploit=has_metasploit,
        has_nuclei=has_nuclei, min_cvss=min_cvss, max_cvss=max_cvss,
        min_epss=min_epss, min_xploit=min_xploit,
        days=days, vendor=vendor, cwe=cwe,
    )

    # Sorting
    sort_field_map = {
        "published_at": CVE.published_at,
        "cvss_score":   CVE.cvss_score,
        "xploit_score": CVE.xploit_score,
        "epss_score":   CVE.epss_score,
        "modified_at":  CVE.modified_at,
    }
    sort_col = sort_field_map.get(sort, CVE.published_at)
    order_fn = desc if order.lower() == "desc" else asc

    # Total count
    count_q = select(func.count(CVE.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar_one()

    # Data query
    q = select(CVE).where(and_(*filters)).order_by(order_fn(sort_col)).offset((page - 1) * size).limit(size)
    rows = (await db.execute(q)).scalars().all()

    return {
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
        "data": [_serialize_cve(r) for r in rows],
    }


@router.get("/{cve_id}")
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    """
    Get full CVE detail including all associated exploits.
    """
    cve_id = cve_id.upper()
    q = select(CVE).where(CVE.id == cve_id)
    cve = (await db.execute(q)).scalar_one_or_none()
    if not cve:
        raise HTTPException(404, f"{cve_id} not found in database")

    # Fetch exploits
    exp_q = select(Exploit).where(Exploit.cve_id == cve_id).order_by(desc(Exploit.quality_score))
    exploits = (await db.execute(exp_q)).scalars().all()

    data = _serialize_cve(cve, full=True)
    data["exploits"] = [_serialize_exploit(e) for e in exploits]
    return data


def _serialize_cve(cve: CVE, full: bool = False) -> dict:
    d = {
        "id":              cve.id,
        "description":     cve.description,
        "published_at":    cve.published_at.isoformat() if cve.published_at else None,
        "modified_at":     cve.modified_at.isoformat() if cve.modified_at else None,
        "cvss_score":      cve.cvss_score,
        "cvss_v31_score":  cve.cvss_v31_score,
        "severity":        cve.severity.value if cve.severity else "UNKNOWN",
        "epss_score":      cve.epss_score,
        "epss_percentile": cve.epss_percentile,
        "xploit_score":    cve.xploit_score,
        "kev":             cve.kev,
        "kev_date_added":  cve.kev_date_added.isoformat() if cve.kev_date_added else None,
        "kev_ransomware":  cve.kev_ransomware,
        "has_any_exploit": cve.has_any_exploit,
        "exploit_count":   cve.exploit_count,
        "exploit_sources": {
            "exploitdb":   cve.has_exploitdb,
            "github_poc":  cve.has_github_poc,
            "metasploit":  cve.has_metasploit,
            "nuclei":      cve.has_nuclei,
            "packetstorm": cve.has_packetstorm,
        },
        "cwe_ids":          cve.cwe_ids,
    }
    if full:
        d.update({
            "cvss_v31_vector":   cve.cvss_v31_vector,
            "cvss_v30_score":    cve.cvss_v30_score,
            "cvss_v2_score":     cve.cvss_v2_score,
            "affected_products": cve.affected_products,
            "references":        cve.references,
            "kev_due_date":      cve.kev_due_date,
        })
    return d


def _serialize_exploit(e: Exploit) -> dict:
    return {
        "id":              e.id,
        "source":          e.source.value if e.source else None,
        "source_id":       e.source_id,
        "source_url":      e.source_url,
        "title":           e.title,
        "author":          e.author,
        "exploit_type":    e.exploit_type.value if e.exploit_type else None,
        "platform":        e.platform,
        "language":        e.language,
        "github_stars":    e.github_stars,
        "github_forks":    e.github_forks,
        "nuclei_verified": e.nuclei_verified,
        "quality_score":   e.quality_score,
        "published_at":    e.published_at.isoformat() if e.published_at else None,
        "edb_id":          e.edb_id,
    }
