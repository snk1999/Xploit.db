from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, desc, func
from app.core.database import get_db
from app.models.models import CVE
from app.api.cves import _serialize_cve
from app.core.config import settings

router = APIRouter()

@router.get("/")
async def full_text_search(
    q: str = Query(..., min_length=2),
    page: int = Query(1, ge=1),
    size: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    sort: str = Query("published_at", description="Field to sort by: published_at, cvss_score, xploit_score, epss_score"),
    order: str = Query("desc", description="asc or desc"),
    db: AsyncSession = Depends(get_db),
):
    search_term = f"%{q}%"
    filters = or_(CVE.id.ilike(search_term), CVE.description.ilike(search_term), CVE.affected_products.cast(str).ilike(search_term))
    total = (await db.execute(select(func.count(CVE.id)).where(filters))).scalar_one()
    
    # Sorting logic matching the main CVE API
    sort_field_map = {
        "published_at": CVE.published_at,
        "cvss_score":   CVE.cvss_score,
        "xploit_score": CVE.xploit_score,
        "epss_score":   CVE.epss_score,
        "modified_at":  CVE.modified_at,
    }
    sort_col = sort_field_map.get(sort, CVE.published_at)
    
    # Handle NULL values differently based on field type
    if sort in ["cvss_score", "xploit_score", "epss_score"]:
        # For score fields: NULL = lowest priority
        if order.lower() == "desc":
            sort_col = sort_col.desc().nulls_last()
        else:
            sort_col = sort_col.asc().nulls_first()
    else:
        # For date fields: NULL dates always come last
        if order.lower() == "desc":
            sort_col = sort_col.desc().nulls_last()
        else:
            sort_col = sort_col.asc().nulls_last()
    
    rows = (await db.execute(select(CVE).where(filters).order_by(sort_col).offset((page-1)*size).limit(size))).scalars().all()
    return {"query": q, "total": total, "page": page, "size": size, "pages": (total + size - 1) // size, "data": [_serialize_cve(r) for r in rows]}
