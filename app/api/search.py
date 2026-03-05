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
    db: AsyncSession = Depends(get_db),
):
    search_term = f"%{q}%"
    filters = or_(CVE.id.ilike(search_term), CVE.description.ilike(search_term), CVE.affected_products.cast(str).ilike(search_term))
    total = (await db.execute(select(func.count(CVE.id)).where(filters))).scalar_one()
    rows  = (await db.execute(select(CVE).where(filters).order_by(desc(CVE.xploit_score)).offset((page-1)*size).limit(size))).scalars().all()
    return {"query": q, "total": total, "page": page, "size": size, "pages": (total + size - 1) // size, "data": [_serialize_cve(r) for r in rows]}
