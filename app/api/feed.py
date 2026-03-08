from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_
from datetime import datetime, timezone, timedelta
from typing import Optional
from app.core.database import get_db
from app.models.models import CVE
from app.api.cves import _serialize_cve

router = APIRouter()

@router.get("/latest")
async def latest_feed(
    hours: int = Query(24, ge=1, le=168),
    severity: Optional[str] = Query(None),
    exploit_only: bool = Query(False),
    kev_only: bool = Query(False),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    filters = [CVE.published_at >= cutoff]
    if severity: filters.append(CVE.severity.in_([s.strip().upper() for s in severity.split(",")]))
    if exploit_only: filters.append(CVE.has_any_exploit == True)
    if kev_only: filters.append(CVE.kev == True)
    rows = (await db.execute(select(CVE).where(and_(*filters)).order_by(CVE.cvss_score.desc().nulls_last()).limit(size))).scalars().all()
    return {"window_hours": hours, "count": len(rows), "generated_at": datetime.now(timezone.utc).isoformat(), "data": [_serialize_cve(r) for r in rows]}

@router.get("/hotlist")
async def hotlist(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(CVE).where(CVE.xploit_score >= 70).order_by(CVE.xploit_score.desc().nulls_last()).limit(25))).scalars().all()
    return {"title": "XPLOIT.DB Hotlist", "count": len(rows), "generated_at": datetime.now(timezone.utc).isoformat(), "data": [_serialize_cve(r) for r in rows]}
