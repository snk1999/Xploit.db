from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timezone, timedelta
from app.core.database import get_db
from app.models.models import CVE, Exploit, SyncLog, SeverityEnum

router = APIRouter()

@router.get("/summary")
async def get_summary(db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    thirty_days = now - timedelta(days=30)
    seven_days  = now - timedelta(days=7)
    async def count(q): return (await db.execute(q)).scalar_one()
    total_cves        = await count(select(func.count(CVE.id)))
    total_exploits    = await count(select(func.count(Exploit.id)))
    cves_with_exploit = await count(select(func.count(CVE.id)).where(CVE.has_any_exploit == True))
    kev_count         = await count(select(func.count(CVE.id)).where(CVE.kev == True))
    critical_30d      = await count(select(func.count(CVE.id)).where(CVE.severity == SeverityEnum.CRITICAL, CVE.published_at >= thirty_days))
    high_30d          = await count(select(func.count(CVE.id)).where(CVE.severity == SeverityEnum.HIGH, CVE.published_at >= thirty_days))
    new_7d            = await count(select(func.count(CVE.id)).where(CVE.published_at >= seven_days))
    msf_count         = await count(select(func.count(CVE.id)).where(CVE.has_metasploit == True))
    nuclei_count      = await count(select(func.count(CVE.id)).where(CVE.has_nuclei == True))
    sev_rows = (await db.execute(select(CVE.severity, func.count(CVE.id)).group_by(CVE.severity))).fetchall()
    severity_breakdown = {row[0].value if row[0] else "UNKNOWN": row[1] for row in sev_rows}
    top_cves = (await db.execute(select(CVE).order_by(CVE.xploit_score.desc().nulls_last()).limit(5))).scalars().all()
    sync_rows = (await db.execute(select(SyncLog.source, func.max(SyncLog.finished_at)).where(SyncLog.status == "success").group_by(SyncLog.source))).fetchall()
    last_syncs = {row[0]: row[1].isoformat() if row[1] else None for row in sync_rows}
    return {
        "totals": {
            "cves": total_cves, "exploits": total_exploits,
            "cves_with_exploit": cves_with_exploit, "kev": kev_count,
            "with_metasploit": msf_count, "with_nuclei": nuclei_count,
            "exploit_coverage_pct": round(cves_with_exploit / max(total_cves, 1) * 100, 1),
        },
        "last_30_days": {"critical": critical_30d, "high": high_30d},
        "last_7_days": {"new_cves": new_7d},
        "severity_breakdown": severity_breakdown,
        "top_priority_cves": [{"id": c.id, "xploit_score": c.xploit_score, "cvss_score": c.cvss_score, "severity": c.severity.value if c.severity else None, "kev": c.kev, "has_metasploit": c.has_metasploit, "description": (c.description or "")[:120]} for c in top_cves],
        "last_syncs": last_syncs,
    }

@router.get("/sync-health")
async def get_sync_health(db: AsyncSession = Depends(get_db)):
    q = select(SyncLog).order_by(desc(SyncLog.started_at)).limit(20)
    logs = (await db.execute(q)).scalars().all()
    return [{"source": l.source, "status": l.status.value if l.status else None, "started_at": l.started_at.isoformat() if l.started_at else None, "duration_secs": l.duration_secs, "records_added": l.records_added, "error": l.error_message} for l in logs]
