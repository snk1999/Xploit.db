from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import logging
from sqlalchemy import text

from app.api import cves, exploits, stats, search, feed
from app.core.config import settings
from app.core.database import engine, Base
from app.core.scheduler import start_scheduler, stop_scheduler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("xploitdb")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 XPLOIT.DB starting up...")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all, checkfirst=True)
        logger.info("✅ Database tables ready")
    except Exception as e:
        logger.error(f"DB init error: {e}")
        raise
    await start_scheduler()
    yield
    logger.info("🛑 Shutting down...")
    await stop_scheduler()


app = FastAPI(
    title="XPLOIT.DB API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cves.router,     prefix="/api/v1/cves",     tags=["CVEs"])
app.include_router(exploits.router, prefix="/api/v1/exploits", tags=["Exploits"])
app.include_router(stats.router,    prefix="/api/v1/stats",    tags=["Statistics"])
app.include_router(search.router,   prefix="/api/v1/search",   tags=["Search"])
app.include_router(feed.router,     prefix="/api/v1/feed",     tags=["Feed"])

@app.get("/")
async def root():
    return {"service": "XPLOIT.DB API", "version": "1.0.0", "status": "operational", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "ok"}
