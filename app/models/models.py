from sqlalchemy import (
    Column, String, Float, Integer, Boolean, DateTime,
    Text, JSON, ForeignKey, UniqueConstraint, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum
from app.core.database import Base


class SeverityEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    NONE     = "NONE"
    UNKNOWN  = "UNKNOWN"

class ExploitSourceEnum(str, enum.Enum):
    EXPLOITDB   = "exploitdb"
    GITHUB_POC  = "github_poc"
    METASPLOIT  = "metasploit"
    NUCLEI      = "nuclei"
    PACKETSTORM = "packetstorm"

class ExploitTypeEnum(str, enum.Enum):
    REMOTE    = "remote"
    LOCAL     = "local"
    WEBAPPS   = "webapps"
    DOS       = "dos"
    SHELLCODE = "shellcode"
    PAPERS    = "papers"
    UNKNOWN   = "unknown"

class SyncStatusEnum(str, enum.Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED  = "failed"
    RUNNING = "running"


class CVE(Base):
    __tablename__ = "cves"

    id                = Column(String(30), primary_key=True)
    description       = Column(Text, nullable=True)
    published_at      = Column(DateTime(timezone=True), nullable=True)
    modified_at       = Column(DateTime(timezone=True), nullable=True)
    cvss_v31_score    = Column(Float, nullable=True)
    cvss_v31_vector   = Column(String(200), nullable=True)
    cvss_v30_score    = Column(Float, nullable=True)
    cvss_v2_score     = Column(Float, nullable=True)
    cvss_score        = Column(Float, nullable=True)
    severity          = Column(SAEnum(SeverityEnum), default=SeverityEnum.UNKNOWN)
    cwe_ids           = Column(JSON, default=list)
    affected_products = Column(JSON, default=list)
    kev               = Column(Boolean, default=False)
    kev_date_added    = Column(DateTime(timezone=True), nullable=True)
    kev_due_date      = Column(String(20), nullable=True)
    kev_ransomware    = Column(String(50), nullable=True)
    epss_score        = Column(Float, nullable=True)
    epss_percentile   = Column(Float, nullable=True)
    epss_updated_at   = Column(DateTime(timezone=True), nullable=True)
    has_exploitdb     = Column(Boolean, default=False)
    has_github_poc    = Column(Boolean, default=False)
    has_metasploit    = Column(Boolean, default=False)
    has_nuclei        = Column(Boolean, default=False)
    has_packetstorm   = Column(Boolean, default=False)
    has_any_exploit   = Column(Boolean, default=False)
    exploit_count     = Column(Integer, default=0)
    xploit_score      = Column(Float, default=0.0)
    references        = Column(JSON, default=list)
    created_at        = Column(DateTime(timezone=True), server_default=func.now())
    updated_at        = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

    exploits = relationship("Exploit", back_populates="cve", cascade="all, delete-orphan")

    def compute_xploit_score(self) -> float:
        score = 0.0
        if self.cvss_score:
            score += min(self.cvss_score * 4.0, 40.0)
        if self.epss_score:
            score += self.epss_score * 20.0
        if self.kev:
            score += 20.0
        if self.has_metasploit:
            score += 10.0
        if self.has_nuclei:
            score += 5.0
        if self.has_exploitdb or self.has_github_poc or self.has_packetstorm:
            score += 5.0
        self.xploit_score = round(min(score, 100.0), 2)
        return self.xploit_score


class Exploit(Base):
    __tablename__ = "exploits"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    cve_id          = Column(String(30), ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    source          = Column(SAEnum(ExploitSourceEnum), nullable=False)
    source_id       = Column(String(200), nullable=True)
    source_url      = Column(Text, nullable=True)
    title           = Column(Text, nullable=True)
    description     = Column(Text, nullable=True)
    author          = Column(String(200), nullable=True)
    exploit_type    = Column(SAEnum(ExploitTypeEnum), default=ExploitTypeEnum.UNKNOWN)
    platform        = Column(String(100), nullable=True)
    language        = Column(String(50), nullable=True)
    github_stars    = Column(Integer, nullable=True)
    github_forks    = Column(Integer, nullable=True)
    github_owner    = Column(String(200), nullable=True)
    nuclei_verified = Column(Boolean, default=False)
    nuclei_severity = Column(String(20), nullable=True)
    nuclei_tags     = Column(JSON, default=list)
    edb_id          = Column(Integer, nullable=True)
    raw_content     = Column(Text, nullable=True)
    content_hash    = Column(String(64), nullable=True)
    quality_score   = Column(Integer, default=0)
    published_at    = Column(DateTime(timezone=True), nullable=True)
    fetched_at      = Column(DateTime(timezone=True), server_default=func.now())
    updated_at      = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

    cve = relationship("CVE", back_populates="exploits")

    __table_args__ = (
        UniqueConstraint("source", "source_id", name="uq_exploit_source_id"),
    )


class SyncLog(Base):
    __tablename__ = "sync_logs"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    source          = Column(String(50), nullable=False)
    status          = Column(SAEnum(SyncStatusEnum), default=SyncStatusEnum.RUNNING)
    started_at      = Column(DateTime(timezone=True), server_default=func.now())
    finished_at     = Column(DateTime(timezone=True), nullable=True)
    duration_secs   = Column(Float, nullable=True)
    records_fetched = Column(Integer, default=0)
    records_added   = Column(Integer, default=0)
    records_updated = Column(Integer, default=0)
    error_message   = Column(Text, nullable=True)
    extra_data      = Column(JSON, default=dict)
