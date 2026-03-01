import uuid
import time
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    phase: str
    recommendation: str = ""
    cvss_score: float = 0.0
    references: List[str] = field(default_factory=list)
    category: str = ""
    module: str = ""
    evidence: str = ""


@dataclass
class AuditEntry:
    timestamp: float
    action: str
    details: str
    phase: str = ""


@dataclass
class AssessmentJob:
    job_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: str = ""
    hostname: str = ""
    scheme: str = "https"
    port: Optional[int] = None
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    findings: List[Finding] = field(default_factory=list)
    audit_log: List[AuditEntry] = field(default_factory=list)
    phases_completed: List[str] = field(default_factory=list)
    aborted: bool = False

    @property
    def base_url(self) -> str:
        port_str = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.hostname}{port_str}"

    def add_audit(self, action: str, details: str, phase: str = ""):
        self.audit_log.append(
            AuditEntry(
                timestamp=time.time(),
                action=action,
                details=details,
                phase=phase,
            )
        )

    def to_report(self) -> dict:
        severity_counts = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        max_cvss = max((f.cvss_score for f in self.findings), default=0.0)

        return {
            "job_id": self.job_id,
            "target": self.target,
            "hostname": self.hostname,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(
                (self.completed_at or time.time()) - self.created_at, 2
            ),
            "summary": {
                "total_findings": len(self.findings),
                "severity_distribution": severity_counts,
                "max_cvss_score": max_cvss,
                "risk_level": (
                    "CRITICAL" if max_cvss >= 9.0
                    else "HIGH" if max_cvss >= 7.0
                    else "MEDIUM" if max_cvss >= 4.0
                    else "LOW" if max_cvss >= 0.1
                    else "NONE"
                ),
            },
            "findings": [
                {
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "phase": f.phase,
                    "recommendation": f.recommendation,
                    "cvss_score": f.cvss_score,
                    "references": f.references,
                    "category": getattr(f, "category", ""),
                    "module": getattr(f, "module", ""),
                    "evidence": getattr(f, "evidence", ""),
                }
                for f in self.findings
            ],
            "phases_completed": self.phases_completed,
            "audit_log": [
                {
                    "timestamp": a.timestamp,
                    "action": a.action,
                    "details": a.details,
                    "phase": a.phase,
                }
                for a in self.audit_log
            ],
        }
