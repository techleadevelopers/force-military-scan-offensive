import json
import sys
import time
from typing import Optional


class BaseModule:
    name: str = "base"
    phase: str = "base"
    description: str = ""
    timeout: int = 120

    def __init__(self):
        self._start_time = 0.0
        self._job_id = ""

    def emit(self, event_type: str, data: dict):
        payload = {"event": event_type, "data": data, "timestamp": time.time()}
        print(json.dumps(payload), flush=True)

    def log(self, message: str, level: str = "info"):
        self.emit("log_stream", {"message": message, "level": level, "phase": self.phase})

    def finding(
        self,
        severity: str,
        title: str,
        description: str,
        recommendation: str = "",
        cvss_score: float = 0.0,
        references: Optional[list] = None,
    ):
        self.emit(
            "finding_detected",
            {
                "severity": severity,
                "title": title,
                "description": description,
                "phase": self.phase,
                "recommendation": recommendation,
                "cvss_score": cvss_score,
                "references": references or [],
            },
        )

    def asset(
        self,
        asset_type: str,
        path: str,
        label: str,
        severity: str,
        category: str = "",
    ):
        self.emit(
            "asset_detected",
            {
                "type": asset_type,
                "path": path,
                "label": label,
                "severity": severity,
                "phase": self.phase,
                "category": category,
                "jobId": self._job_id,
                "timestamp": time.time(),
            },
        )

    def phase_update(self, status: str):
        self.emit("phase_update", {"phase": self.phase, "status": status})

    def telemetry(self, **kwargs):
        self.emit("telemetry_update", kwargs)

    async def execute(self, job) -> list:
        raise NotImplementedError

    async def run(self, job) -> list:
        self._start_time = time.time()
        self.phase_update("running")
        self.log(f"Initializing module: {self.name}")
        self.log(f"Description: {self.description}")
        try:
            findings = await self.execute(job)
            elapsed = round(time.time() - self._start_time, 2)
            self.log(
                f"Module {self.name} completed in {elapsed}s — {len(findings)} finding(s)",
                "success",
            )
            self.phase_update("completed")
            return findings
        except Exception as e:
            self.log(f"Module {self.name} error: {str(e)}", "error")
            self.phase_update("error")
            return []
