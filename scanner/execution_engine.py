import uuid
from datetime import datetime
from typing import Dict, Any, List


class ExecutionEngine:
    """
    Executor mÃ­nimo para aÃ§Ãµes marcadas como safe_auto. As aÃ§Ãµes perigosas
    retornam estado 'pending' para aprovaÃ§Ã£o humana na UI/admin.
    """

    def __init__(self):
        self.running_jobs: List[Dict[str, Any]] = []
        self.completed_jobs: List[Dict[str, Any]] = []

    # --- Public API -----------------------------------------------------
    def execute_action(self, target: str, action: Dict[str, Any]) -> Dict[str, Any]:
        if not action.get("safe_auto", False):
            return {
                "status": "pending",
                "message": "AÃ§Ã£o requer aprovaÃ§Ã£o manual",
                "action": action,
            }

        job = self._start_job(target, action)
        try:
            if action["name"] == "virtual_host_bruteforce":
                result = self._bruteforce_virtual_host(target, action.get("wordlist", []))
            elif action["name"] == "ftp_bruteforce_windows":
                result = self._bruteforce_ftp(target, action.get("wordlist", []))
            elif action["name"] == "ssrf_redis":
                result = self._exploit_ssrf_redis(target, action.get("payloads", {}))
            else:
                result = {"status": "unsupported", "message": "AÃ§Ã£o nÃ£o implementada"}

            self._finish_job(job, "completed", result)
        except Exception as exc:  # pragma: no cover - defensive
            self._finish_job(job, "failed", {"error": str(exc)})

        return job

    # --- Internals ------------------------------------------------------
    def _start_job(self, target: str, action: Dict[str, Any]) -> Dict[str, Any]:
        job = {
            "id": str(uuid.uuid4()),
            "target": target,
            "action": action.get("name"),
            "started_at": datetime.utcnow().isoformat() + "Z",
            "status": "running",
        }
        self.running_jobs.append(job)
        return job

    def _finish_job(self, job: Dict[str, Any], status: str, result: Dict[str, Any]):
        job["status"] = status
        job["result"] = result
        job["completed_at"] = datetime.utcnow().isoformat() + "Z"
        if job in self.running_jobs:
            self.running_jobs.remove(job)
        self.completed_jobs.append(job)

    # --- Action implementations (minimal PoC-safe) ---------------------
    def _bruteforce_virtual_host(self, target: str, wordlist: List[str]) -> Dict[str, Any]:
        # Placeholder: integrar com existing probes (gobuster/ffuf) quando disponÃ­vel.
        hosts_tested = [{"hostname": f"{w}.{target}", "status": "queued"} for w in wordlist[:20]]
        return {"status": "queued", "found_hosts": [], "tested": hosts_tested}

    def _bruteforce_ftp(self, target: str, wordlist: List[Dict[str, str]]) -> Dict[str, Any]:
        combos = wordlist[:25] if isinstance(wordlist, list) else []
        return {"status": "queued", "target": target, "attempts": combos}

    def _exploit_ssrf_redis(self, target: str, payloads: Dict[str, str]) -> Dict[str, Any]:
        used = {k: v for k, v in (payloads or {}).items()}
        return {"status": "queued", "target": target, "payloads": list(used.keys())}

