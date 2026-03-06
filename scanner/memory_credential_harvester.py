from typing import List, Dict, Any


class MemoryCredentialHarvester:
    """
    Stub for in-memory credential harvesting. Non-destructive placeholder that
    returns synthetic creds when enabled.
    """

    def __init__(self, log):
        self.log = log

    def harvest_memory(self, access: Dict[str, Any]) -> List[Dict[str, Any]]:
        creds: List[Dict[str, Any]] = []
        os_name = access.get("os", "").lower()

        if os_name == "windows":
            self.log("[HARVEST] Simulating lsass dump parsing (stub)", "warn", "memory")
            creds.append({"user": "admin", "password": "Passw0rd!", "source": "lsass_stub"})
        elif os_name == "linux":
            self.log("[HARVEST] Simulating /proc mem scrape for DB processes (stub)", "warn", "memory")
            creds.append({"user": "postgres", "password": "pg_secret", "source": "proc_mem_stub"})

        return creds
