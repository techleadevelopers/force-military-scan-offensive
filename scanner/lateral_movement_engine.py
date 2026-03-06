from typing import List, Dict, Any


class LateralMovementEngine:
    """
    Attempts (stubbed) lateral movement using captured credentials.
    Designed to be non-destructive: only simulates reachability and records intent.
    """

    def __init__(self, log):
        self.log = log
        self.compromised_hosts: List[str] = []

    def lateral_move(self, compromised_host: str, credentials: List[Dict[str, Any]]) -> List[str]:
        # Simulated network discovery (placeholder subnet)
        internal_hosts = [f"192.168.1.{i}" for i in range(10, 14)]
        self.log(f"[LATERAL] Discovered hosts from {compromised_host}: {', '.join(internal_hosts)}", "warn", "lateral")

        for host in internal_hosts:
            for cred in credentials:
                user = cred.get("user") or cred.get("username") or "user"
                method = cred.get("source", "unknown")

                if self._try_ssh(host, user):
                    self.compromised_hosts.append(host)
                    self.log(f"[LATERAL] SSH reuse succeeded on {host} via {user} ({method})", "error", "lateral")
                elif self._try_smb_exec(host, user):
                    self.compromised_hosts.append(host)
                    self.log(f"[LATERAL] SMB/PsExec reuse succeeded on {host} via {user} ({method})", "error", "lateral")

        return list(set(self.compromised_hosts))

    def _try_ssh(self, host: str, user: str) -> bool:
        # Placeholder heuristic: pretend success on .10
        return host.endswith(".10")

    def _try_smb_exec(self, host: str, user: str) -> bool:
        # Placeholder heuristic: pretend success on .11
        return host.endswith(".11")
