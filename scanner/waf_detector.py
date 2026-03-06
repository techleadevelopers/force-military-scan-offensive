import re
from typing import Dict, Optional, Tuple


class WAFDetector:
    """Detecta WAF a partir de resposta HTTP e, opcionalmente, JA4/TLS."""

    SIGNATURES = {
        "akamai": {
            "headers": ["x-akamai", "x-akamai-", "akamai"],
            "server": ["akamai", "akamaighost"],
            "body_patterns": [
                r"reference #\d+\.\d+\.\d+",
                r"access denied",
                r"edgesuite\.net",
                r"akamai",
            ],
            "codes": [403, 406, 503],
        },
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache", "cf-request", "__cfduid"],
            "server": ["cloudflare"],
            "body_patterns": [
                r"cloudflare",
                r"cf-ray",
                r"attention required",
                r"please enable cookies",
            ],
            "codes": [403, 503, 520],
            "ja4": None,
        },
        "sucuri": {
            "headers": ["x-sucuri", "x-sucuri-"],
            "server": ["sucuri", "cloudproxy"],
            "body_patterns": [
                r"sucuri",
                r"cloudproxy",
                r"website firewall",
            ],
            "codes": [403, 503],
        },
        "imperva": {
            "headers": ["x-iinfo", "incapsula"],
            "server": ["incapsula"],
            "body_patterns": [
                r"incapsula",
                r"imperva",
                r"blocked because of web application firewall",
            ],
            "codes": [403, 404],
        },
        "aws_waf": {
            "headers": ["x-amzn-", "x-amzn-requestid", "x-amz-cf-id"],
            "server": [],
            "body_patterns": [
                r"request blocked",
                r"aws.waf",
                r"403 forbidden",
            ],
            "codes": [403],
        },
        "f5": {
            "headers": ["bigip", "x-wa-info"],
            "server": ["bigip"],
            "body_patterns": [
                r"the requested url was rejected",
                r"x-wa-info",
            ],
            "codes": [200, 403],
        },
        "cloud_armor": {
            "headers": ["x-goog-"],
            "server": ["gws"],
            "body_patterns": [r"cloud armor", r"google cloud armor"],
            "codes": [403],
        },
    }

    @classmethod
    def detect(cls, response, ja4_hash: Optional[str] = None) -> Dict:
        """
        Detecta WAF a partir de resposta HTTP
        Retorna: {
            'detected': bool,
            'vendor': str,
            'mode': str,
            'confidence': int,
            'evidence': str
        }
        """
        result = {
            "detected": False,
            "vendor": "unknown",
            "mode": None,
            "confidence": 0,
            "evidence": None,
        }

        if response is None:
            return result

        # 1. Verifica código HTTP
        if getattr(response, "status_code", None) in [403, 406, 503, 520]:
            result["mode"] = f"http_{response.status_code}"
            result["confidence"] += 30

        # 2. Headers
        headers = {k.lower(): v for k, v in getattr(response, "headers", {}).items()}

        for vendor, sig in cls.SIGNATURES.items():
            # Headers específicos
            for header in sig["headers"]:
                if any(h.startswith(header) for h in headers):
                    result.update(
                        {
                            "detected": True,
                            "vendor": vendor,
                            "mode": "header_match",
                            "confidence": max(result["confidence"], 70),
                            "evidence": f"Header: {header}",
                        }
                    )
                    break

            # Server header
            if "server" in headers:
                server = headers["server"].lower()
                for s in sig["server"]:
                    if s in server:
                        result.update(
                            {
                                "detected": True,
                                "vendor": vendor,
                                "mode": "server_match",
                                "confidence": max(result["confidence"], 80),
                                "evidence": f"Server: {server}",
                            }
                        )
                        break

        # 3. Body patterns
        body_text = getattr(response, "text", "") or ""
        if body_text:
            body = body_text.lower()
            for vendor, sig in cls.SIGNATURES.items():
                for pattern in sig["body_patterns"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        result.update(
                            {
                                "detected": True,
                                "vendor": vendor,
                                "mode": "body_match",
                                "confidence": max(result["confidence"], 75),
                                "evidence": f"Body pattern: {pattern}",
                            }
                        )
                        break

        # 4. Padrão específico Akamai (mais preciso)
        if body_text and re.search(r"reference #\d+\.\d+\.\d+", body_text):
            result.update(
                {
                    "detected": True,
                    "vendor": "akamai",
                    "mode": "akamai_block_page",
                    "confidence": 95,
                    "evidence": "Akamai block page",
                }
            )

        # 5. JA4/TLS fingerprint (opcional)
        if ja4_hash:
            matched = cls._match_ja4(ja4_hash)
            if matched:
                vendor, confidence = matched
                result.update(
                    {
                        "detected": True,
                        "vendor": vendor,
                        "mode": "ja4_match",
                        "confidence": max(result["confidence"], confidence),
                        "evidence": f"ja4:{ja4_hash}",
                    }
                )

        return result

    @classmethod
    def _match_ja4(cls, ja4_hash: str) -> Optional[Tuple[str, int]]:
        for vendor, sig in cls.SIGNATURES.items():
            expected = sig.get("ja4")
            if expected and expected == ja4_hash:
                return vendor, 90
        return None
