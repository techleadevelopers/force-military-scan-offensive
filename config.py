import os


class SniperConfig:
    """Configurações do Sniper Mode"""

    SNIPER_WAF_BYPASS = os.getenv("SNIPER_WAF_BYPASS", "true").lower() == "true"
    SNIPER_WAF_VENDOR_HINT = os.getenv("SNIPER_WAF_VENDOR_HINT", "auto")
    SNIPER_WAF_VARIANTS_PER_VECTOR = int(os.getenv("SNIPER_WAF_VARIANTS_PER_VECTOR", "6"))
    SNIPER_MIN_DELAY = int(os.getenv("SNIPER_MIN_DELAY", "100"))
    SNIPER_MAX_DELAY = int(os.getenv("SNIPER_MAX_DELAY", "500"))
    SNIPER_PROXY_LIST = [p for p in os.getenv("SNIPER_PROXY_LIST", "").split(",") if p]
    SNIPER_ROTATE_ON_BLOCKS = int(os.getenv("SNIPER_ROTATE_ON_BLOCKS", "3"))

