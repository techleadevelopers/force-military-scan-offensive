import time
import random
from typing import Optional


class RateLimiter:
    """Gerencia ritmo de requisições para evitar bloqueios"""

    def __init__(self, min_delay=0.1, max_delay=0.5, jitter=True):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.last_request = 0.0
        self.consecutive_blocks = 0

    def wait(self):
        """Aguarda tempo apropriado antes da próxima requisição"""

        if self.consecutive_blocks > 2:
            delay = self.max_delay * 2
        else:
            delay = random.uniform(self.min_delay, self.max_delay)

        if self.jitter:
            delay *= random.uniform(0.8, 1.2)

        elapsed = time.time() - self.last_request
        if elapsed < delay:
            time.sleep(delay - elapsed)

        self.last_request = time.time()

    def report_block(self, blocked: bool):
        """Reporta se houve bloqueio para ajustar estratégia"""
        if blocked:
            self.consecutive_blocks += 1
        else:
            self.consecutive_blocks = max(0, self.consecutive_blocks - 1)

    def need_proxy_rotation(self) -> bool:
        """Verifica se precisa trocar de proxy"""
        return self.consecutive_blocks > 3


class ProxyRotator:
    """Rotaciona proxies para evitar bloqueio por IP"""

    def __init__(self, proxy_list: Optional[list] = None):
        self.proxies = proxy_list or []
        self.current_idx = 0
        self.failed_proxies = set()

    def get_next_proxy(self) -> Optional[dict]:
        """Retorna próximo proxy disponível"""
        if not self.proxies:
            return None

        for _ in range(len(self.proxies)):
            proxy = self.proxies[self.current_idx]
            self.current_idx = (self.current_idx + 1) % len(self.proxies)

            if proxy not in self.failed_proxies:
                return proxy

        return None

    def mark_failed(self, proxy):
        """Marca proxy como falho"""
        self.failed_proxies.add(proxy)

    def rotate_user_agent(self):
        """Rotaciona User-Agent"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
        ]
        return random.choice(agents)

