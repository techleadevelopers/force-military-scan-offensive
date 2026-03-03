import re


class RedisSSRFValidator:
    def __init__(self):
        self.redis_signatures = [
            b"+OK\r\n",
            b"-ERR",
            b"$",
            b"*",
            b":",
            b"redis_version",
            b"# Server\r\n",
            b"role:",
            b"db0:",
            b"connected_clients:",
            b"used_memory:",
            b"total_commands_processed:",
        ]

        self.html_signatures = [
            b"<!DOCTYPE html",
            b"<html",
            b"<head",
            b"<body",
            b"<script",
            b"<style",
            b"<title",
            b"<div",
            b"<span",
            b"<a href",
        ]

    def validate_redis_response(self, response_text, response_headers, url):
        """Return dict with is_redis, confidence, action, reason"""
        content_type = (response_headers.get("content-type", "") or "").lower()

        if "html" in content_type:
            return {"is_redis": False, "confidence": 0, "reason": "Resposta HTML, não Redis", "action": "REJECT"}
        if "json" in content_type:
            return {"is_redis": False, "confidence": 0, "reason": "Resposta JSON, não Redis", "action": "REJECT"}

        response_bytes = response_text.encode() if isinstance(response_text, str) else response_text

        for sig in self.html_signatures:
            if sig in response_bytes[:500]:
                return {
                    "is_redis": False,
                    "confidence": 0,
                    "reason": "Resposta contém HTML",
                    "action": "REJECT",
                }

        redis_matches = [sig for sig in self.redis_signatures if sig in response_bytes]

        if len(redis_matches) >= 2:
            return {
                "is_redis": True,
                "confidence": min(len(redis_matches) * 20, 100),
                "signatures": [sig.decode(errors="ignore") for sig in redis_matches[:3]],
                "reason": f"{len(redis_matches)} assinaturas Redis encontradas",
                "action": "ACCEPT",
            }

        if len(redis_matches) == 1:
            return {
                "is_redis": False,
                "confidence": 30,
                "reason": "Apenas 1 assinatura Redis - possível falso positivo",
                "action": "REJECT",
            }

        if len(response_bytes) < 30 or len(response_bytes) > 10000:
            return {
                "is_redis": False,
                "confidence": 10,
                "reason": f"Tamanho incompatível com Redis ({len(response_bytes)} bytes)",
                "action": "REJECT",
            }

        return {"is_redis": False, "confidence": 0, "reason": "Nenhuma assinatura Redis encontrada", "action": "REJECT"}
