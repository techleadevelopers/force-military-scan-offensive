from typing import List, Dict, Any
import requests


class VectorMatrix:
    """Gerencia múltiplos vetores de ataque"""

    VECTORS = {
        "get_param": {
            "name": "GET Parameter",
            "transport": "GET",
            "test": lambda sess, url, param, payload: sess.get(
                f"{url}?{param}={requests.utils.quote(payload)}"
            ),
        },
        "post_form": {
            "name": "POST Form",
            "transport": "POST",
            "test": lambda sess, url, param, payload: sess.post(url, data={param: payload}),
        },
        "post_json": {
            "name": "POST JSON",
            "transport": "POST",
            "test": lambda sess, url, param, payload: sess.post(url, json={param: payload}),
        },
        "header": {
            "name": "HTTP Header",
            "transport": "GET",
            "test": lambda sess, url, param, payload: sess.get(url, headers={param: payload}),
        },
        "cookie": {
            "name": "Cookie",
            "transport": "GET",
            "test": lambda sess, url, param, payload: sess.get(url, cookies={param: payload}),
        },
        "path": {
            "name": "URL Path",
            "transport": "GET",
            "test": lambda sess, url, param, payload: sess.get(f"{url.rstrip('/')}/{payload}"),
        },
        "user_agent": {
            "name": "User-Agent",
            "transport": "GET",
            "test": lambda sess, url, param, payload: sess.get(url, headers={"User-Agent": payload}),
        },
        "referer": {
            "name": "Referer",
            "transport": "GET",
            "test": lambda sess, url, param, payload: sess.get(url, headers={"Referer": payload}),
        },
    }

    @classmethod
    def test_vector(
        cls, vector_id: str, session: requests.Session, url: str, param: str, payload: str
    ) -> Dict[str, Any]:
        """Testa um payload em um vetor específico"""

        if vector_id not in cls.VECTORS:
            raise ValueError(f"Vector {vector_id} não existe")

        vector = cls.VECTORS[vector_id]

        try:
            response = vector["test"](session, url, param, payload)

            return {
                "vector": vector_id,
                "vector_name": vector["name"],
                "transport": vector["transport"],
                "status_code": response.status_code,
                "response_size": len(response.text) if hasattr(response, "text") else 0,
                "blocked": response.status_code in [403, 406, 503],
                "success": response.status_code == 200,
                "headers": dict(response.headers),
                "snippet": response.text[:200] if hasattr(response, "text") else "",
            }
        except Exception as e:
            return {
                "vector": vector_id,
                "vector_name": vector["name"],
                "transport": vector["transport"],
                "error": str(e),
                "blocked": False,
                "success": False,
            }

    @classmethod
    def find_weak_vector(
        cls, session: requests.Session, url: str, param: str, payloads: List[str]
    ) -> str:
        """Encontra o vetor mais fraco (menos bloqueios)"""

        scores = {v: 0 for v in cls.VECTORS.keys()}

        for vector_id in cls.VECTORS.keys():
            for payload in payloads[:3]:  # Testa 3 payloads
                result = cls.test_vector(vector_id, session, url, param, payload)
                if result.get("success"):
                    scores[vector_id] += 2
                elif not result.get("blocked"):
                    scores[vector_id] += 1

        if scores:
            return max(scores, key=scores.get)
        return "get_param"  # fallback

