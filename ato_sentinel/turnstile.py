from __future__ import annotations

import httpx

from ato_sentinel.config import Settings


class TurnstileVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def verify(self, token: str, remote_ip: str) -> tuple[bool, str]:
        if not self.settings.turnstile_secret_key:
            return token == "dev-bypass", "disabled"

        with httpx.Client(timeout=10) as client:
            response = client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={
                    "secret": self.settings.turnstile_secret_key,
                    "response": token,
                    "remoteip": remote_ip,
                },
            )
            response.raise_for_status()
        payload = response.json()
        return bool(payload.get("success")), payload.get("error-codes", ["ok"])[0]
