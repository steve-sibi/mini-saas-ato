from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any

from argon2 import PasswordHasher
from itsdangerous import BadSignature, BadTimeSignature, URLSafeTimedSerializer

from ato_sentinel.config import Settings

_PASSWORD_HASHER = PasswordHasher()


def hash_password(password: str) -> str:
    return _PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except Exception:
        return False


def generate_session_id() -> str:
    return secrets.token_urlsafe(48)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_backup_codes(count: int = 10) -> list[str]:
    codes: list[str] = []
    for _ in range(count):
        raw = secrets.token_hex(4).upper()
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def compute_device_fingerprint(headers: dict[str, str], device_entropy: str) -> str:
    parts = [
        headers.get("user-agent", ""),
        headers.get("accept-language", ""),
        headers.get("sec-ch-ua-platform", ""),
        headers.get("sec-ch-ua", ""),
        device_entropy,
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _serializer(secret: str, purpose: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt=f"ato-sentinel:{purpose}")


def sign_ticket(settings: Settings, purpose: str, payload: dict[str, Any]) -> str:
    return _serializer(settings.app_secret_key, purpose).dumps(payload)


def load_ticket(
    settings: Settings,
    purpose: str,
    token: str,
    max_age_seconds: int,
) -> dict[str, Any]:
    try:
        return _serializer(settings.app_secret_key, purpose).loads(token, max_age=max_age_seconds)
    except (BadSignature, BadTimeSignature) as exc:
        raise ValueError("invalid or expired ticket") from exc


def verify_webhook_signature(
    secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    tolerance_seconds: int,
) -> bool:
    try:
        sent_at = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
    except ValueError:
        return False

    age = abs((datetime.now(timezone.utc) - sent_at).total_seconds())
    if age > tolerance_seconds:
        return False

    signed_payload = f"{timestamp}.".encode("utf-8") + body
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
