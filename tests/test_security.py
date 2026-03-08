from __future__ import annotations

from datetime import datetime, timezone
import hmac
import hashlib

from ato_sentinel.security import (
    generate_backup_codes,
    hash_backup_code,
    hash_password,
    verify_password,
    verify_webhook_signature,
)


def test_argon2_password_round_trip():
    hashed = hash_password("Sup3rSecret!")
    assert hashed != "Sup3rSecret!"
    assert verify_password("Sup3rSecret!", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_backup_codes_are_deterministically_hashed():
    codes = generate_backup_codes(3)
    assert len(codes) == 3
    assert len({hash_backup_code(code) for code in codes}) == 3
    assert hash_backup_code(codes[0]) == hash_backup_code(codes[0])


def test_webhook_hmac_verification_accepts_valid_signature():
    secret = "webhook-secret"
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    body = b'{"alert_id":"123"}'
    signature = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + body,
        hashlib.sha256,
    ).hexdigest()
    assert verify_webhook_signature(secret, timestamp, body, signature, 60) is True
    assert verify_webhook_signature(secret, timestamp, body, "bad-signature", 60) is False
