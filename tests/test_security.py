from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from ato_sentinel.security import (
    compute_device_fingerprint,
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


def test_device_fingerprint_is_deterministic_and_changes_with_entropy():
    headers = {
        "user-agent": "Browser/1.0",
        "accept-language": "en-US",
        "sec-ch-ua-platform": "macOS",
        "sec-ch-ua": '"Chromium";v="122"',
    }
    first = compute_device_fingerprint(headers, "laptop-a")
    second = compute_device_fingerprint(headers, "laptop-a")
    changed_entropy = compute_device_fingerprint(headers, "laptop-b")
    changed_header = compute_device_fingerprint({**headers, "accept-language": "en-GB"}, "laptop-a")

    assert first == second
    assert first != changed_entropy
    assert first != changed_header
