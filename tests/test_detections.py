from __future__ import annotations

from datetime import datetime, timezone
import json

from fastapi.testclient import TestClient

from ato_sentinel.models import ChallengeRule, ContainmentAction, Detection, UserSession

from tests.helpers import bootstrap_csrf


def _register(client, email: str, password: str):
    csrf = bootstrap_csrf(client, "/auth/register")
    client.post(
        "/auth/register",
        data={"csrf_token": csrf, "email": email, "password": password},
        follow_redirects=False,
    )


def _login(client, email: str, password: str, *, headers: dict[str, str]):
    csrf = bootstrap_csrf(client, "/auth/login")
    return client.post(
        "/auth/login",
        data={
            "csrf_token": csrf,
            "email": email,
            "password": password,
            "cf-turnstile-response": "dev-bypass",
        },
        headers=headers,
        follow_redirects=False,
    )


def test_password_spray_and_distributed_stuffing_create_challenge_rules(client):
    for index in range(20):
        _login(
            client,
            f"victim{index}@example.com",
            "bad-password",
            headers={"X-Forwarded-For": "198.51.100.17", "X-Device-Entropy": "sprayer"},
        )

    for index in range(8):
        _login(
            client,
            "target@example.com",
            "bad-password",
            headers={
                "X-Forwarded-For": f"203.0.113.{40 + index}",
                "X-Device-Entropy": f"bot-{index}",
            },
        )

    with client.app.state.session_factory() as db:
        rules = db.query(ChallengeRule).all()
        rule_keys = {(rule.scope, rule.key) for rule in rules}
        assert ("ip", "198.51.100.17") in rule_keys
        assert ("account", "target@example.com") in rule_keys


def test_session_reuse_revokes_sid_and_creates_detection(client):
    _register(client, "reuse@example.com", "P@ssw0rd!123")
    response = _login(
        client,
        "reuse@example.com",
        "P@ssw0rd!123",
        headers={"X-Forwarded-For": "198.51.100.11", "X-Device-Entropy": "trusted-browser"},
    )
    assert response.status_code == 303
    stolen_sid = client.cookies["ato_sid"]

    with TestClient(client.app) as attacker:
        attacker.cookies.set("ato_sid", stolen_sid)
        response = attacker.get(
            "/account/security",
            headers={"X-Forwarded-For": "198.51.100.33", "X-Device-Entropy": "attacker-browser"},
            follow_redirects=False,
        )
        assert response.status_code == 303

    with client.app.state.session_factory() as db:
        detection = db.query(Detection).filter(Detection.detection_type == "ATO-002").one()
        session_record = db.query(UserSession).filter(UserSession.sid == stolen_sid).one()
        assert detection.subject_value == stolen_sid
        assert session_record.revoked_at is not None


def test_impossible_travel_detection_and_datadog_webhook_idempotency(client):
    _register(client, "travel@example.com", "P@ssw0rd!123")
    _login(
        client,
        "travel@example.com",
        "P@ssw0rd!123",
        headers={
            "X-Forwarded-For": "198.51.100.20",
            "X-Device-Entropy": "chicago-laptop",
            "X-Debug-Country": "US",
            "X-Debug-City": "Chicago",
            "X-Debug-Latitude": "41.8781",
            "X-Debug-Longitude": "-87.6298",
        },
    )
    _login(
        client,
        "travel@example.com",
        "P@ssw0rd!123",
        headers={
            "X-Forwarded-For": "203.0.113.44",
            "X-Device-Entropy": "tokyo-phone",
            "X-Debug-Country": "JP",
            "X-Debug-City": "Tokyo",
            "X-Debug-Latitude": "35.6764",
            "X-Debug-Longitude": "139.6500",
        },
    )

    with client.app.state.session_factory() as db:
        impossible = db.query(Detection).filter(Detection.detection_type == "ATO-003").one()
        assert impossible.subject_value == "travel@example.com"

    payload = {
        "alert_id": "alert-123",
        "detection_type": "ATO-001",
        "entity_type": "ip",
        "entity_value": "198.51.100.17",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "monitor_name": "ATO-001 Password Spray",
    }
    headers = {"X-ATO-Webhook-Token": "test-webhook-secret"}
    first = client.post("/internal/datadog/contain", content=json.dumps(payload), headers=headers)
    second = client.post("/internal/datadog/contain", content=json.dumps(payload), headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["idempotent"] is True

    with client.app.state.session_factory() as db:
        actions = db.query(ContainmentAction).filter(ContainmentAction.external_id == "alert-123").all()
        assert len(actions) == 1
