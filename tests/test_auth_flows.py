from __future__ import annotations

from datetime import timedelta

import pyotp

from ato_sentinel.models import ChallengeRule, User, UserSession, utcnow

from tests.helpers import bootstrap_csrf, extract_backup_codes, extract_hidden_value, extract_secret


def test_register_login_logout(client):
    csrf = bootstrap_csrf(client, "/auth/register")
    response = client.post(
        "/auth/register",
        data={"csrf_token": csrf, "email": "alice@example.com", "password": "P@ssw0rd!123"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    csrf = bootstrap_csrf(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf,
            "email": "alice@example.com",
            "password": "P@ssw0rd!123",
            "cf-turnstile-response": "dev-bypass",
        },
        headers={"X-Device-Entropy": "trusted-browser"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.cookies.get("ato_sid")

    page = client.get("/account/security", headers={"X-Device-Entropy": "trusted-browser"})
    assert page.status_code == 200
    assert "alice@example.com" in page.text

    csrf = bootstrap_csrf(client, "/account/security")
    response = client.post(
        "/auth/logout",
        data={"csrf_token": csrf},
        headers={"X-Device-Entropy": "trusted-browser"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.cookies.get("ato_sid") is None


def test_mfa_enrollment_and_backup_code_login(client):
    csrf = bootstrap_csrf(client, "/auth/register")
    client.post(
        "/auth/register",
        data={"csrf_token": csrf, "email": "mfa@example.com", "password": "P@ssw0rd!123"},
        follow_redirects=False,
    )

    csrf = bootstrap_csrf(client, "/auth/login")
    login = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf,
            "email": "mfa@example.com",
            "password": "P@ssw0rd!123",
            "cf-turnstile-response": "dev-bypass",
        },
        headers={"X-Device-Entropy": "trusted-browser"},
        follow_redirects=False,
    )
    assert login.status_code == 303

    enroll_page = client.get("/auth/mfa/enroll", headers={"X-Device-Entropy": "trusted-browser"})
    assert "data:image/svg+xml;base64," in enroll_page.text
    ticket = extract_hidden_value(enroll_page.text, "ticket")
    secret = extract_secret(enroll_page.text)
    csrf = client.cookies["ato_csrf"]
    enroll = client.post(
        "/auth/mfa/enroll",
        data={
            "csrf_token": csrf,
            "ticket": ticket,
            "totp_code": pyotp.TOTP(secret).now(),
        },
        headers={"X-Device-Entropy": "trusted-browser"},
    )
    backup_codes = extract_backup_codes(enroll.text)
    assert len(backup_codes) == 10

    with client.app.state.session_factory() as db:
        user = db.query(User).filter(User.email == "mfa@example.com").one()
        assert user.mfa_enabled is True

    csrf = bootstrap_csrf(client, "/account/security")
    client.post(
        "/auth/logout",
        data={"csrf_token": csrf},
        headers={"X-Device-Entropy": "trusted-browser"},
        follow_redirects=False,
    )

    csrf = bootstrap_csrf(client, "/auth/login")
    verify_page = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf,
            "email": "mfa@example.com",
            "password": "P@ssw0rd!123",
            "cf-turnstile-response": "dev-bypass",
        },
        headers={"X-Device-Entropy": "trusted-browser"},
    )
    ticket = extract_hidden_value(verify_page.text, "ticket")
    csrf = client.cookies["ato_csrf"]
    verify = client.post(
        "/auth/mfa/verify",
        data={
            "csrf_token": csrf,
            "ticket": ticket,
            "backup_code": backup_codes[0],
        },
        headers={"X-Device-Entropy": "trusted-browser"},
        follow_redirects=False,
    )
    assert verify.status_code == 303
    assert client.cookies.get("ato_sid")

    with client.app.state.session_factory() as db:
        session_count = db.query(UserSession).count()
        assert session_count >= 2


def test_register_existing_email_redirects_without_enumeration(client):
    csrf = bootstrap_csrf(client, "/auth/register")
    first = client.post(
        "/auth/register",
        data={"csrf_token": csrf, "email": "dup@example.com", "password": "P@ssw0rd!123"},
        follow_redirects=False,
    )
    assert first.status_code == 303
    assert first.headers["location"] == "/auth/login?notice=account-created"

    csrf = bootstrap_csrf(client, "/auth/register")
    second = client.post(
        "/auth/register",
        data={"csrf_token": csrf, "email": "dup@example.com", "password": "AnotherP@ss!234"},
        follow_redirects=False,
    )
    assert second.status_code == 303
    assert second.headers["location"] == "/auth/login?notice=account-created"

    with client.app.state.session_factory() as db:
        users = db.query(User).filter(User.email == "dup@example.com").all()
        assert len(users) == 1


def test_login_with_account_challenge_requires_turnstile_and_triggers_step_up(client):
    csrf = bootstrap_csrf(client, "/auth/register")
    client.post(
        "/auth/register",
        data={"csrf_token": csrf, "email": "challenged@example.com", "password": "P@ssw0rd!123"},
        follow_redirects=False,
    )

    with client.app.state.session_factory() as db:
        db.add(
            ChallengeRule(
                scope="account",
                key="challenged@example.com",
                reason="distributed_credential_stuffing",
                expires_at=utcnow() + timedelta(minutes=30),
            )
        )
        db.commit()

    page = client.get("/auth/login?email=challenged@example.com")
    assert page.status_code == 200
    assert "Challenge mode enabled" in page.text
    assert "distributed_credential_stuffing" in page.text

    csrf = client.cookies["ato_csrf"]
    missing_token = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf,
            "email": "challenged@example.com",
            "password": "P@ssw0rd!123",
        },
        headers={"X-Device-Entropy": "step-up-browser"},
    )
    assert missing_token.status_code == 200
    assert "Challenge validation failed" in missing_token.text

    csrf = bootstrap_csrf(client, "/auth/login?email=challenged@example.com")
    allowed = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf,
            "email": "challenged@example.com",
            "password": "P@ssw0rd!123",
            "cf-turnstile-response": "dev-bypass",
        },
        headers={"X-Device-Entropy": "step-up-browser"},
    )
    assert allowed.status_code == 200
    assert "Risk-based step-up requires MFA enrollment before sign-in completes." in allowed.text
    assert "Enable MFA and continue" in allowed.text
    assert client.cookies.get("ato_sid") is None


def test_csrf_missing_and_mismatched_tokens_are_rejected(client):
    missing = client.post(
        "/auth/register",
        data={"email": "csrf@example.com", "password": "P@ssw0rd!123"},
        follow_redirects=False,
    )
    assert missing.status_code == 403

    bootstrap_csrf(client, "/auth/register")
    mismatched = client.post(
        "/auth/register",
        data={"csrf_token": "wrong-token", "email": "csrf@example.com", "password": "P@ssw0rd!123"},
        follow_redirects=False,
    )
    assert mismatched.status_code == 403
