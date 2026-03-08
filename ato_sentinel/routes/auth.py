from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlencode

import pyotp
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ato_sentinel.deps import AuthenticationRequired, enforce_csrf, get_db, get_optional_auth_context, require_authenticated
from ato_sentinel.models import User
from ato_sentinel.security import generate_backup_codes, load_ticket, sign_ticket, verify_password
from ato_sentinel.services.authentication import (
    consume_backup_code,
    create_user,
    is_step_up_active,
    issue_session,
    normalize_email,
    replace_recovery_codes,
    revoke_session,
)
from ato_sentinel.services.detections import challenge_required_for_login, evaluate_login_failure, evaluate_login_success
from ato_sentinel.services.events import emit_auth_event, get_geo_context, persist_auth_event
from ato_sentinel.templating import template_response

router = APIRouter(prefix="/auth", tags=["auth"])


def _redirect_with_notice(path: str, notice: str) -> RedirectResponse:
    return RedirectResponse(url=f"{path}?{urlencode({'notice': notice})}", status_code=303)


def _set_session_cookie(request: Request, response, sid: str) -> None:
    settings = request.app.state.settings
    response.set_cookie(
        settings.session_cookie_name,
        sid,
        httponly=True,
        samesite="lax",
        secure=settings.use_secure_cookies,
        max_age=settings.session_ttl_hours * 3600,
    )


@router.get("/register")
def register_form(request: Request):
    return template_response(request, "auth/register.html")


@router.post("/register")
def register_post(
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(),
    email: str = Form(),
    password: str = Form(),
):
    enforce_csrf(request, csrf_token)
    normalized_email = normalize_email(email)
    if db.scalar(select(User).where(User.email == normalized_email)):
        return template_response(
            request,
            "auth/register.html",
            error="That email is already registered.",
            email=normalized_email,
        )
    user = create_user(db, normalized_email, password)
    event = persist_auth_event(
        db,
        request,
        event_type="registration",
        outcome="success",
        user=user,
        email=user.email,
    )
    emit_auth_event(request, event)
    db.commit()
    return _redirect_with_notice("/auth/login", "account-created")


@router.get("/login")
def login_form(
    request: Request,
    email: str = "",
    error: str | None = None,
    notice: str | None = None,
    db: Session = Depends(get_db),
    auth_context=Depends(get_optional_auth_context),
):
    if auth_context:
        return RedirectResponse(url="/account/security", status_code=303)
    challenge_required, reasons = challenge_required_for_login(db, request.state.context.ip, normalize_email(email) if email else None)
    return template_response(
        request,
        "auth/login.html",
        email=email,
        error=error,
        notice=notice,
        challenge_required=challenge_required,
        challenge_reasons=reasons,
    )


@router.post("/login")
def login_post(
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(),
    email: str = Form(),
    password: str = Form(),
    turnstile_response: str = Form(default="", alias="cf-turnstile-response"),
):
    enforce_csrf(request, csrf_token)
    normalized_email = normalize_email(email)
    challenge_required, reasons = challenge_required_for_login(db, request.state.context.ip, normalized_email)
    if challenge_required:
        token = turnstile_response or "dev-bypass"
        challenge_ok, challenge_status = request.app.state.turnstile.verify(token, request.state.context.ip)
        if not challenge_ok:
            return template_response(
                request,
                "auth/login.html",
                email=normalized_email,
                error=f"Challenge validation failed: {challenge_status}.",
                challenge_required=True,
                challenge_reasons=reasons,
            )

    user = db.scalar(select(User).where(User.email == normalized_email))
    if not user or not verify_password(password, user.password_hash):
        event = persist_auth_event(
            db,
            request,
            event_type="login",
            outcome="fail",
            user=user,
            email=normalized_email,
        )
        detections = evaluate_login_failure(db, event)
        emit_auth_event(request, event, [item.detection_type for item in detections])
        db.commit()
        challenge_required, reasons = challenge_required_for_login(db, request.state.context.ip, normalized_email)
        return template_response(
            request,
            "auth/login.html",
            email=normalized_email,
            error="Invalid credentials.",
            challenge_required=challenge_required,
            challenge_reasons=reasons,
        )

    ticket_payload = {
        "user_id": user.id,
        "email": user.email,
        "device_fingerprint": request.state.context.device_fingerprint,
        "source_ip": request.state.context.ip,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    settings = request.app.state.settings
    if is_step_up_active(user) and not user.mfa_enabled:
        secret = pyotp.random_base32()
        ticket = sign_ticket(
            settings,
            "mfa-enroll",
            {**ticket_payload, "secret": secret, "complete_login": True},
        )
        return template_response(
            request,
            "auth/mfa_enroll.html",
            pending_login=True,
            ticket=ticket,
            secret=secret,
            error=None,
            notice="Risk-based step-up requires MFA enrollment before sign-in completes.",
        )

    if user.mfa_enabled or is_step_up_active(user):
        ticket = sign_ticket(settings, "mfa-verify", ticket_payload)
        return template_response(
            request,
            "auth/mfa_verify.html",
            ticket=ticket,
            email=user.email,
            requires_step_up=is_step_up_active(user),
        )

    geo = get_geo_context(request)
    session_record = issue_session(db, settings, user, request.state.context, geo)
    event = persist_auth_event(
        db,
        request,
        event_type="login",
        outcome="success",
        user=user,
        email=user.email,
        session_id=session_record.sid,
    )
    detections = evaluate_login_success(db, event, user, session_record)
    emit_auth_event(request, event, [item.detection_type for item in detections])
    db.commit()
    response = RedirectResponse(url="/account/security?notice=signed-in", status_code=303)
    _set_session_cookie(request, response, session_record.sid)
    return response


@router.post("/mfa/verify")
def mfa_verify_post(
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(),
    ticket: str = Form(),
    totp_code: str = Form(default=""),
    backup_code: str = Form(default=""),
):
    enforce_csrf(request, csrf_token)
    settings = request.app.state.settings
    try:
        payload = load_ticket(settings, "mfa-verify", ticket, 600)
    except ValueError:
        return _redirect_with_notice("/auth/login", "mfa-ticket-expired")

    if payload["device_fingerprint"] != request.state.context.device_fingerprint:
        return _redirect_with_notice("/auth/login", "mfa-context-changed")

    user = db.get(User, payload["user_id"])
    if not user or not user.mfa_enabled:
        return _redirect_with_notice("/auth/login", "mfa-not-configured")

    totp_ok = False
    if totp_code:
        totp_ok = pyotp.TOTP(user.mfa_secret or "").verify(totp_code.strip(), valid_window=1)
    backup_ok = False
    if backup_code:
        backup_ok = consume_backup_code(db, user, backup_code)

    if not totp_ok and not backup_ok:
        event = persist_auth_event(
            db,
            request,
            event_type="mfa_verify",
            outcome="fail",
            user=user,
            email=user.email,
        )
        emit_auth_event(request, event)
        db.commit()
        return template_response(
            request,
            "auth/mfa_verify.html",
            ticket=ticket,
            email=user.email,
            error="The TOTP code or backup code was invalid.",
            requires_step_up=is_step_up_active(user),
        )

    geo = get_geo_context(request)
    session_record = issue_session(db, settings, user, request.state.context, geo)
    event = persist_auth_event(
        db,
        request,
        event_type="login",
        outcome="success",
        user=user,
        email=user.email,
        session_id=session_record.sid,
    )
    detections = evaluate_login_success(db, event, user, session_record)
    emit_auth_event(request, event, [item.detection_type for item in detections])
    db.commit()
    response = RedirectResponse(url="/account/security?notice=mfa-verified", status_code=303)
    _set_session_cookie(request, response, session_record.sid)
    return response


@router.get("/mfa/enroll")
def mfa_enroll_form(
    request: Request,
    ticket: str | None = None,
    db: Session = Depends(get_db),
    auth_context=Depends(get_optional_auth_context),
):
    settings = request.app.state.settings
    if ticket:
        try:
            payload = load_ticket(settings, "mfa-enroll", ticket, 600)
        except ValueError:
            return _redirect_with_notice("/auth/login", "mfa-enrollment-expired")
        return template_response(
            request,
            "auth/mfa_enroll.html",
            pending_login=bool(payload.get("complete_login")),
            ticket=ticket,
            secret=payload["secret"],
        )

    if not auth_context:
        raise AuthenticationRequired()
    if auth_context.user.mfa_enabled:
        return _redirect_with_notice("/account/security", "mfa-already-enabled")

    secret = pyotp.random_base32()
    ticket = sign_ticket(
        settings,
        "mfa-enroll",
        {
            "user_id": auth_context.user.id,
            "email": auth_context.user.email,
            "device_fingerprint": request.state.context.device_fingerprint,
            "source_ip": request.state.context.ip,
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "secret": secret,
            "complete_login": False,
        },
    )
    return template_response(
        request,
        "auth/mfa_enroll.html",
        pending_login=False,
        ticket=ticket,
        secret=secret,
    )


@router.post("/mfa/enroll")
def mfa_enroll_post(
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(),
    ticket: str = Form(),
    totp_code: str = Form(),
):
    enforce_csrf(request, csrf_token)
    settings = request.app.state.settings
    try:
        payload = load_ticket(settings, "mfa-enroll", ticket, 600)
    except ValueError:
        return _redirect_with_notice("/auth/login", "mfa-enrollment-expired")

    user = db.get(User, payload["user_id"])
    if not user:
        return _redirect_with_notice("/auth/login", "unknown-user")

    if payload["device_fingerprint"] != request.state.context.device_fingerprint:
        return _redirect_with_notice("/auth/login", "mfa-context-changed")

    if not pyotp.TOTP(payload["secret"]).verify(totp_code.strip(), valid_window=1):
        return template_response(
            request,
            "auth/mfa_enroll.html",
            pending_login=bool(payload.get("complete_login")),
            ticket=ticket,
            secret=payload["secret"],
            error="The TOTP verification code was invalid.",
        )

    user.mfa_secret = payload["secret"]
    user.mfa_enabled = True
    backup_codes = generate_backup_codes()
    replace_recovery_codes(db, user, backup_codes)

    if payload.get("complete_login"):
        geo = get_geo_context(request)
        session_record = issue_session(db, settings, user, request.state.context, geo)
        event = persist_auth_event(
            db,
            request,
            event_type="login",
            outcome="success",
            user=user,
            email=user.email,
            session_id=session_record.sid,
        )
        detections = evaluate_login_success(db, event, user, session_record)
        emit_auth_event(request, event, [item.detection_type for item in detections])
        db.commit()
        response = template_response(
            request,
            "auth/mfa_enroll_success.html",
            backup_codes=backup_codes,
            pending_login=True,
        )
        _set_session_cookie(request, response, session_record.sid)
        return response

    current_session = getattr(request.state, "current_session", None)
    event = persist_auth_event(
        db,
        request,
        event_type="mfa_enroll",
        outcome="success",
        user=user,
        email=user.email,
        session_id=current_session.sid if current_session else None,
    )
    emit_auth_event(request, event)
    db.commit()
    return template_response(
        request,
        "auth/mfa_enroll_success.html",
        backup_codes=backup_codes,
        pending_login=False,
    )


@router.post("/logout")
def logout_post(
    request: Request,
    db: Session = Depends(get_db),
    auth_context=Depends(require_authenticated),
    csrf_token: str = Form(),
):
    enforce_csrf(request, csrf_token)
    revoke_session(auth_context.session)
    event = persist_auth_event(
        db,
        request,
        event_type="logout",
        outcome="success",
        user=auth_context.user,
        email=auth_context.user.email,
        session_id=auth_context.session.sid,
    )
    emit_auth_event(request, event)
    db.commit()
    response = RedirectResponse(url="/auth/login?notice=signed-out", status_code=303)
    response.delete_cookie(request.app.state.settings.session_cookie_name)
    return response
