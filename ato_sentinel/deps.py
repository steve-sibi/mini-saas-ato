from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ato_sentinel.models import User, UserSession, ensure_utc, utcnow
from ato_sentinel.security import constant_time_equal
from ato_sentinel.services.detections import handle_session_reuse
from ato_sentinel.services.events import get_geo_context
from ato_sentinel.types import AuthenticatedContext


class AuthenticationRequired(Exception):
    pass


class SessionRiskRedirect(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def get_db(request: Request):
    db: Session = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def enforce_csrf(request: Request, token: str | None) -> None:
    expected = request.state.context.csrf_token
    if not token or not expected or not constant_time_equal(token, expected):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def get_optional_auth_context(
    request: Request,
    db: Session = Depends(get_db),
) -> AuthenticatedContext | None:
    request.state.current_user = None
    request.state.current_session = None

    sid = request.cookies.get(request.app.state.settings.session_cookie_name)
    if not sid:
        return None

    session_record = db.scalar(select(UserSession).where(UserSession.sid == sid))
    expires_at = ensure_utc(session_record.expires_at) if session_record else None
    revoked_at = ensure_utc(session_record.revoked_at) if session_record else None
    if not session_record or revoked_at or (expires_at and expires_at <= utcnow()):
        return None

    user = db.get(User, session_record.user_id)
    if not user:
        return None

    geo = get_geo_context(request)
    if session_record.device_fingerprint != request.state.context.device_fingerprint:
        handle_session_reuse(db, request, session_record, user, geo)
        db.commit()
        raise SessionRiskRedirect("session-reused")

    session_record.last_seen_at = utcnow()
    session_record.last_seen_ip = request.state.context.ip
    session_record.last_seen_country = geo.country_code
    session_record.last_seen_city = geo.city
    request.state.current_user = user
    request.state.current_session = session_record
    db.commit()
    return AuthenticatedContext(user=user, session=session_record, geo=geo)


def require_authenticated(
    request: Request,
    db: Session = Depends(get_db),
) -> AuthenticatedContext:
    auth_context = get_optional_auth_context(request, db)
    if auth_context is None:
        raise AuthenticationRequired()
    return auth_context
