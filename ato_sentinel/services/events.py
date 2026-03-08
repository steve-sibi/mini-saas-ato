from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from ato_sentinel.logging import emit_log
from ato_sentinel.models import AuthEvent, User
from ato_sentinel.types import GeoContext


def get_geo_context(request: Request) -> GeoContext:
    cached = getattr(request.state, "geo_context", None)
    if cached is not None:
        return cached

    geo = request.app.state.geoip.lookup(
        request.state.context.ip,
        {key.lower(): value for key, value in request.headers.items()},
    )
    request.state.geo_context = geo
    return geo


def persist_auth_event(
    db: Session,
    request: Request,
    *,
    event_type: str,
    outcome: str,
    user: User | None = None,
    email: str | None = None,
    session_id: str | None = None,
    risk_score: int = 0,
    risk_flags: list[str] | None = None,
) -> AuthEvent:
    geo = get_geo_context(request)
    event = AuthEvent(
        event_type=event_type,
        outcome=outcome,
        user_id=user.id if user else None,
        email=email or (user.email if user else None),
        session_id=session_id,
        source_ip=request.state.context.ip,
        user_agent=request.state.context.user_agent,
        country_code=geo.country_code,
        city=geo.city,
        latitude=geo.latitude,
        longitude=geo.longitude,
        asn=geo.asn,
        device_fingerprint=request.state.context.device_fingerprint,
        risk_score=risk_score,
        risk_flags=risk_flags or [],
    )
    db.add(event)
    db.flush()
    return event


def append_risk_flag(event: AuthEvent, flag: str, score: int) -> None:
    flags = list(event.risk_flags or [])
    if flag not in flags:
        flags.append(flag)
    event.risk_flags = flags
    event.risk_score = max(event.risk_score, score)


def emit_auth_event(request: Request, event: AuthEvent, detection_types: list[str] | None = None) -> None:
    settings = request.app.state.settings
    emit_log(
        settings,
        {
            "event_id": event.id,
            "event_type": event.event_type,
            "outcome": event.outcome,
            "user_id": event.user_id,
            "email": event.email,
            "session_id": event.session_id,
            "source_ip": event.source_ip,
            "user_agent": event.user_agent,
            "country_code": event.country_code,
            "city": event.city,
            "latitude": event.latitude,
            "longitude": event.longitude,
            "asn": event.asn,
            "device_fingerprint": event.device_fingerprint,
            "risk_score": event.risk_score,
            "risk_flags": event.risk_flags,
            "geo_lookup_status": get_geo_context(request).status,
            "detection_types": detection_types or [],
            "created_at": event.created_at,
        },
    )
