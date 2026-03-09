from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ato_sentinel.deps import enforce_csrf, get_db, require_authenticated
from ato_sentinel.models import AuthEvent, ChallengeRule, Detection, UserSession, utcnow
from ato_sentinel.services.authentication import revoke_session
from ato_sentinel.services.detections import _create_containment_action
from ato_sentinel.services.events import emit_auth_event, persist_auth_event
from ato_sentinel.templating import template_response

router = APIRouter(prefix="/account", tags=["account"])


@router.get("/security")
def security_center(
    request: Request,
    notice: str | None = None,
    db: Session = Depends(get_db),
    auth_context=Depends(require_authenticated),
):
    active_sessions = db.scalars(
        select(UserSession).where(UserSession.user_id == auth_context.user.id).order_by(UserSession.last_seen_at.desc())
    ).all()
    recent_events = db.scalars(
        select(AuthEvent).where(AuthEvent.user_id == auth_context.user.id).order_by(AuthEvent.created_at.desc()).limit(20)
    ).all()
    detections = db.scalars(
        select(Detection).where(Detection.user_id == auth_context.user.id).order_by(Detection.occurred_at.desc()).limit(10)
    ).all()
    account_step_up_active = db.scalar(
        select(ChallengeRule.id).where(
            ChallengeRule.scope == "account",
            ChallengeRule.key == auth_context.user.email,
            ChallengeRule.expires_at >= utcnow(),
        )
    ) is not None
    return template_response(
        request,
        "account/security.html",
        notice=notice,
        sessions=active_sessions,
        recent_events=recent_events,
        detections=detections,
        account_step_up_active=account_step_up_active,
    )


@router.post("/sessions/{sid}/revoke")
def revoke_session_post(
    request: Request,
    sid: str,
    db: Session = Depends(get_db),
    auth_context=Depends(require_authenticated),
    csrf_token: str | None = Form(default=None),
):
    enforce_csrf(request, csrf_token)

    target = db.scalar(
        select(UserSession).where(
            UserSession.sid == sid,
            UserSession.user_id == auth_context.user.id,
        )
    )
    if not target:
        raise HTTPException(status_code=404, detail="Session not found")

    revoke_session(target)
    _create_containment_action(
        db,
        detection_id=None,
        action_type="self_revoke_session",
        entity_type="session",
        entity_value=sid,
        notes="Revoked from the Account Security Center.",
    )
    event = persist_auth_event(
        db,
        request,
        event_type="session_revoke",
        outcome="success",
        user=auth_context.user,
        email=auth_context.user.email,
        session_id=sid,
    )
    emit_auth_event(request, event)
    db.commit()

    response = RedirectResponse(url="/account/security?notice=session-revoked", status_code=303)
    if sid == auth_context.session.sid:
        response.delete_cookie(request.app.state.settings.session_cookie_name, path="/")
    return response
