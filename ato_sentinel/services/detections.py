from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from ato_sentinel.models import AuthEvent, ChallengeRule, ContainmentAction, Detection, User, UserSession, ensure_utc, utcnow
from ato_sentinel.services.authentication import revoke_other_sessions, revoke_session
from ato_sentinel.services.events import append_risk_flag, emit_auth_event, persist_auth_event
from ato_sentinel.types import GeoContext


@dataclass(frozen=True)
class DetectionSpec:
    code: str
    mitre: str
    risk_flag: str
    title: str
    runbook_path: str


DETECTION_SPECS = {
    "ATO-001": DetectionSpec(
        code="ATO-001",
        mitre="T1110.003",
        risk_flag="password_spray_suspected",
        title="Password spray suspected",
        runbook_path="runbooks/ATO-001-Password-Spray.md",
    ),
    "ATO-002": DetectionSpec(
        code="ATO-002",
        mitre="T1550.004",
        risk_flag="session_reuse_suspected",
        title="Session cookie reuse suspected",
        runbook_path="runbooks/ATO-002-Session-Reuse.md",
    ),
    "ATO-003": DetectionSpec(
        code="ATO-003",
        mitre="T1078.004",
        risk_flag="impossible_travel_suspected",
        title="Impossible travel suspected",
        runbook_path="runbooks/ATO-003-Impossible-Travel.md",
    ),
    "ATO-004": DetectionSpec(
        code="ATO-004",
        mitre="T1110.004",
        risk_flag="distributed_credential_stuffing_suspected",
        title="Distributed credential stuffing suspected",
        runbook_path="runbooks/ATO-004-Distributed-Credential-Stuffing.md",
    ),
}


def _ensure_detection(
    db: Session,
    *,
    detection_type: str,
    subject_type: str,
    subject_value: str,
    occurred_at: datetime,
    description: str,
    user_id: int | None,
    session_id: str | None,
    auth_event_id: int | None,
    dedupe_window: timedelta,
) -> Detection:
    spec = DETECTION_SPECS[detection_type]
    window_start = occurred_at - dedupe_window
    existing = db.scalar(
        select(Detection).where(
            Detection.detection_type == detection_type,
            Detection.subject_type == subject_type,
            Detection.subject_value == subject_value,
            Detection.occurred_at >= window_start,
        ).order_by(Detection.occurred_at.desc())
    )
    if existing:
        existing.occurred_at = occurred_at
        existing.description = description
        existing.auth_event_id = auth_event_id
        if session_id:
            existing.session_id = session_id
        return existing

    detection = Detection(
        detection_type=detection_type,
        mitre_attack_id=spec.mitre,
        subject_type=subject_type,
        subject_value=subject_value,
        title=spec.title,
        description=description,
        containment_state="pending",
        occurred_at=occurred_at,
        user_id=user_id,
        session_id=session_id,
        auth_event_id=auth_event_id,
        runbook_path=spec.runbook_path,
    )
    db.add(detection)
    db.flush()
    return detection


def _ensure_challenge_rule(
    db: Session,
    *,
    scope: str,
    key: str,
    reason: str,
    detection_id: int | None,
    expires_at: datetime,
) -> ChallengeRule:
    rule = db.scalar(
        select(ChallengeRule).where(
            ChallengeRule.scope == scope,
            ChallengeRule.key == key,
            ChallengeRule.expires_at >= utcnow(),
        ).order_by(ChallengeRule.expires_at.desc())
    )
    if rule:
        current_expiry = ensure_utc(rule.expires_at) or utcnow()
        next_expiry = ensure_utc(expires_at) or expires_at
        if current_expiry < next_expiry:
            rule.expires_at = expires_at
        rule.reason = reason
        if detection_id:
            rule.detection_id = detection_id
        return rule

    rule = ChallengeRule(
        scope=scope,
        key=key,
        reason=reason,
        expires_at=expires_at,
        detection_id=detection_id,
    )
    db.add(rule)
    db.flush()
    return rule


def _create_containment_action(
    db: Session,
    *,
    detection_id: int | None,
    action_type: str,
    entity_type: str,
    entity_value: str,
    notes: str | None = None,
    external_id: str | None = None,
) -> ContainmentAction:
    if external_id:
        existing = db.scalar(select(ContainmentAction).where(ContainmentAction.external_id == external_id))
        if existing:
            return existing
    action = ContainmentAction(
        detection_id=detection_id,
        action_type=action_type,
        entity_type=entity_type,
        entity_value=entity_value,
        notes=notes,
        external_id=external_id,
        executed_at=utcnow(),
    )
    db.add(action)
    db.flush()
    return action


def challenge_required_for_login(db: Session, source_ip: str, email: str | None) -> tuple[bool, list[str]]:
    active_rules = db.scalars(
        select(ChallengeRule).where(ChallengeRule.expires_at >= utcnow())
    ).all()
    reasons: list[str] = []
    for rule in active_rules:
        if rule.scope == "ip" and rule.key == source_ip:
            reasons.append(rule.reason)
        if email and rule.scope == "account" and rule.key == email:
            reasons.append(rule.reason)
    return bool(reasons), reasons


def evaluate_login_failure(db: Session, event: AuthEvent) -> list[Detection]:
    detections: list[Detection] = []

    spray_window = event.created_at - timedelta(minutes=10)
    spray_count, targeted_accounts = db.execute(
        select(
            func.count(AuthEvent.id),
            func.count(distinct(AuthEvent.email)),
        ).where(
            AuthEvent.event_type == "login",
            AuthEvent.outcome == "fail",
            AuthEvent.source_ip == event.source_ip,
            AuthEvent.created_at >= spray_window,
        )
    ).one()
    if spray_count >= 15 and targeted_accounts >= 5:
        append_risk_flag(event, DETECTION_SPECS["ATO-001"].risk_flag, 60)
        detection = _ensure_detection(
            db,
            detection_type="ATO-001",
            subject_type="ip",
            subject_value=event.source_ip,
            occurred_at=event.created_at,
            description="High-volume failed logins from one IP across many accounts.",
            user_id=event.user_id,
            session_id=event.session_id,
            auth_event_id=event.id,
            dedupe_window=timedelta(minutes=10),
        )
        _ensure_challenge_rule(
            db,
            scope="ip",
            key=event.source_ip,
            reason="password_spray",
            detection_id=detection.id,
            expires_at=event.created_at + timedelta(minutes=15),
        )
        _create_containment_action(
            db,
            detection_id=detection.id,
            action_type="challenge_ip",
            entity_type="ip",
            entity_value=event.source_ip,
            notes="Require Turnstile for 15 minutes.",
        )
        detection.containment_state = "challenged"
        detections.append(detection)

    stuffing_window = event.created_at - timedelta(minutes=15)
    failure_count, distinct_ips = db.execute(
        select(
            func.count(AuthEvent.id),
            func.count(distinct(AuthEvent.source_ip)),
        ).where(
            AuthEvent.event_type == "login",
            AuthEvent.outcome == "fail",
            AuthEvent.email == event.email,
            AuthEvent.created_at >= stuffing_window,
        )
    ).one()
    if event.email and failure_count >= 8 and distinct_ips >= 5:
        append_risk_flag(event, DETECTION_SPECS["ATO-004"].risk_flag, 70)
        detection = _ensure_detection(
            db,
            detection_type="ATO-004",
            subject_type="account",
            subject_value=event.email,
            occurred_at=event.created_at,
            description="Repeated failed logins against one account from distributed IPs.",
            user_id=event.user_id,
            session_id=event.session_id,
            auth_event_id=event.id,
            dedupe_window=timedelta(minutes=15),
        )
        _ensure_challenge_rule(
            db,
            scope="account",
            key=event.email,
            reason="distributed_credential_stuffing",
            detection_id=detection.id,
            expires_at=event.created_at + timedelta(minutes=30),
        )
        _create_containment_action(
            db,
            detection_id=detection.id,
            action_type="challenge_account",
            entity_type="account",
            entity_value=event.email,
            notes="Require Turnstile and step-up on the targeted account.",
        )
        detection.containment_state = "challenged"
        detections.append(detection)

    return detections


def _distance_km(lat_one: float, lon_one: float, lat_two: float, lon_two: float) -> float:
    radius_km = 6371.0
    d_lat = math.radians(lat_two - lat_one)
    d_lon = math.radians(lon_two - lon_one)
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(math.radians(lat_one))
        * math.cos(math.radians(lat_two))
        * math.sin(d_lon / 2) ** 2
    )
    return 2 * radius_km * math.asin(math.sqrt(a))


def evaluate_login_success(
    db: Session,
    event: AuthEvent,
    user: User,
    session_record: UserSession,
) -> list[Detection]:
    previous_login = db.scalar(
        select(AuthEvent).where(
            AuthEvent.user_id == user.id,
            AuthEvent.event_type == "login",
            AuthEvent.outcome == "success",
            AuthEvent.id != event.id,
        ).order_by(AuthEvent.created_at.desc())
    )
    if not previous_login:
        return []

    if previous_login.device_fingerprint == event.device_fingerprint:
        return []
    if not all(
        value is not None
        for value in (
            previous_login.latitude,
            previous_login.longitude,
            event.latitude,
            event.longitude,
        )
    ):
        return []

    event_created_at = ensure_utc(event.created_at) or utcnow()
    previous_created_at = ensure_utc(previous_login.created_at)
    if previous_created_at is None:
        return []
    elapsed_hours = (event_created_at - previous_created_at).total_seconds() / 3600
    if elapsed_hours <= 0 or elapsed_hours >= 6:
        return []

    distance_km = _distance_km(
        previous_login.latitude,
        previous_login.longitude,
        event.latitude,
        event.longitude,
    )
    if distance_km / elapsed_hours <= 900:
        return []

    append_risk_flag(event, DETECTION_SPECS["ATO-003"].risk_flag, 85)
    detection = _ensure_detection(
        db,
        detection_type="ATO-003",
        subject_type="account",
        subject_value=user.email,
        occurred_at=event.created_at,
        description="Successful login pattern implies impossible travel with a new device fingerprint.",
        user_id=user.id,
        session_id=session_record.sid,
        auth_event_id=event.id,
        dedupe_window=timedelta(hours=6),
    )
    user.step_up_required_until = event_created_at + timedelta(hours=24)
    revoked = revoke_other_sessions(db, user.id, keep_sid=session_record.sid)
    _create_containment_action(
        db,
        detection_id=detection.id,
        action_type="step_up_account",
        entity_type="account",
        entity_value=user.email,
        notes="Require MFA-based step-up for 24 hours.",
    )
    _create_containment_action(
        db,
        detection_id=detection.id,
        action_type="revoke_other_sessions",
        entity_type="account",
        entity_value=user.email,
        notes=f"Revoked {revoked} prior active session(s).",
    )
    detection.containment_state = "contained"
    return [detection]


def handle_session_reuse(
    db: Session,
    request: Request,
    session_record: UserSession,
    user: User,
    geo: GeoContext,
) -> Detection:
    event = persist_auth_event(
        db,
        request,
        event_type="session_access",
        outcome="blocked",
        user=user,
        email=user.email,
        session_id=session_record.sid,
    )
    append_risk_flag(event, DETECTION_SPECS["ATO-002"].risk_flag, 90)
    detection = _ensure_detection(
        db,
        detection_type="ATO-002",
        subject_type="session",
        subject_value=session_record.sid,
        occurred_at=event.created_at,
        description=(
            f"Session reuse suspected from {request.state.context.ip}"
            f" with geo status {geo.status}."
        ),
        user_id=user.id,
        session_id=session_record.sid,
        auth_event_id=event.id,
        dedupe_window=timedelta(hours=1),
    )
    revoke_session(session_record)
    _create_containment_action(
        db,
        detection_id=detection.id,
        action_type="revoke_session",
        entity_type="session",
        entity_value=session_record.sid,
        notes="Revoked the session after a device fingerprint mismatch.",
    )
    detection.containment_state = "contained"
    emit_auth_event(request, event, [detection.detection_type])
    return detection


def apply_webhook_containment(
    db: Session,
    *,
    detection_type: str,
    entity_type: str,
    entity_value: str,
    external_id: str,
    monitor_name: str,
    occurred_at: datetime,
) -> tuple[ContainmentAction, bool]:
    existing = db.scalar(select(ContainmentAction).where(ContainmentAction.external_id == external_id))
    if existing:
        return existing, True

    spec = DETECTION_SPECS.get(detection_type)
    if not spec:
        raise ValueError(f"unsupported detection type: {detection_type}")

    detection = _ensure_detection(
        db,
        detection_type=detection_type,
        subject_type=entity_type,
        subject_value=entity_value,
        occurred_at=occurred_at,
        description=f"Datadog containment invoked from monitor {monitor_name}.",
        user_id=None,
        session_id=entity_value if entity_type == "session" else None,
        auth_event_id=None,
        dedupe_window=timedelta(hours=1),
    )

    action_type = "external_containment"
    if entity_type == "ip":
        _ensure_challenge_rule(
            db,
            scope="ip",
            key=entity_value,
            reason="datadog_webhook",
            detection_id=detection.id,
            expires_at=occurred_at + timedelta(minutes=15),
        )
        action_type = "challenge_ip"
        detection.containment_state = "challenged"
    elif entity_type == "session":
        session_record = db.scalar(select(UserSession).where(UserSession.sid == entity_value))
        if session_record:
            revoke_session(session_record)
        action_type = "revoke_session"
        detection.containment_state = "contained"
    elif entity_type == "account":
        _ensure_challenge_rule(
            db,
            scope="account",
            key=entity_value,
            reason="datadog_webhook",
            detection_id=detection.id,
            expires_at=occurred_at + timedelta(minutes=30),
        )
        user = db.scalar(select(User).where(User.email == entity_value))
        if user:
            user.step_up_required_until = max(
                ensure_utc(user.step_up_required_until) or occurred_at,
                occurred_at + timedelta(hours=24),
            )
        action_type = "challenge_account"
        detection.containment_state = "challenged"
    else:
        raise ValueError(f"unsupported entity type: {entity_type}")

    action = _create_containment_action(
        db,
        detection_id=detection.id,
        action_type=action_type,
        entity_type=entity_type,
        entity_value=entity_value,
        notes=f"Applied from Datadog monitor {monitor_name}.",
        external_id=external_id,
    )
    return action, False
