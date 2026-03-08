from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ato_sentinel.config import Settings
from ato_sentinel.models import MfaRecoveryCode, User, UserSession, ensure_utc, utcnow
from ato_sentinel.security import generate_session_id, hash_backup_code, hash_password
from ato_sentinel.types import GeoContext, RequestContext


def normalize_email(email: str) -> str:
    return email.strip().lower()


def create_user(db: Session, email: str, password: str) -> User:
    user = User(email=normalize_email(email), password_hash=hash_password(password))
    db.add(user)
    db.flush()
    return user


def is_step_up_active(user: User) -> bool:
    step_up_until = ensure_utc(user.step_up_required_until)
    if not step_up_until:
        return False
    return step_up_until > utcnow()


def issue_session(
    db: Session,
    settings: Settings,
    user: User,
    request_context: RequestContext,
    geo: GeoContext,
) -> UserSession:
    session_record = UserSession(
        sid=generate_session_id(),
        user_id=user.id,
        expires_at=utcnow() + timedelta(hours=settings.session_ttl_hours),
        device_fingerprint=request_context.device_fingerprint,
        last_seen_ip=request_context.ip,
        last_seen_country=geo.country_code,
        last_seen_city=geo.city,
        last_seen_at=utcnow(),
        step_up_required=is_step_up_active(user),
    )
    db.add(session_record)
    db.flush()
    return session_record


def revoke_session(session_record: UserSession) -> None:
    if not session_record.revoked_at:
        session_record.revoked_at = utcnow()


def revoke_other_sessions(db: Session, user_id: int, keep_sid: str | None = None) -> int:
    active_sessions = db.scalars(
        select(UserSession).where(
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
        )
    ).all()
    revoked = 0
    for session_record in active_sessions:
        if keep_sid and session_record.sid == keep_sid:
            continue
        revoke_session(session_record)
        revoked += 1
    return revoked


def replace_recovery_codes(db: Session, user: User, raw_codes: list[str]) -> None:
    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    for code in raw_codes:
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=hash_backup_code(code)))
    db.flush()


def consume_backup_code(db: Session, user: User, raw_code: str) -> bool:
    code_hash = hash_backup_code(raw_code.strip().upper())
    recovery_code = db.scalar(
        select(MfaRecoveryCode).where(
            MfaRecoveryCode.user_id == user.id,
            MfaRecoveryCode.code_hash == code_hash,
            MfaRecoveryCode.used_at.is_(None),
        )
    )
    if not recovery_code:
        return False
    recovery_code.used_at = utcnow()
    return True
