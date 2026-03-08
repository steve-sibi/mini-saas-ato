"""initial schema

Revision ID: 20260308_0001
Revises:
Create Date: 2026-03-08 00:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260308_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("mfa_secret", sa.String(length=64), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("step_up_required_until", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=False)

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"])
    op.create_index("ix_mfa_recovery_codes_code_hash", "mfa_recovery_codes", ["code_hash"])

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sid", sa.String(length=96), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("device_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("last_seen_ip", sa.String(length=64), nullable=False),
        sa.Column("last_seen_country", sa.String(length=8), nullable=True),
        sa.Column("last_seen_city", sa.String(length=255), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("step_up_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("sid"),
    )
    op.create_index("ix_user_sessions_sid", "user_sessions", ["sid"], unique=False)
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"], unique=False)
    op.create_index(
        "ix_user_sessions_user_revoked_expires",
        "user_sessions",
        ["user_id", "revoked_at", "expires_at"],
        unique=False,
    )
    op.create_index("ix_user_sessions_device_fingerprint", "user_sessions", ["device_fingerprint"], unique=False)

    op.create_table(
        "auth_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("session_id", sa.String(length=96), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=False),
        sa.Column("country_code", sa.String(length=8), nullable=True),
        sa.Column("city", sa.String(length=255), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("asn", sa.String(length=64), nullable=True),
        sa.Column("device_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_flags", sa.JSON(), nullable=False),
    )
    op.create_index("ix_auth_events_created_at", "auth_events", ["created_at"], unique=False)
    op.create_index("ix_auth_events_event_type", "auth_events", ["event_type"], unique=False)
    op.create_index("ix_auth_events_outcome", "auth_events", ["outcome"], unique=False)
    op.create_index("ix_auth_events_user_id", "auth_events", ["user_id"], unique=False)
    op.create_index("ix_auth_events_email", "auth_events", ["email"], unique=False)
    op.create_index("ix_auth_events_session_id", "auth_events", ["session_id"], unique=False)
    op.create_index("ix_auth_events_source_ip", "auth_events", ["source_ip"], unique=False)
    op.create_index("ix_auth_events_device_fingerprint", "auth_events", ["device_fingerprint"], unique=False)

    op.create_table(
        "detections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("detection_type", sa.String(length=32), nullable=False),
        sa.Column("mitre_attack_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_value", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("containment_state", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("session_id", sa.String(length=96), nullable=True),
        sa.Column("auth_event_id", sa.Integer(), sa.ForeignKey("auth_events.id"), nullable=True),
        sa.Column("runbook_path", sa.String(length=255), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_detections_detection_type", "detections", ["detection_type"], unique=False)
    op.create_index("ix_detections_mitre_attack_id", "detections", ["mitre_attack_id"], unique=False)
    op.create_index("ix_detections_subject_type", "detections", ["subject_type"], unique=False)
    op.create_index("ix_detections_subject_value", "detections", ["subject_value"], unique=False)
    op.create_index("ix_detections_occurred_at", "detections", ["occurred_at"], unique=False)
    op.create_index("ix_detections_user_id", "detections", ["user_id"], unique=False)
    op.create_index("ix_detections_session_id", "detections", ["session_id"], unique=False)
    op.create_index("ix_detections_auth_event_id", "detections", ["auth_event_id"], unique=False)

    op.create_table(
        "containment_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("detection_id", sa.Integer(), sa.ForeignKey("detections.id"), nullable=True),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_value", sa.String(length=255), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("external_id"),
    )
    op.create_index("ix_containment_actions_detection_id", "containment_actions", ["detection_id"], unique=False)
    op.create_index("ix_containment_actions_entity_type", "containment_actions", ["entity_type"], unique=False)
    op.create_index("ix_containment_actions_entity_value", "containment_actions", ["entity_value"], unique=False)

    op.create_table(
        "challenge_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detection_id", sa.Integer(), sa.ForeignKey("detections.id"), nullable=True),
    )
    op.create_index("ix_challenge_rules_scope", "challenge_rules", ["scope"], unique=False)
    op.create_index("ix_challenge_rules_key", "challenge_rules", ["key"], unique=False)
    op.create_index("ix_challenge_rules_expires_at", "challenge_rules", ["expires_at"], unique=False)
    op.create_index(
        "ix_challenge_rules_scope_key_expires",
        "challenge_rules",
        ["scope", "key", "expires_at"],
        unique=False,
    )

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.create_index(
            "ix_auth_events_login_ip_created_desc",
            "auth_events",
            ["source_ip", sa.text("created_at DESC")],
            unique=False,
            postgresql_where=sa.text("event_type = 'login'"),
        )
        op.create_index(
            "ix_auth_events_login_email_created_desc",
            "auth_events",
            ["email", sa.text("created_at DESC")],
            unique=False,
            postgresql_where=sa.text("event_type = 'login'"),
        )
        op.create_index(
            "ix_auth_events_login_email_ip_created_desc",
            "auth_events",
            ["email", "source_ip", sa.text("created_at DESC")],
            unique=False,
            postgresql_where=sa.text("event_type = 'login'"),
        )
        op.create_index(
            "ix_auth_events_authenticated_session_created_desc",
            "auth_events",
            ["session_id", sa.text("created_at DESC")],
            unique=False,
            postgresql_where=sa.text("session_id IS NOT NULL"),
        )


def downgrade() -> None:
    op.drop_table("challenge_rules")
    op.drop_table("containment_actions")
    op.drop_table("detections")
    op.drop_table("auth_events")
    op.drop_table("user_sessions")
    op.drop_table("mfa_recovery_codes")
    op.drop_table("users")
