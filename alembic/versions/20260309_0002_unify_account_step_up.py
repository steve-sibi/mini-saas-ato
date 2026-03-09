"""unify account step-up enforcement

Revision ID: 20260309_0002
Revises: 20260308_0001
Create Date: 2026-03-09 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260309_0002"
down_revision = "20260308_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("step_up_required_until")

    with op.batch_alter_table("user_sessions") as batch_op:
        batch_op.drop_column("step_up_required")


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("step_up_required_until", sa.DateTime(timezone=True), nullable=True))

    with op.batch_alter_table("user_sessions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "step_up_required",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
