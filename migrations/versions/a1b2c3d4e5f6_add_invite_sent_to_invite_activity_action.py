"""add invite_sent to invite_activity_action enum

Revision ID: a1b2c3d4e5f6
Revises: ec6c5e687fd9
Create Date: 2026-03-20 07:30:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'ec6c5e687fd9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PostgreSQL: ADD VALUE to existing enum type.
    # IF NOT EXISTS prevents failure on re-run.
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'invite_sent'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values without recreating the type.
    # Downgrade is a no-op — the value is harmless if unused.
    pass
