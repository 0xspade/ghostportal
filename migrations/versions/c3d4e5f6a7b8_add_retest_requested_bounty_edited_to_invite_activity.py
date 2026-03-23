"""add retest_requested and bounty_edited to invite_activity_action enum

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-03-21 02:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'retest_requested'")
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'bounty_edited'")


def downgrade() -> None:
    pass
