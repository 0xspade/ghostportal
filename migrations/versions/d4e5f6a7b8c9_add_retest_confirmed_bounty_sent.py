# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0 License

"""Add retest_confirmed and bounty_sent to invite_activity_action enum

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-03-21
"""

from alembic import op
import sqlalchemy as sa

revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'bounty_sent'")
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'retest_confirmed'")


def downgrade():
    # PostgreSQL does not support removing values from an enum type
    pass
