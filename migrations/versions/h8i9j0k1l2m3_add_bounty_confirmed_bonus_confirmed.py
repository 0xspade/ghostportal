# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0 License

"""Add bounty_confirmed and bonus_confirmed to invite_activity_action enum

Revision ID: h8i9j0k1l2m3
Revises: g7h8i9j0k1l2
Create Date: 2026-03-21

"""
from alembic import op

revision = 'h8i9j0k1l2m3'
down_revision = 'g7h8i9j0k1l2'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'bounty_confirmed'")
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'bonus_confirmed'")


def downgrade():
    # PostgreSQL does not support removing enum values — downgrade is a no-op
    pass
