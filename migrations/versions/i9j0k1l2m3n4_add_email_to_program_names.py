# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0 License

"""Add email column to program_names table

Revision ID: i9j0k1l2m3n4
Revises: h8i9j0k1l2m3
Create Date: 2026-03-31

"""
import sqlalchemy as sa
from alembic import op

revision = 'i9j0k1l2m3n4'
down_revision = 'h8i9j0k1l2m3'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'program_names',
        sa.Column('email', sa.String(254), nullable=True),
    )


def downgrade():
    op.drop_column('program_names', 'email')
