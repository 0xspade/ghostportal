"""add is_bonus to bounty_payments

Revision ID: g7h8i9j0k1l2
Revises: f6a7b8c9d0e1
Create Date: 2026-03-21

"""
from alembic import op
import sqlalchemy as sa

revision = 'g7h8i9j0k1l2'
down_revision = 'f6a7b8c9d0e1'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'bounty_payments',
        sa.Column('is_bonus', sa.Boolean(), nullable=False, server_default='false')
    )


def downgrade():
    op.drop_column('bounty_payments', 'is_bonus')
