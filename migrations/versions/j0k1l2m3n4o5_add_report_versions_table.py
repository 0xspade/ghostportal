# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0 License

"""Add report_versions table

Revision ID: j0k1l2m3n4o5
Revises: i9j0k1l2m3n4
Create Date: 2026-05-05

"""
import app.models
import sqlalchemy as sa
from alembic import op

revision = 'j0k1l2m3n4o5'
down_revision = 'i9j0k1l2m3n4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'report_versions',
        sa.Column('id', app.models.GUID(), nullable=False),
        sa.Column('report_id', app.models.GUID(), sa.ForeignKey('reports.id', ondelete='CASCADE'), nullable=False),
        sa.Column('snapshot', sa.JSON(), nullable=False),
        sa.Column('changed_fields', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_report_versions_report_id'), 'report_versions', ['report_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_report_versions_report_id'), table_name='report_versions')
    op.drop_table('report_versions')
