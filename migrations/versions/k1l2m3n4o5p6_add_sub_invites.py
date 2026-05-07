# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0 License

"""Add security_team_sub_invites table and sub_invite enum values

Revision ID: k1l2m3n4o5p6
Revises: j0k1l2m3n4o5
Create Date: 2026-05-07

"""
import sqlalchemy as sa
from alembic import op

revision = 'k1l2m3n4o5p6'
down_revision = 'j0k1l2m3n4o5'
branch_labels = None
depends_on = None


def upgrade():
    # Add new enum values for InviteActivity.action
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'sub_invite_requested'")
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'sub_invite_approved'")
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'sub_invite_rejected'")

    # Create sub_invite_status enum
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE sub_invite_status AS ENUM ('pending', 'approved', 'rejected');
        EXCEPTION
            WHEN duplicate_object THEN NULL;
        END $$;
    """)

    # Create security_team_sub_invites table
    op.create_table(
        'security_team_sub_invites',
        sa.Column('id', sa.dialects.postgresql.UUID(as_uuid=True), nullable=False,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('invite_id', sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('requested_email', sa.String(254), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('status', sa.dialects.postgresql.ENUM(
                      'pending', 'approved', 'rejected',
                      name='sub_invite_status', create_type=False),
                  nullable=False, server_default='pending'),
        sa.Column('approved_invite_id', sa.dialects.postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['invite_id'], ['security_team_invites.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['approved_invite_id'], ['security_team_invites.id'],
                                ondelete='SET NULL'),
    )
    op.create_index('ix_security_team_sub_invites_invite_id',
                    'security_team_sub_invites', ['invite_id'])
    op.create_index('ix_security_team_sub_invites_status',
                    'security_team_sub_invites', ['status'])


def downgrade():
    op.drop_index('ix_security_team_sub_invites_status', table_name='security_team_sub_invites')
    op.drop_index('ix_security_team_sub_invites_invite_id', table_name='security_team_sub_invites')
    op.drop_table('security_team_sub_invites')
    # PostgreSQL does not support removing enum values — enum type itself kept
