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

    # Create security_team_sub_invites table using raw SQL — bypasses SQLAlchemy's
    # automatic CREATE TYPE emission which ignores create_type=False in this version.
    op.execute("""
        CREATE TABLE IF NOT EXISTS security_team_sub_invites (
            id              UUID        NOT NULL DEFAULT gen_random_uuid(),
            invite_id       UUID        NOT NULL,
            requested_email VARCHAR(254) NOT NULL,
            note            TEXT,
            status          sub_invite_status NOT NULL DEFAULT 'pending',
            approved_invite_id UUID,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            reviewed_at     TIMESTAMPTZ,
            PRIMARY KEY (id),
            FOREIGN KEY (invite_id)
                REFERENCES security_team_invites(id) ON DELETE CASCADE,
            FOREIGN KEY (approved_invite_id)
                REFERENCES security_team_invites(id) ON DELETE SET NULL
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_security_team_sub_invites_invite_id
        ON security_team_sub_invites (invite_id)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_security_team_sub_invites_status
        ON security_team_sub_invites (status)
    """)


def downgrade():
    op.drop_index('ix_security_team_sub_invites_status', table_name='security_team_sub_invites')
    op.drop_index('ix_security_team_sub_invites_invite_id', table_name='security_team_sub_invites')
    op.drop_table('security_team_sub_invites')
    # PostgreSQL does not support removing enum values — enum type itself kept
