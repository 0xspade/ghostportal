"""invite_activity invite_id set null on delete

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-03-21

"""
from alembic import op

revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade():
    # Make invite_id nullable
    op.alter_column('invite_activities', 'invite_id', nullable=True)
    # Drop CASCADE FK, add SET NULL FK
    op.drop_constraint('invite_activities_invite_id_fkey', 'invite_activities', type_='foreignkey')
    op.create_foreign_key(
        'invite_activities_invite_id_fkey',
        'invite_activities', 'security_team_invites',
        ['invite_id'], ['id'],
        ondelete='SET NULL',
    )


def downgrade():
    op.drop_constraint('invite_activities_invite_id_fkey', 'invite_activities', type_='foreignkey')
    op.create_foreign_key(
        'invite_activities_invite_id_fkey',
        'invite_activities', 'security_team_invites',
        ['invite_id'], ['id'],
        ondelete='CASCADE',
    )
    op.alter_column('invite_activities', 'invite_id', nullable=False)
