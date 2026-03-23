# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Add not_applicable to report_status_enum and report_reopened to invite_activity_action

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-03-21
"""

from alembic import op

revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TYPE report_status_enum ADD VALUE IF NOT EXISTS 'not_applicable'")
    op.execute("ALTER TYPE invite_activity_action ADD VALUE IF NOT EXISTS 'report_reopened'")


def downgrade():
    # PostgreSQL does not support removing enum values
    pass
