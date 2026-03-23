"""add_cvss_vector_cvss_score_to_report_templates

Revision ID: ec6c5e687fd9
Revises: 35dd88de73d8
Create Date: 2026-03-20 06:17:27.837532+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ec6c5e687fd9'
down_revision: Union[str, None] = '35dd88de73d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('report_templates', sa.Column('cvss_vector', sa.String(500), nullable=True))
    op.add_column('report_templates', sa.Column('cvss_score', sa.Numeric(4, 1), nullable=True))


def downgrade() -> None:
    op.drop_column('report_templates', 'cvss_score')
    op.drop_column('report_templates', 'cvss_vector')
