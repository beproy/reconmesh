"""add ahmia to enrichment_type enum

Revision ID: 0eb2e270946e
Revises: 363d2677c921
Create Date: 2026-05-12 10:12:19.664816

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0eb2e270946e'
down_revision: Union[str, None] = '363d2677c921'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE enrichment_type_enum ADD VALUE IF NOT EXISTS 'AHMIA'")


def downgrade() -> None:
    pass
