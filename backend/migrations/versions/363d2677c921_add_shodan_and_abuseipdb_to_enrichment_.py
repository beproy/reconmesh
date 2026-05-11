"""add shodan and abuseipdb to enrichment_type enum

Revision ID: 363d2677c921
Revises: c891ae6a28a9
Create Date: 2026-05-11 03:41:23.273644

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '363d2677c921'
down_revision: Union[str, None] = 'c891ae6a28a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE enrichment_type_enum ADD VALUE IF NOT EXISTS 'SHODAN'")
    op.execute("ALTER TYPE enrichment_type_enum ADD VALUE IF NOT EXISTS 'ABUSEIPDB'")


def downgrade() -> None:
    pass
