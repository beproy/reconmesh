"""add shodan and abuseipdb to enrichment_type enum

Revision ID: c891ae6a28a9
Revises: 62900eaa4fba
Create Date: 2026-05-11 03:37:40.112054

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c891ae6a28a9'
down_revision: Union[str, None] = '62900eaa4fba'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE enrichment_type_enum ADD VALUE IF NOT EXISTS 'SHODAN'")
    op.execute("ALTER TYPE enrichment_type_enum ADD VALUE IF NOT EXISTS 'ABUSEIPDB'")


def downgrade() -> None:
    pass
