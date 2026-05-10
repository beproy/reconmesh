"""add virustotal to enrichment_type enum

Revision ID: 62900eaa4fba
Revises: dc55da13de80
Create Date: 2026-05-10 19:36:47.356992

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '62900eaa4fba'
down_revision: Union[str, None] = 'dc55da13de80'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Alembic can't auto-detect enum value additions in Postgres.
    # We manually add 'virustotal' to the enrichment_type_enum.
    op.execute("ALTER TYPE enrichment_type_enum ADD VALUE IF NOT EXISTS 'VIRUSTOTAL'")


def downgrade() -> None:
    # Postgres doesn't support removing values from enums.
    # This is a one-way migration, which is fine — the value is harmless
    # even if the enricher code is removed.
    pass
