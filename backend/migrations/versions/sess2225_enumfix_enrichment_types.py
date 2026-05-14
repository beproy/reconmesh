"""fix session 22-25 enrichment type enum case

Revision ID: sess2225_enumfix
Revises: sess2225_enrichtypes
Create Date: 2026-05-14

The previous migration (sess2225_enrichtypes) added the new enrichment
type values in lowercase: 'urlscan', 'hackertarget', 'mnemonic_pdns',
'threatminer'.

But SQLAlchemy's default Enum mapping uses the Python enum MEMBER NAME,
not its value. Every existing value in the DB enum is uppercase
('DNS', 'VIRUSTOTAL', etc.) — matching the member names. So the new
values also need to be uppercase to match what SQLAlchemy emits.

This migration adds the correct UPPERCASE values:
  - URLSCAN
  - HACKERTARGET
  - MNEMONIC_PDNS
  - THREATMINER

The lowercase values from the previous migration are left in place.
Postgres does not support removing enum values, but unused values are
harmless — nothing in the codebase will ever reference them.
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "sess2225_enumfix"
down_revision = "sess2225_enrichtypes"
branch_labels = None
depends_on = None


ENUM_NAME = "enrichment_type_enum"

# UPPERCASE — matches the Python enum member names, which is what
# SQLAlchemy's default Enum mapping sends to Postgres.
NEW_VALUES = [
    "URLSCAN",
    "HACKERTARGET",
    "MNEMONIC_PDNS",
    "THREATMINER",
]


def upgrade() -> None:
    for value in NEW_VALUES:
        op.execute(f"ALTER TYPE {ENUM_NAME} ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    # Postgres does not support removing enum values. No-op by design —
    # see the long comment in add_session22_25_enrichment_types.py.
    pass
