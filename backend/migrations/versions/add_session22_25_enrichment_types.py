"""add session 22-25 enrichment types

Revision ID: sess2225_enrichtypes
Revises: <PASTE_CURRENT_HEAD_HERE>
Create Date: 2026-05-14

Adds four new values to the enrichment_type_enum Postgres type:
  - urlscan        (Session 22 — URLScan.io)
  - hackertarget   (Session 23 — HackerTarget reverse-IP)
  - mnemonic_pdns  (Session 24 — Mnemonic Passive DNS)
  - threatminer    (Session 25 — ThreatMiner)

Postgres enums can't have values added inside a transaction in older
versions, but PG 12+ (we're on 16) allows ALTER TYPE ... ADD VALUE
in a transaction. Alembic runs migrations transactionally, so this is
fine on PG 16. We use IF NOT EXISTS so the migration is idempotent —
re-running it won't error if a value already exists.
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "sess2225_enrichtypes"
down_revision = "a7b9c2d4e5f1"  # <- replace with output of `alembic heads`
branch_labels = None
depends_on = None


# The enum type name — matches Enum(EnrichmentType, name="enrichment_type_enum")
ENUM_NAME = "enrichment_type_enum"

NEW_VALUES = [
    "urlscan",
    "hackertarget",
    "mnemonic_pdns",
    "threatminer",
]


def upgrade() -> None:
    for value in NEW_VALUES:
        op.execute(f"ALTER TYPE {ENUM_NAME} ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    # Postgres does NOT support removing values from an enum type.
    # The only way to "remove" a value is to recreate the type without it,
    # which means rewriting every column that uses it. That's destructive
    # and not worth it for a downgrade path on a dev tool.
    #
    # If you genuinely need to roll back, the practical approach is:
    #   1. Ensure no rows use the new enum values
    #   2. Manually recreate the type
    # We intentionally leave downgrade as a no-op rather than provide a
    # footgun.
    pass
