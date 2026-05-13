"""add mitre attack tables

Revision ID: a7b9c2d4e5f1
Revises: <PASTE_CURRENT_HEAD_HERE>
Create Date: 2026-05-13

Adds four tables to support MITRE ATT&CK Enterprise data:
  attack_groups, attack_techniques, attack_malware, attack_relationships

All four use STIX ID as the primary key. attack_id (G0016 / T1566.001 /
S0367) is a separate uniquely-indexed column — it's the human-readable
identifier we'll show in the UI.

Relationships table is intentionally NOT foreign-keyed to the others:
STIX relationships can point at object types we don't import (tools,
mitigations, campaigns, data components). source_ref and target_ref are
indexed for pivot performance instead.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "a7b9c2d4e5f1"
down_revision = "81ba3f47884f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_groups",
        sa.Column("stix_id", sa.Text(), primary_key=True),
        sa.Column("attack_id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("aliases", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("external_references", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_attack_groups_attack_id", "attack_groups", ["attack_id"], unique=True)
    op.create_index("ix_attack_groups_name", "attack_groups", ["name"])

    op.create_table(
        "attack_techniques",
        sa.Column("stix_id", sa.Text(), primary_key=True),
        sa.Column("attack_id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kill_chain_phases", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("platforms", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("data_sources", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("detection", sa.Text(), nullable=True),
        sa.Column("external_references", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_attack_techniques_attack_id", "attack_techniques", ["attack_id"], unique=True)

    op.create_table(
        "attack_malware",
        sa.Column("stix_id", sa.Text(), primary_key=True),
        sa.Column("attack_id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("aliases", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("malware_types", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("platforms", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_family", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("external_references", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_attack_malware_attack_id", "attack_malware", ["attack_id"], unique=True)
    op.create_index("ix_attack_malware_name", "attack_malware", ["name"])

    op.create_table(
        "attack_relationships",
        sa.Column("stix_id", sa.Text(), primary_key=True),
        sa.Column("relationship_type", sa.Text(), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=False),
        sa.Column("target_ref", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_attack_rel_type", "attack_relationships", ["relationship_type"])
    op.create_index("ix_attack_rel_source", "attack_relationships", ["source_ref"])
    op.create_index("ix_attack_rel_target", "attack_relationships", ["target_ref"])


def downgrade() -> None:
    op.drop_index("ix_attack_rel_target", table_name="attack_relationships")
    op.drop_index("ix_attack_rel_source", table_name="attack_relationships")
    op.drop_index("ix_attack_rel_type", table_name="attack_relationships")
    op.drop_table("attack_relationships")

    op.drop_index("ix_attack_malware_name", table_name="attack_malware")
    op.drop_index("ix_attack_malware_attack_id", table_name="attack_malware")
    op.drop_table("attack_malware")

    op.drop_index("ix_attack_techniques_attack_id", table_name="attack_techniques")
    op.drop_table("attack_techniques")

    op.drop_index("ix_attack_groups_name", table_name="attack_groups")
    op.drop_index("ix_attack_groups_attack_id", table_name="attack_groups")
    op.drop_table("attack_groups")
