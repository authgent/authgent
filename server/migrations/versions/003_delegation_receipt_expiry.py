"""Add expires_at to delegation_receipts for cascading revocation.

Revision ID: 003
Revises: 002
Create Date: 2026-08-08 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("delegation_receipts") as batch:
        batch.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index("ix_delegation_receipts_expires_at", ["expires_at"])


def downgrade() -> None:
    with op.batch_alter_table("delegation_receipts") as batch:
        batch.drop_index("ix_delegation_receipts_expires_at")
        batch.drop_column("expires_at")
