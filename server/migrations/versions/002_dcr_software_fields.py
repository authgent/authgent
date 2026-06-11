"""Add RFC 7591 software_id/software_version/software_statement to oauth_clients.

Revision ID: 002
Revises: 001
Create Date: 2026-06-10 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("oauth_clients") as batch:
        batch.add_column(sa.Column("software_id", sa.String(255), nullable=True))
        batch.add_column(sa.Column("software_version", sa.String(64), nullable=True))
        batch.add_column(sa.Column("software_statement", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("oauth_clients") as batch:
        batch.drop_column("software_statement")
        batch.drop_column("software_version")
        batch.drop_column("software_id")
