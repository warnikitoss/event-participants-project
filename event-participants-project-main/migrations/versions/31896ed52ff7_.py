"""empty message

Revision ID: 31896ed52ff7
Revises: f55efb1655d6
Create Date: 2025-04-06 20:57:49.834037

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '31896ed52ff7'
down_revision = 'f55efb1655d6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('avat', sa.String(length=200), nullable=True))
        batch_op.drop_column('last_seen')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('last_seen', sa.DATETIME(), nullable=True))
        batch_op.drop_column('avat')

    # ### end Alembic commands ###
