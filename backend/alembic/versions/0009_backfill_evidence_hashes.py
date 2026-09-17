"""backfill provenance digests for pre-provenance findings
Revision ID: 0009_backfill_evidence_hashes
Revises: 0008_asset_scan_set_null
"""
import hashlib
import json
from alembic import op
import sqlalchemy as sa

revision = "0009_backfill_evidence_hashes"
down_revision = "0008_asset_scan_set_null"


def _digest(value):
    canonical=json.dumps(value or {},sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def upgrade():
    bind=op.get_bind()
    rows=bind.execute(sa.text("SELECT id, evidence FROM findings WHERE evidence_hash = '' OR evidence_hash IS NULL")).mappings().all()
    for row in rows:
        bind.execute(sa.text("UPDATE findings SET evidence_hash = :digest WHERE id = :id"),{"digest":_digest(row["evidence"]),"id":row["id"]})


def downgrade():
    # Hashes are provenance metadata; retaining them is safer than erasing evidence history.
    pass
