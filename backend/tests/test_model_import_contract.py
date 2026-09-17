from app.models import FindingNote, OperationalEvent


def test_operational_event_model_imports_without_reserved_metadata_collision():
    assert OperationalEvent.__table__.c.metadata.name == "metadata"
    assert OperationalEvent.db_metadata.key == "db_metadata"


def test_finding_note_model_keeps_analyst_notes_separate_from_evidence():
    columns = set(FindingNote.__table__.c.keys())
    assert {"finding_id", "workspace_id", "author_id", "note"}.issubset(columns)
    assert "evidence" not in columns
