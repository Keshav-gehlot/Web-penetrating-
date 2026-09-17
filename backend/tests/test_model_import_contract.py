from app.models import OperationalEvent


def test_operational_event_model_imports_without_reserved_metadata_collision():
    assert OperationalEvent.__table__.c.metadata.name == "metadata"
    assert OperationalEvent.db_metadata.key == "db_metadata"
