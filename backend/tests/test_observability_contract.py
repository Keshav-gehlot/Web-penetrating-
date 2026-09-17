import pytest

from app import observability


def test_metadata_is_bounded_and_primitive():
    result = observability._sanitize_metadata({"text": "x" * 5000, "nested": {"secret": "value"}})
    assert len(result["text"]) == observability._MAX_METADATA_VALUE_LENGTH
    assert len(result["nested"]) <= observability._MAX_METADATA_VALUE_LENGTH


def test_metadata_key_count_is_bounded():
    result = observability._sanitize_metadata({str(i): i for i in range(100)})
    assert len(result) == observability._MAX_METADATA_KEYS


@pytest.mark.asyncio
async def test_operational_event_failure_is_non_fatal(monkeypatch):
    class BrokenSession:
        async def __aenter__(self):
            raise RuntimeError("database unavailable")

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(observability, "SessionLocal", lambda: BrokenSession())
    await observability.record_operational_event("worker.error", "test", "error")
