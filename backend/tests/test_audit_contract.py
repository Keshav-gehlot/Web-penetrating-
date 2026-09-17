import pytest

from app.api.audit import record_audit
from app.auth import Principal


class FakeDB:
    def __init__(self):
        self.events = []

    def add(self, event):
        self.events.append(event)

    async def flush(self):
        return None


@pytest.mark.asyncio
async def test_record_audit_uses_authenticated_principal():
    db = FakeDB()
    principal = Principal(actor="analyst@example.test", role="analyst", workspace_id="workspace-a", user_id="user-a")
    event = await record_audit(db, None, "finding.updated", "finding", "finding-1", {"status": ["open", "triaged"]}, principal)
    assert event.actor == "analyst@example.test"
    assert event.workspace_id == "workspace-a"
    assert event.resource_id == "finding-1"
    assert event.metadata_json["status"] == ["open", "triaged"]


@pytest.mark.asyncio
async def test_system_audit_event_is_explicitly_system_owned():
    db = FakeDB()
    event = await record_audit(db, None, "scan.started", "scan", "scan-1", None, None)
    assert event.actor == "system"
    assert event.workspace_id is None
