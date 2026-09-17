import pytest

from app.api import scans


@pytest.mark.asyncio
async def test_execute_scan_fails_when_module_times_out(monkeypatch):
    published = []

    class ScanState:
        id = "scan-1"
        target = "https://example.com"
        modules = ["test_module"]
        status = "running"
        profile = "standard"
        attempt = 1
        workspace_id = "workspace-1"
        started_at = None
        completed_at = None
        worker_id = "worker-1"
        lease_expires_at = None
        cancel_requested_at = None
        error = None

    class DB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, identifier):
            return ScanState()

        async def commit(self):
            return None

    async def fake_run_module(*args, **kwargs):
        return {"module": "test_module", "status": "timeout", "error": "module budget exceeded", "findings": []}

    async def fake_publish(scan_id, event):
        published.append(event)

    monkeypatch.setattr(scans, "SessionLocal", lambda: DB())
    monkeypatch.setattr(scans, "run_module", fake_run_module)
    monkeypatch.setattr(scans.bus, "publish", fake_publish)

    assert await scans.execute_scan("scan-1", expected_worker="worker-1") is False
    assert any(event.get("event") == "module.failed" for event in published)
    assert any(event.get("event") == "scan.failed" for event in published)
