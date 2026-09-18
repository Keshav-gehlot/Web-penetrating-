from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import audit, scans, scope
from app.auth import Principal
from app.scanners import runtime
from app.scanners.runner import run_module


def policy(*, enabled=True, targets=None, ports=None, paths=None):
    return {
        "id": "scope-1",
        "enabled": enabled,
        "authorization_acknowledged": enabled,
        "authorized_targets": targets or ["example.com"],
        "excluded_targets": [],
        "allowed_ports": ports or [443],
        "allowed_paths": paths or ["/"],
        "blocked_paths": [],
        "max_requests": 25,
        "max_concurrency": 1,
        "max_redirects": 2,
    }


def test_scope_change_cancels_queued_and_running_scans():
    now = SimpleNamespace()
    queued = SimpleNamespace(id="queued-1", status="queued")
    running = SimpleNamespace(id="running-1", status="running")
    completed = SimpleNamespace(id="completed-1", status="completed")

    cancelled = scope._cancel_scans_for_scope_change([queued, running, completed], now)

    assert cancelled == ["queued-1", "running-1"]
    for scan in (queued, running):
        assert scan.status == "cancelled"
        assert scan.cancel_requested_at is now
        assert scan.cancelled_at is now
        assert scan.completed_at is now
        assert scan.worker_id is None
        assert scan.lease_expires_at is None
        assert "scope policy changed" in scan.error
    assert completed.status == "completed"


@pytest.mark.asyncio
async def test_scheduled_scope_block_audit_keeps_workspace_context():
    events = []

    class FakeDB:
        def add(self, event):
            events.append(event)

        async def flush(self):
            return None

    await audit.record_audit(
        FakeDB(),
        None,
        "schedule.scope_blocked",
        "schedule",
        "schedule-1",
        {"reason": "target outside scope"},
        workspace_id="workspace-1",
    )

    assert events[0].workspace_id == "workspace-1"
    assert events[0].actor == "system"
    assert events[0].action == "schedule.scope_blocked"


@pytest.mark.asyncio
async def test_create_scan_rejects_target_outside_workspace_scope(monkeypatch):
    principal = Principal("analyst@example.com", "analyst", "workspace-1", "user-1")
    monkeypatch.setattr(scans, "_load_scope", lambda db, workspace_id: policy())
    monkeypatch.setattr(scans, "enqueue_scan", lambda scan_id: _done())
    monkeypatch.setattr(scans, "record_audit", lambda *args, **kwargs: _done())
    monkeypatch.setattr(scans, "_op", lambda *args, **kwargs: _done())
    monkeypatch.setattr(scans.bus, "publish", lambda *args, **kwargs: _done())

    with pytest.raises(HTTPException) as exc:
        await scans.create_scan(
            scans.ScanRequest(target="https://outside.example", profile="standard"),
            None,
            principal,
            SimpleNamespace(),
        )

    assert exc.value.status_code == 403
    assert "outside" in str(exc.value.detail).lower()


@pytest.mark.asyncio
async def test_create_scan_rejects_when_scope_is_disabled(monkeypatch):
    principal = Principal("analyst@example.com", "analyst", "workspace-1", "user-1")
    monkeypatch.setattr(scans, "_load_scope", lambda db, workspace_id: policy(enabled=False))

    with pytest.raises(HTTPException) as exc:
        await scans.create_scan(
            scans.ScanRequest(target="https://example.com", profile="standard"),
            None,
            principal,
            SimpleNamespace(),
        )

    assert exc.value.status_code == 403
    assert "disabled" in str(exc.value.detail).lower()


@pytest.mark.asyncio
async def test_create_scan_allows_only_an_authorized_target(monkeypatch):
    principal = Principal("analyst@example.com", "analyst", "workspace-1", "user-1")
    enqueued = []

    class FakeDB:
        def add(self, obj):
            self.obj = obj

        async def scalar(self, query):
            return None

        async def flush(self):
            return None

        async def commit(self):
            return None

        async def refresh(self, obj):
            return None

    async def enqueue(scan_id):
        enqueued.append(scan_id)

    async def no_op(*args, **kwargs):
        return None

    monkeypatch.setattr(scans, "_load_scope", lambda db, workspace_id: policy())
    monkeypatch.setattr(scans, "enqueue_scan", enqueue)
    monkeypatch.setattr(scans, "record_audit", no_op)
    monkeypatch.setattr(scans, "_op", no_op)
    monkeypatch.setattr(scans.bus, "publish", no_op)

    result = await scans.create_scan(
        scans.ScanRequest(target="https://example.com", profile="standard"),
        None,
        principal,
        FakeDB(),
    )

    assert result["status"] == "queued"
    assert len(enqueued) == 1


@pytest.mark.asyncio
async def test_scanner_modules_refuse_out_of_scope_network_requests():
    scope_policy = policy()
    runtime.ensure_runtime("scope-test", scope=scope_policy)

    result = await run_module(
        "security_txt",
        "https://outside.example",
        runtime_id="scope-test",
        scope=scope_policy,
    )

    assert result["status"] == "error"
    assert "outside" in result["error"].lower()


@pytest.mark.asyncio
async def test_trust_audit_uses_the_same_scope_guard():
    scope_policy = policy()
    runtime.ensure_runtime("trust-scope-test", scope=scope_policy)

    result = await run_module(
        "web_trust_audit",
        "https://outside.example",
        runtime_id="trust-scope-test",
        scope=scope_policy,
    )

    assert result["status"] == "error"
    assert "outside" in result["error"].lower()


def test_scope_runtime_rejects_disallowed_port_and_path():
    scope_policy = policy(ports=[443], paths=["/api"])
    runtime.ensure_runtime("runtime-policy-test", scope=scope_policy)

    with pytest.raises(RuntimeError, match="port"):
        runtime._assert_scope_url("https://example.com:8443/api")

    with pytest.raises(RuntimeError, match="path"):
        runtime._assert_scope_url("https://example.com/admin")


async def _done():
    return None
