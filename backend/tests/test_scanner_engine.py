import pytest

from app.scanners import modules
from app.scanners.runner import run_module


def test_finding_confidence_is_normalized():
    finding = modules.finding("test", "x", confidence=4)
    assert finding["confidence"] == 1.0
    assert finding["provenance"]["method"] == "passive_or_safe_probe"


@pytest.mark.asyncio
async def test_http_methods_uses_allow_from_safe_options(monkeypatch):
    class Response:
        status_code = 200
        headers = {"allow": "GET, HEAD"}

    async def snapshot(_):
        return Response()

    async def options(_):
        return Response()

    monkeypatch.setattr(modules, "http_snapshot", snapshot)
    monkeypatch.setattr(modules, "bounded_options", options)
    result = await modules.http_methods("https://example.com")
    assert result["methods"] == ["GET", "HEAD"]


@pytest.mark.asyncio
async def test_runner_attaches_metrics_and_evidence(monkeypatch):
    async def module(_):
        return {
            "module": "demo",
            "findings": [modules.finding("demo", "candidate", evidence={"path": "/admin"})],
        }

    monkeypatch.setitem(modules.MODULES, "demo", module)
    result = await run_module("demo", "https://example.com")
    assert result["metrics"]["finding_count"] == 1
    assert result["metrics"]["requests"] == 0
    assert result["findings"][0]["evidence"]["schema_version"] == "1.0"
    assert result["findings"][0]["evidence"]["target"] == "https://example.com"


def test_discovery_modules_have_safe_scope_wrappers():
    assert callable(modules.MODULES["dns_recon"])
    assert callable(modules.MODULES["http_methods"])
    assert callable(modules.MODULES["redirect_inventory"])
