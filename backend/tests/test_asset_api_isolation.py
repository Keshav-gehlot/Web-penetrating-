import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.auth import Principal, current_principal
from app.database import Base, get_db
from app.main import app
from app.models import Asset, Finding, Organization, Scan, Workspace


@pytest.fixture
async def api_db():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as db:
        org = Organization(id="org-test", name="Test", slug="test")
        ws_a = Workspace(id="workspace-a", organization_id=org.id, name="A", slug="a")
        ws_b = Workspace(id="workspace-b", organization_id=org.id, name="B", slug="b")
        asset_a = Asset(id="asset-a", host="a.example.com", target="https://a.example.com", workspace_id=ws_a.id)
        asset_b = Asset(id="asset-b", host="b.example.com", target="https://b.example.com", workspace_id=ws_b.id)
        scan_a = Scan(id="scan-a", target=asset_a.target, host=asset_a.host, profile="quick", status="completed", modules=[], workspace_id=ws_a.id, asset_id=asset_a.id)
        scan_b = Scan(id="scan-b", target=asset_b.target, host=asset_b.host, profile="quick", status="completed", modules=[], workspace_id=ws_b.id, asset_id=asset_b.id)
        finding_a = Finding(id="finding-a", scan_id=scan_a.id, module="test", title="A finding", severity="high", evidence={}, evidence_hash="", evidence_source="test")
        finding_b = Finding(id="finding-b", scan_id=scan_b.id, module="test", title="B finding", severity="critical", evidence={}, evidence_hash="", evidence_source="test")
        db.add_all([org, ws_a, ws_b, asset_a, asset_b, scan_a, scan_b, finding_a, finding_b])
        await db.commit()
        yield db
    await engine.dispose()


@pytest.fixture
async def client(api_db):
    principal = Principal(actor="user-a", user_id="user-a", workspace_id="workspace-a", role="owner")
    async def override_db():
        yield api_db
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_principal] = lambda: principal
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        yield http
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_asset_list_is_workspace_isolated(client):
    response = await client.get("/api/v1/assets")
    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == ["asset-a"]


@pytest.mark.asyncio
async def test_asset_detail_cannot_cross_workspace(client):
    response = await client.get("/api/v1/assets/asset-b")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_asset_findings_cannot_cross_workspace(client):
    response = await client.get("/api/v1/assets/asset-b/findings")
    assert response.status_code == 404
    response = await client.get("/api/v1/assets/asset-a/findings")
    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == ["finding-a"]


@pytest.mark.asyncio
async def test_bulk_operation_rejects_cross_workspace_asset_ids(client):
    response = await client.post("/api/v1/assets/bulk", json={"asset_ids": ["asset-a", "asset-b"], "action": "deactivate"})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_asset_update_cannot_cross_workspace(client):
    response = await client.patch("/api/v1/assets/asset-b", json={"notes": "attempted"})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_asset_delete_cannot_cross_workspace(client):
    response = await client.delete("/api/v1/assets/asset-b")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_asset_import_requires_scope(client):
    response = await client.post("/api/v1/assets/import", json={"assets": [{"target": "https://new.example.com"}]})
    assert response.status_code == 409
