import pytest
from app.scanners import modules

@pytest.mark.asyncio
async def test_authenticated_endpoint_inventory_is_registered():
    assert "authenticated_endpoint_inventory" in modules.MODULES
    result = await modules.authenticated_endpoint_inventory
    assert callable(result)
