from app.scanners import modules

def test_authenticated_endpoint_inventory_is_registered():
    assert "authenticated_endpoint_inventory" in modules.MODULES
    assert callable(modules.MODULES["authenticated_endpoint_inventory"])
    assert "authorization_surface" in modules.MODULES
    assert callable(modules.MODULES["authorization_surface"])
