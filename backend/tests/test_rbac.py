from app.rbac import ALL_PERMISSIONS, PERMISSIONS, ROLE_LEVEL, Role, can_assign_role, role_permissions


def test_all_roles_have_permission_sets():
    assert set(PERMISSIONS) == set(Role)
    assert Role.OWNER in PERMISSIONS
    assert "scan:create" in role_permissions(Role.ANALYST.value)
    assert "users:manage" not in role_permissions(Role.ANALYST.value)


def test_owner_has_every_defined_permission():
    assert role_permissions(Role.OWNER.value) == set(ALL_PERMISSIONS)


def test_role_assignment_blocks_vertical_escalation():
    assert can_assign_role("owner", "owner")
    assert can_assign_role("admin", "admin")
    assert can_assign_role("admin", "viewer")
    assert can_assign_role("security_lead", "analyst")
    assert not can_assign_role("admin", "owner")
    assert not can_assign_role("analyst", "admin")
    assert not can_assign_role("viewer", "developer")
    assert not can_assign_role("unknown", "viewer")


def test_role_levels_are_strictly_ordered():
    assert ROLE_LEVEL[Role.OWNER] > ROLE_LEVEL[Role.ADMIN]
    assert ROLE_LEVEL[Role.ADMIN] > ROLE_LEVEL[Role.SECURITY_LEAD]
    assert ROLE_LEVEL[Role.SECURITY_LEAD] > ROLE_LEVEL[Role.ANALYST]
    assert ROLE_LEVEL[Role.ANALYST] > ROLE_LEVEL[Role.DEVELOPER]
    assert ROLE_LEVEL[Role.DEVELOPER] > ROLE_LEVEL[Role.VIEWER]
