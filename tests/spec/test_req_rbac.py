"""RBAC — REQ-API-008, REQ-EVT-007 (2 tests)."""
import pytest


REQUIRED_PERMISSIONS = (
    "quarantine:approve",
    "quarantine:dismiss",
    "quarantine:release",
    "sourceblock:release",
    "sourceblock:exempt",
    "policy:publish",
    "policy:acknowledge",
    "device:rebaseline",
    "suppression:create",
)


class TestRBAC:
    @pytest.mark.skip(reason="REQ-API-008")
    @pytest.mark.parametrize("permission", REQUIRED_PERMISSIONS)
    def test_required_permission_enforced(self, permission):
        """REQ-API-008: RBAC MUST enforce nine minimum permissions."""
        ...

    @pytest.mark.skip(reason="REQ-EVT-007")
    def test_privileged_action_records_five_audit_fields(self):
        """REQ-EVT-007: actor/timestamp/triggering event/reason/revision."""
        ...
