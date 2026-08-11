from __future__ import annotations

import unittest

from trading_lab.windows_acl import (
    ADMINISTRATORS_SID,
    MODIFY_RIGHTS,
    READ_RIGHTS,
    SYSTEM_SID,
    evaluate_acl_snapshot,
)


GATEWAY = "S-1-5-21-1-2-3-1001"
AGENT = "S-1-5-21-1-2-3-1002"


def rule(sid: str, rights: int, access_type: str = "Allow") -> dict[str, object]:
    return {"sid": sid, "type": access_type, "rights": rights, "inherited": False}


def target(path: str, role: str, principal: str, rights: int) -> dict[str, object]:
    return {
        "path": path,
        "role": role,
        "is_directory": True,
        "exists": True,
        "protected": True,
        "owner_sid": ADMINISTRATORS_SID,
        "rules": [
            rule(SYSTEM_SID, 2032127),
            rule(ADMINISTRATORS_SID, 2032127),
            rule(principal, rights),
        ],
    }


def safe_snapshot() -> dict[str, object]:
    return {
        "gateway_sid": GATEWAY,
        "automaton_sid": AGENT,
        "current_sid": GATEWAY,
        "administrator_member_sids": [],
        "targets": [
            target("C:/control", "gateway_control", GATEWAY, READ_RIGHTS),
            target("C:/data", "gateway_data", GATEWAY, MODIFY_RIGHTS),
            target("C:/agent", "automaton_state", AGENT, MODIFY_RIGHTS),
        ],
    }


def workspace_target() -> dict[str, object]:
    item = target("C:/automaton", "workspace_code", GATEWAY, READ_RIGHTS)
    item["rules"].append(rule(AGENT, READ_RIGHTS))  # type: ignore[union-attr]
    return item


class WindowsAclTests(unittest.TestCase):
    def test_accepts_strict_three_way_separation(self) -> None:
        result = evaluate_acl_snapshot(safe_snapshot(), require_current_gateway=True)
        self.assertTrue(result.passed, result.detail)

    def test_rejects_agent_access_to_gateway_data(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][1]["rules"].append(rule(AGENT, READ_RIGHTS))  # type: ignore[index,union-attr]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)

    def test_rejects_gateway_write_access_to_control(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][0]["rules"][2] = rule(GATEWAY, MODIFY_RIGHTS)  # type: ignore[index]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)

    def test_rejects_inherited_directory_or_wrong_runtime_identity(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][0]["protected"] = False  # type: ignore[index]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["current_sid"] = AGENT
        self.assertFalse(
            evaluate_acl_snapshot(snapshot, require_current_gateway=True).passed
        )

    def test_rejects_administrator_membership_and_gateway_owned_control(self) -> None:
        snapshot = safe_snapshot()
        snapshot["administrator_member_sids"] = [GATEWAY]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][0]["owner_sid"] = GATEWAY  # type: ignore[index]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)

    def test_workspace_requires_both_identities_read_only(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"].append(workspace_target())  # type: ignore[union-attr]
        self.assertTrue(evaluate_acl_snapshot(snapshot).passed)
        snapshot["targets"][-1]["rules"][-1] = rule(AGENT, MODIFY_RIGHTS)  # type: ignore[index]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)


if __name__ == "__main__":
    unittest.main()
