from __future__ import annotations

import unittest

from trading_lab.windows_acl import (
    ADMINISTRATORS_SID,
    APPEND_ONLY_RIGHTS,
    FULL_CONTROL_RIGHTS,
    MODIFY_RIGHTS,
    READ_EXECUTE_RIGHTS,
    READ_RIGHTS,
    SYSTEM_SID,
    evaluate_acl_snapshot,
)


GATEWAY = "S-1-5-21-1-2-3-1001"
AGENT = "S-1-5-21-1-2-3-1002"


def rule(sid: str, rights: int, access_type: str = "Allow") -> dict[str, object]:
    return {"sid": sid, "type": access_type, "rights": rights, "inherited": False}


def target(
    path: str, role: str, principal: str, rights: int, *, is_directory: bool = True
) -> dict[str, object]:
    return {
        "path": path,
        "role": role,
        "is_directory": is_directory,
        "require_protected": True,
        "exists": True,
        "protected": True,
        "reparse": False,
        "owner_sid": ADMINISTRATORS_SID,
        "rules": [
            rule(SYSTEM_SID, FULL_CONTROL_RIGHTS),
            rule(ADMINISTRATORS_SID, FULL_CONTROL_RIGHTS),
            rule(principal, rights),
        ],
    }


def shared_target(path: str, role: str, rights: int, *, is_directory: bool) -> dict[str, object]:
    item = target(path, role, GATEWAY, rights, is_directory=is_directory)
    item["rules"].append(rule(AGENT, rights))  # type: ignore[union-attr]
    return item


def safe_snapshot() -> dict[str, object]:
    return {
        "gateway_sid": GATEWAY,
        "automaton_sid": AGENT,
        "current_sid": GATEWAY,
        "administrator_member_sids": [],
        "targets": [
            target("C:/control", "gateway_navigation", GATEWAY, READ_EXECUTE_RIGHTS),
            target("C:/control/trading.yaml", "control_file", GATEWAY, READ_RIGHTS, is_directory=False),
            target("C:/operational", "gateway_modify", GATEWAY, MODIFY_RIGHTS),
            target("C:/agent", "automaton_state", AGENT, MODIFY_RIGHTS),
            shared_target("C:/ipc", "shared_navigation", READ_EXECUTE_RIGHTS, is_directory=True),
            shared_target("C:/ipc/automaton.key", "ipc_file", READ_RIGHTS, is_directory=False),
            target("C:/audit/journal", "append_directory", GATEWAY, READ_EXECUTE_RIGHTS),
            target("C:/audit/journal/audit.jsonl", "append_file", GATEWAY, APPEND_ONLY_RIGHTS, is_directory=False),
        ],
    }


class WindowsAclTests(unittest.TestCase):
    def test_accepts_separated_least_privilege_domains(self) -> None:
        result = evaluate_acl_snapshot(safe_snapshot(), require_current_gateway=True)
        self.assertTrue(result.passed, result.detail)

    def test_rejects_agent_access_to_gateway_domain(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][2]["rules"].append(rule(AGENT, READ_RIGHTS))  # type: ignore[index,union-attr]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)

    def test_rejects_gateway_write_or_execute_access_to_control_file(self) -> None:
        for unsafe in (MODIFY_RIGHTS, READ_RIGHTS | 32):
            snapshot = safe_snapshot()
            snapshot["targets"][1]["rules"][2] = rule(GATEWAY, unsafe)  # type: ignore[index]
            self.assertFalse(evaluate_acl_snapshot(snapshot).passed)

    def test_rejects_ipc_key_write_delete_or_execute(self) -> None:
        for unsafe in (MODIFY_RIGHTS, READ_RIGHTS | 32, READ_RIGHTS | 65536):
            snapshot = safe_snapshot()
            snapshot["targets"][5]["rules"][2] = rule(GATEWAY, unsafe)  # type: ignore[index]
            self.assertFalse(evaluate_acl_snapshot(snapshot).passed)

    def test_append_file_allows_append_but_rejects_overwrite_delete_and_modify(self) -> None:
        self.assertTrue(evaluate_acl_snapshot(safe_snapshot()).passed)
        for unsafe in (APPEND_ONLY_RIGHTS | 2, APPEND_ONLY_RIGHTS | 65536, MODIFY_RIGHTS):
            snapshot = safe_snapshot()
            snapshot["targets"][7]["rules"][2] = rule(GATEWAY, unsafe)  # type: ignore[index]
            self.assertFalse(evaluate_acl_snapshot(snapshot).passed)

    def test_rejects_deny_inherited_unexpected_and_missing_admin_recovery_aces(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][0]["rules"].append(rule(GATEWAY, 1, "Deny"))  # type: ignore[index,union-attr]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][0]["rules"][2]["inherited"] = True  # type: ignore[index]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][0]["rules"].append(rule("S-1-5-11", READ_RIGHTS))  # type: ignore[index,union-attr]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][0]["rules"][0] = rule(SYSTEM_SID, READ_RIGHTS)  # type: ignore[index]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)

    def test_requires_administrators_owner_and_dedicated_non_admin_runtime(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][0]["owner_sid"] = GATEWAY  # type: ignore[index]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["administrator_member_sids"] = [GATEWAY]
        self.assertFalse(evaluate_acl_snapshot(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["current_sid"] = AGENT
        self.assertFalse(evaluate_acl_snapshot(snapshot, require_current_gateway=True).passed)


if __name__ == "__main__":
    unittest.main()
