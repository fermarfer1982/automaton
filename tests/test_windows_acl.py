from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from trading_lab.windows_acl import (
    ADMINISTRATORS_SID,
    APPEND_ONLY_RIGHTS,
    FULL_CONTROL_RIGHTS,
    MODIFY_RIGHTS,
    READ_EXECUTE_RIGHTS,
    READ_RIGHTS,
    SYSTEM_SID,
    MaintenanceAccessPolicy,
    WindowsAclPolicy,
    evaluate_acl_snapshot,
    load_windows_acl_policy,
)


GATEWAY = "S-1-5-21-1-2-3-1001"
AGENT = "S-1-5-21-1-2-3-1002"
MAINTENANCE = "S-1-5-21-1-2-3-1003"
SECOND_HUMAN = "S-1-5-21-1-2-3-1004"
MAINTENANCE_IDENTITY = "LABHOST\\LabMaintainer"
INHERITANCE = "ContainerInherit, ObjectInherit"


def policy(*allowed_keys: str) -> WindowsAclPolicy:
    return WindowsAclPolicy(
        maintenance_identity=MAINTENANCE_IDENTITY,
        maintenance_targets={
            key: MaintenanceAccessPolicy(
                rights=FULL_CONTROL_RIGHTS,
                inheritance_flags=frozenset({"ContainerInherit", "ObjectInherit"}),
                propagation_flags=frozenset(),
            )
            for key in allowed_keys
        },
    )


SAFE_POLICY = policy("lab_root", "operational", "automaton_state")


def rule(
    sid: str,
    rights: int,
    access_type: str = "Allow",
    *,
    inherited: bool = False,
    inheritance_flags: str = "None",
    propagation_flags: str = "None",
) -> dict[str, object]:
    return {
        "sid": sid,
        "type": access_type,
        "rights": rights,
        "inherited": inherited,
        "inheritance_flags": inheritance_flags,
        "propagation_flags": propagation_flags,
    }


def target(
    path: str,
    policy_key: str,
    role: str,
    principal: str,
    rights: int,
    *,
    is_directory: bool = True,
    maintenance: bool = False,
) -> dict[str, object]:
    rules = [
        rule(SYSTEM_SID, FULL_CONTROL_RIGHTS),
        rule(ADMINISTRATORS_SID, FULL_CONTROL_RIGHTS),
        rule(principal, rights),
    ]
    if maintenance:
        rules.append(
            rule(
                MAINTENANCE,
                FULL_CONTROL_RIGHTS,
                inheritance_flags=INHERITANCE,
            )
        )
    return {
        "path": path,
        "policy_key": policy_key,
        "role": role,
        "is_directory": is_directory,
        "require_protected": True,
        "exists": True,
        "protected": True,
        "reparse": False,
        "owner_sid": ADMINISTRATORS_SID,
        "rules": rules,
    }


def shared_target(
    path: str,
    policy_key: str,
    role: str,
    rights: int,
    *,
    is_directory: bool,
    maintenance: bool = False,
) -> dict[str, object]:
    item = target(
        path,
        policy_key,
        role,
        GATEWAY,
        rights,
        is_directory=is_directory,
        maintenance=maintenance,
    )
    item["rules"].append(rule(AGENT, rights))  # type: ignore[union-attr]
    return item


def safe_snapshot() -> dict[str, object]:
    return {
        "gateway_sid": GATEWAY,
        "automaton_sid": AGENT,
        "maintenance_identity": MAINTENANCE_IDENTITY,
        "maintenance_sid": MAINTENANCE,
        "maintenance_local_user": True,
        "maintenance_enabled": True,
        "current_sid": GATEWAY,
        "administrator_member_sids": [MAINTENANCE],
        "targets": [
            shared_target(
                "C:/ProgramData/AutomatonMT5Lab",
                "lab_root",
                "shared_navigation",
                READ_EXECUTE_RIGHTS,
                is_directory=True,
                maintenance=True,
            ),
            target(
                "C:/control",
                "control_directory",
                "gateway_navigation",
                GATEWAY,
                READ_EXECUTE_RIGHTS,
            ),
            target(
                "C:/control/trading.yaml",
                "control_config",
                "control_file",
                GATEWAY,
                READ_RIGHTS,
                is_directory=False,
            ),
            target(
                "C:/operational",
                "operational",
                "gateway_modify",
                GATEWAY,
                MODIFY_RIGHTS,
                maintenance=True,
            ),
            target(
                "C:/agent",
                "automaton_state",
                "automaton_state",
                AGENT,
                MODIFY_RIGHTS,
                maintenance=True,
            ),
            shared_target(
                "C:/ipc",
                "ipc_directory",
                "shared_navigation",
                READ_EXECUTE_RIGHTS,
                is_directory=True,
            ),
            shared_target(
                "C:/ipc/automaton.key",
                "ipc_key",
                "ipc_file",
                READ_RIGHTS,
                is_directory=False,
            ),
            target(
                "C:/audit/journal",
                "audit_journal",
                "append_directory",
                GATEWAY,
                READ_EXECUTE_RIGHTS,
            ),
            target(
                "C:/audit/journal/audit.jsonl",
                "audit_journal_file",
                "append_file",
                GATEWAY,
                APPEND_ONLY_RIGHTS,
                is_directory=False,
            ),
        ],
    }


def verify(snapshot: dict[str, object], acl_policy: WindowsAclPolicy = SAFE_POLICY):
    return evaluate_acl_snapshot(snapshot, maintenance_policy=acl_policy)


class WindowsAclTests(unittest.TestCase):
    def test_accepts_separated_least_privilege_domains(self) -> None:
        result = evaluate_acl_snapshot(
            safe_snapshot(),
            maintenance_policy=SAFE_POLICY,
            require_current_gateway=True,
        )
        self.assertTrue(result.passed, result.detail)
        self.assertEqual(MAINTENANCE, result.maintenance_sid)

    def test_real_root_shape_with_exact_maintenance_full_control_passes(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"] = [snapshot["targets"][0]]  # type: ignore[index]
        self.assertTrue(verify(snapshot).passed)

    def test_required_maintenance_ace_is_fail_closed(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][0]["rules"] = snapshot["targets"][0]["rules"][:-1]  # type: ignore[index]
        self.assertFalse(verify(snapshot).passed)

    def test_wrong_or_additional_human_sid_is_rejected(self) -> None:
        for extra_sid in (SECOND_HUMAN, "S-1-5-11"):
            snapshot = safe_snapshot()
            snapshot["targets"][0]["rules"].append(  # type: ignore[index,union-attr]
                rule(extra_sid, FULL_CONTROL_RIGHTS, inheritance_flags=INHERITANCE)
            )
            self.assertFalse(verify(snapshot).passed)

    def test_maintenance_cannot_alias_runtime_or_builtin_principals(self) -> None:
        for unsafe_sid in (GATEWAY, AGENT, SYSTEM_SID, ADMINISTRATORS_SID):
            snapshot = safe_snapshot()
            snapshot["maintenance_sid"] = unsafe_sid
            snapshot["administrator_member_sids"] = [unsafe_sid]
            self.assertFalse(verify(snapshot).passed)

    def test_maintenance_must_be_enabled_local_direct_administrator(self) -> None:
        for field in ("maintenance_local_user", "maintenance_enabled"):
            snapshot = safe_snapshot()
            snapshot[field] = False
            self.assertFalse(verify(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["administrator_member_sids"] = []
        self.assertFalse(verify(snapshot).passed)

    def test_maintenance_rights_and_inheritance_are_exact(self) -> None:
        for property_name, unsafe_value in (
            ("rights", MODIFY_RIGHTS),
            ("inheritance_flags", "None"),
            ("propagation_flags", "InheritOnly"),
        ):
            snapshot = safe_snapshot()
            snapshot["targets"][0]["rules"][3][property_name] = unsafe_value  # type: ignore[index]
            self.assertFalse(verify(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][0]["rules"][3]["inherited"] = True  # type: ignore[index]
        self.assertFalse(verify(snapshot).passed)

    def test_maintenance_is_allowed_only_on_explicit_target_keys(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][1]["rules"].append(  # type: ignore[index,union-attr]
            rule(MAINTENANCE, FULL_CONTROL_RIGHTS, inheritance_flags=INHERITANCE)
        )
        self.assertFalse(verify(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][3]["rules"] = snapshot["targets"][3]["rules"][:-1]  # type: ignore[index]
        self.assertFalse(verify(snapshot).passed)

    def test_gateway_and_agent_mutation_on_root_are_rejected(self) -> None:
        for principal_index in (2, 4):
            snapshot = safe_snapshot()
            snapshot["targets"][0]["rules"][principal_index]["rights"] = MODIFY_RIGHTS  # type: ignore[index]
            self.assertFalse(verify(snapshot).passed)

    def test_rejects_agent_access_to_gateway_domain(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][3]["rules"].append(rule(AGENT, READ_RIGHTS))  # type: ignore[index,union-attr]
        self.assertFalse(verify(snapshot).passed)

    def test_rejects_gateway_write_or_execute_access_to_control_file(self) -> None:
        for unsafe in (MODIFY_RIGHTS, READ_RIGHTS | 32):
            snapshot = safe_snapshot()
            snapshot["targets"][2]["rules"][2] = rule(GATEWAY, unsafe)  # type: ignore[index]
            self.assertFalse(verify(snapshot).passed)

    def test_mt5_read_only_authorization_file_is_exact_read_only_and_agent_denied(self) -> None:
        authorization = target(
            "C:/control/demo-authorization/mt5-read-only-authorization-id.json",
            "control_mt5_read_only_authorization_file",
            "control_file",
            GATEWAY,
            READ_RIGHTS,
            is_directory=False,
        )
        snapshot = safe_snapshot()
        snapshot["targets"].append(authorization)  # type: ignore[union-attr]
        self.assertTrue(verify(snapshot).passed)

        writable = copy.deepcopy(snapshot)
        writable["targets"][-1]["rules"][2] = rule(GATEWAY, MODIFY_RIGHTS)  # type: ignore[index]
        self.assertFalse(verify(writable).passed)

        agent_readable = copy.deepcopy(snapshot)
        agent_readable["targets"][-1]["rules"].append(rule(AGENT, READ_RIGHTS))  # type: ignore[index,union-attr]
        self.assertFalse(verify(agent_readable).passed)

        reparse = copy.deepcopy(snapshot)
        reparse["targets"][-1]["reparse"] = True  # type: ignore[index]
        self.assertFalse(verify(reparse).passed)

    def test_rejects_ipc_key_write_delete_or_execute(self) -> None:
        for unsafe in (MODIFY_RIGHTS, READ_RIGHTS | 32, READ_RIGHTS | 65536):
            snapshot = safe_snapshot()
            snapshot["targets"][6]["rules"][2] = rule(GATEWAY, unsafe)  # type: ignore[index]
            self.assertFalse(verify(snapshot).passed)

    def test_append_file_allows_append_but_rejects_overwrite_delete_and_modify(self) -> None:
        self.assertTrue(verify(safe_snapshot()).passed)
        for unsafe in (APPEND_ONLY_RIGHTS | 2, APPEND_ONLY_RIGHTS | 65536, MODIFY_RIGHTS):
            snapshot = safe_snapshot()
            snapshot["targets"][8]["rules"][2] = rule(GATEWAY, unsafe)  # type: ignore[index]
            self.assertFalse(verify(snapshot).passed)

    def test_rejects_deny_inherited_unexpected_and_missing_admin_recovery_aces(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][1]["rules"].append(rule(GATEWAY, 1, "Deny"))  # type: ignore[index,union-attr]
        self.assertFalse(verify(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][1]["rules"][2]["inherited"] = True  # type: ignore[index]
        self.assertFalse(verify(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][1]["rules"].append(rule("S-1-5-11", READ_RIGHTS))  # type: ignore[index,union-attr]
        self.assertFalse(verify(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["targets"][1]["rules"][0] = rule(SYSTEM_SID, READ_RIGHTS)  # type: ignore[index]
        self.assertFalse(verify(snapshot).passed)

    def test_requires_administrators_owner_and_dedicated_non_admin_runtime(self) -> None:
        snapshot = safe_snapshot()
        snapshot["targets"][0]["owner_sid"] = GATEWAY  # type: ignore[index]
        self.assertFalse(verify(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["administrator_member_sids"] = [MAINTENANCE, GATEWAY]
        self.assertFalse(verify(snapshot).passed)
        snapshot = safe_snapshot()
        snapshot["current_sid"] = AGENT
        self.assertFalse(
            evaluate_acl_snapshot(
                snapshot,
                maintenance_policy=SAFE_POLICY,
                require_current_gateway=True,
            ).passed
        )

    def test_policy_loader_rejects_sid_unknown_targets_and_nonexact_rights(self) -> None:
        valid = {
            "schema_version": 1,
            "maintenance_identity": MAINTENANCE_IDENTITY,
            "maintenance_targets": {
                key: {
                    "rights": "FullControl",
                    "inheritance_flags": ["ContainerInherit", "ObjectInherit"],
                    "propagation_flags": [],
                }
                for key in (
                    "automaton_state",
                    "gateway_logs",
                    "lab_root",
                    "logs_root",
                    "operational",
                    "security_logs",
                )
            },
        }
        cases = []
        sid_identity = copy.deepcopy(valid)
        sid_identity["maintenance_identity"] = MAINTENANCE
        cases.append(sid_identity)
        missing_target = copy.deepcopy(valid)
        del missing_target["maintenance_targets"]["lab_root"]
        cases.append(missing_target)
        weak_rights = copy.deepcopy(valid)
        weak_rights["maintenance_targets"]["lab_root"]["rights"] = "Modify"
        cases.append(weak_rights)
        for payload in cases:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "policy.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_windows_acl_policy(path)


if __name__ == "__main__":
    unittest.main()
