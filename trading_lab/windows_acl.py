from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .config import GatewayBootstrapConfig, SecurityConfig


SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
SYNCHRONIZE_RIGHT = 1048576
READ_RIGHTS = 131209 | SYNCHRONIZE_RIGHT
READ_EXECUTE_RIGHTS = 131241 | SYNCHRONIZE_RIGHT
MODIFY_RIGHTS = 197055 | SYNCHRONIZE_RIGHT
FULL_CONTROL_RIGHTS = 2032127
APPEND_DATA_RIGHT = 4
EXECUTE_RIGHT = 32
APPEND_ONLY_RIGHTS = READ_RIGHTS | APPEND_DATA_RIGHT
WRITE_OR_SECURITY_RIGHTS = 2 | 4 | 16 | 64 | 256 | 65536 | 262144 | 524288
APPEND_FORBIDDEN_RIGHTS = WRITE_OR_SECURITY_RIGHTS & ~APPEND_DATA_RIGHT
ACL_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "windows-acl-policy.json"
MAINTENANCE_TARGET_KEYS = frozenset({
    "automaton_state",
    "gateway_logs",
    "lab_root",
    "logs_root",
    "operational",
    "security_logs",
})
KNOWN_TARGET_KEYS = frozenset({
    "audit_journal",
    "audit_journal_file",
    "audit_navigation",
    "audit_sqlite",
    "automaton_state",
    "control_config",
    "control_demo_authorization",
    "control_directory",
    "control_kill_switch",
    "control_mt5_read_only_authorization_file",
    "gateway_logs",
    "ipc_directory",
    "ipc_key",
    "lab_root",
    "logs_root",
    "operational",
    "research",
    "security_log_file",
    "security_logs",
    "workspace_code",
})

MT5_READ_ONLY_AUTHORIZATION_NAME = re.compile(
    r"mt5-read-only-authorization-[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json"
)


def discover_mt5_read_only_authorizations(root: str | Path) -> tuple[Path, ...]:
    authorization_root = Path(os.path.abspath(root))
    discovered: list[Path] = []
    try:
        with os.scandir(authorization_root) as entries:
            for entry in entries:
                if not MT5_READ_ONLY_AUTHORIZATION_NAME.fullmatch(entry.name):
                    raise ValueError(f"unexpected authorization artifact name: {entry.name}")
                entry_stat = entry.stat(follow_symlinks=False)
                reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if (
                    entry.is_symlink()
                    or not entry.is_file(follow_symlinks=False)
                    or getattr(entry_stat, "st_file_attributes", 0) & reparse_flag
                ):
                    raise ValueError(f"authorization artifact is not a regular non-reparse file: {entry.name}")
                discovered.append(authorization_root / entry.name)
    except OSError as exc:
        raise ValueError("Cannot enumerate the protected authorization directory") from exc
    return tuple(discovered)


@dataclass(frozen=True)
class MaintenanceAccessPolicy:
    rights: int
    inheritance_flags: frozenset[str]
    propagation_flags: frozenset[str]


@dataclass(frozen=True)
class WindowsAclPolicy:
    maintenance_identity: str
    maintenance_targets: Mapping[str, MaintenanceAccessPolicy]


@dataclass(frozen=True)
class AclVerification:
    passed: bool
    detail: str
    gateway_sid: str | None = None
    automaton_sid: str | None = None
    current_sid: str | None = None
    maintenance_sid: str | None = None


def load_windows_acl_policy(path: str | Path = ACL_POLICY_PATH) -> WindowsAclPolicy:
    policy_path = Path(path)
    if not policy_path.is_absolute() or not policy_path.is_file():
        raise ValueError("Windows ACL policy must be an existing absolute file")
    if policy_path.is_symlink() or policy_path.stat().st_size > 32_768:
        raise ValueError("Windows ACL policy path is unsafe")
    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version", "maintenance_identity", "maintenance_targets"
    }:
        raise ValueError("Windows ACL policy schema is invalid")
    if raw["schema_version"] != 1:
        raise ValueError("Windows ACL policy schema version is unsupported")
    identity = raw["maintenance_identity"]
    if (
        not isinstance(identity, str)
        or not identity.strip()
        or identity != identity.strip()
        or identity.startswith("S-")
        or "\\" not in identity
    ):
        raise ValueError("maintenance identity must be an explicit Windows account name")
    targets = raw["maintenance_targets"]
    if not isinstance(targets, dict) or set(targets) != MAINTENANCE_TARGET_KEYS:
        raise ValueError("maintenance target allowlist does not match the reviewed policy")
    parsed: dict[str, MaintenanceAccessPolicy] = {}
    for target_key, entry in targets.items():
        if not isinstance(entry, dict) or set(entry) != {
            "rights", "inheritance_flags", "propagation_flags"
        }:
            raise ValueError(f"maintenance policy is malformed for {target_key}")
        if entry["rights"] != "FullControl":
            raise ValueError(f"maintenance rights must be exact FullControl for {target_key}")
        inheritance = entry["inheritance_flags"]
        propagation = entry["propagation_flags"]
        if (
            not isinstance(inheritance, list)
            or set(inheritance) != {"ContainerInherit", "ObjectInherit"}
            or len(inheritance) != 2
            or not isinstance(propagation, list)
            or propagation
        ):
            raise ValueError(f"maintenance inheritance is malformed for {target_key}")
        parsed[target_key] = MaintenanceAccessPolicy(
            rights=FULL_CONTROL_RIGHTS,
            inheritance_flags=frozenset(inheritance),
            propagation_flags=frozenset(),
        )
    return WindowsAclPolicy(identity, parsed)


_ACL_PROBE = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
function Resolve-Sid([string]$identity) {
  if ($identity -match '^S-\d(-\d+)+$') {
    return ([System.Security.Principal.SecurityIdentifier]::new($identity)).Value
  }
  return ([System.Security.Principal.NTAccount]::new($identity)).Translate(
    [System.Security.Principal.SecurityIdentifier]
  ).Value
}
$gatewaySid = Resolve-Sid $request.gateway_identity
$automatonSid = Resolve-Sid $request.automaton_identity
$maintenanceSid = Resolve-Sid $request.maintenance_identity
$maintenanceUser = Get-LocalUser -SID $([System.Security.Principal.SecurityIdentifier]::new($maintenanceSid)) -ErrorAction Stop
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$adminMembers = @(Get-LocalGroupMember -SID $([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')) |
  ForEach-Object { $_.SID.Value })
$results = @()
foreach ($target in $request.targets) {
  $exists = Test-Path -LiteralPath $target.path
  if (-not $exists) {
    $results += [pscustomobject]@{
      path = $target.path; role = $target.role; policy_key = $target.policy_key
      is_directory = $target.is_directory
      require_protected = $target.require_protected
      exists = $false; protected = $false; owner_sid = $null; rules = @()
    }
    continue
  }
  $acl = Get-Acl -LiteralPath $target.path
  $fileSystemItem = Get-Item -LiteralPath $target.path -Force
  try {
    $ownerSid = ([System.Security.Principal.NTAccount]::new($acl.Owner)).Translate(
      [System.Security.Principal.SecurityIdentifier]
    ).Value
  } catch {
    $ownerSid = $acl.Owner
  }
  $rules = @($acl.Access | ForEach-Object {
    try {
      $sid = $_.IdentityReference.Translate(
        [System.Security.Principal.SecurityIdentifier]
      ).Value
    } catch {
      $sid = 'UNRESOLVED:' + $_.IdentityReference.Value
    }
    [pscustomobject]@{
      sid = $sid
      type = $_.AccessControlType.ToString()
      rights = [int64]$_.FileSystemRights
      inherited = [bool]$_.IsInherited
      inheritance_flags = $_.InheritanceFlags.ToString()
      propagation_flags = $_.PropagationFlags.ToString()
    }
  })
  $results += [pscustomobject]@{
    path = $target.path; role = $target.role; policy_key = $target.policy_key
    is_directory = $target.is_directory
    actual_is_directory = [bool]$fileSystemItem.PSIsContainer
    require_protected = $target.require_protected
    exists = $true; protected = [bool]$acl.AreAccessRulesProtected
    reparse = [bool]($fileSystemItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
    owner_sid = $ownerSid; rules = $rules
  }
}
[pscustomobject]@{
  gateway_sid = $gatewaySid
  automaton_sid = $automatonSid
  maintenance_identity = $request.maintenance_identity
  maintenance_sid = $maintenanceSid
  maintenance_local_user = ($maintenanceUser.PrincipalSource.ToString() -eq 'Local')
  maintenance_enabled = [bool]$maintenanceUser.Enabled
  current_sid = $currentSid
  administrator_member_sids = $adminMembers
  targets = $results
} | ConvertTo-Json -Depth 8 -Compress
"""


def _targets(
    config_path: Path,
    config: GatewayBootstrapConfig | SecurityConfig,
    include_automaton_state: bool,
    *,
    kill_switch_present: bool,
    read_only_authorization_path: Path | None = None,
) -> list[dict[str, Any]]:
    workspace = Path(__file__).resolve().parents[1]
    if any(item is None for item in (
        config.audit_db_path, config.api_key_path, config.gateway_lock_path,
        config.log_dir, config.security_log_dir,
    )):
        raise ValueError("Separated protected paths are required for ACL verification")
    lab_root = config.kill_switch_path.parent.parent
    raw: list[tuple[Path, str, str, bool, bool]] = [
        (lab_root, "lab_root", "shared_navigation", True, True),
        (config_path.parent, "control_directory", "gateway_navigation", True, True),
        (config_path, "control_config", "control_file", False, True),
        (
            config.demo_authorization_path.parent,
            "control_demo_authorization",
            "authorization_directory",
            True,
            True,
        ),
        (config.api_key_path.parent, "ipc_directory", "shared_navigation", True, True),  # type: ignore[union-attr]
        (config.api_key_path, "ipc_key", "ipc_file", False, True),  # type: ignore[arg-type]
        (config.gateway_lock_path.parent, "operational", "gateway_modify", True, True),  # type: ignore[union-attr]
        (config.research_db_path.parent, "research", "gateway_modify", True, True),
        (config.audit_path.parent.parent, "audit_navigation", "gateway_navigation", True, True),
        (config.audit_db_path.parent, "audit_sqlite", "gateway_modify", True, True),  # type: ignore[union-attr]
        (config.audit_path.parent, "audit_journal", "append_directory", True, True),
        (config.audit_path, "audit_journal_file", "append_file", False, True),
        (config.log_dir.parent, "logs_root", "gateway_navigation", True, True),  # type: ignore[union-attr]
        (config.log_dir, "gateway_logs", "gateway_modify", True, True),  # type: ignore[arg-type]
        (config.security_log_dir, "security_logs", "append_directory", True, True),  # type: ignore[arg-type]
        (config.security_log_dir / "security.log", "security_log_file", "append_file", False, True),  # type: ignore[operator]
        (workspace, "workspace_code", "workspace_code", True, True),
    ]
    if kill_switch_present:
        raw.append((config.kill_switch_path, "control_kill_switch", "control_file", False, True))
    authorization_root = Path(os.path.abspath(config.demo_authorization_path.parent))
    discovered_authorizations = {
        artifact.name: artifact
        for artifact in discover_mt5_read_only_authorizations(authorization_root)
    }
    for artifact in discovered_authorizations.values():
        raw.append((
            artifact,
            "control_mt5_read_only_authorization_file",
            "authorization_file",
            False,
            False,
        ))
    if read_only_authorization_path is not None:
        authorization_path = Path(os.path.abspath(read_only_authorization_path))
        if (
            authorization_path.parent != authorization_root
            or not MT5_READ_ONLY_AUTHORIZATION_NAME.fullmatch(authorization_path.name)
        ):
            raise ValueError("MT5 read-only authorization path is outside the protected domain")
        if authorization_path.name not in discovered_authorizations:
            raw.append((
                authorization_path,
                "control_mt5_read_only_authorization_file",
                "authorization_file",
                False,
                False,
            ))
    for relative in (
        "trading_lab", "config", "src/trading", "src/index.ts", "src/config.ts",
        "src/agent/loop.ts", "src/agent/tools.ts", "src/conway/inference.ts",
        "src/identity/wallet.ts", "src/self-mod/code.ts", "src/types.ts",
        "scripts/Initialize-TradingLabAcl.ps1", "package.json",
        "scripts/setup.ps1", "scripts/start_gateway.ps1", "scripts/start_automaton.ps1",
        "scripts/status.ps1", "scripts/stop.ps1", "scripts/test_gateway.ps1",
        "scripts/enable_demo_trading.ps1", "scripts/disable_trading.ps1",
        "scripts/emergency_stop.ps1", "scripts/New-TradingLabUsers.ps1",
        "scripts/Apply-TradingLabAclGate.ps1",
        "scripts/TradingLabAclBootstrap.ps1",
        "scripts/Set-MT5ReadOnlyAuthorizationAcl.ps1",
        "scripts/Set-MT5ReadOnlyProtectedIdentity.ps1",
        "config/windows-acl-policy.json",
        "config/trading.security.example.json",
        "config/trading.example.yaml", "requirements-mt5.txt",
        "requirements-gateway-win-py314.lock",
        "docs/TRADING_LAB.md", "docs/SECURITY_INVARIANTS.md",
        "docs/READINESS_AUDIT.md", "docs/WINDOWS_ACL_MODEL.md",
    ):
        item = workspace / relative
        raw.append((item, "workspace_code", "workspace_code", item.is_dir(), False))
    if include_automaton_state:
        raw.append((config.automaton_state_dir, "automaton_state", "automaton_state", True, True))
    deduplicated: dict[tuple[str, str], dict[str, Any]] = {}
    for path, policy_key, role, is_directory, require_protected in raw:
        # Never resolve security targets through a symlink/junction before the
        # PowerShell probe sees them.  The probe must inspect the asserted path
        # itself so a reparse point cannot be laundered into its destination.
        asserted_path = str(Path(os.path.abspath(path)))
        key = (os.path.normcase(asserted_path), role)
        deduplicated[key] = {
            "path": asserted_path,
            "policy_key": policy_key,
            "role": role,
            "is_directory": is_directory,
            "require_protected": require_protected,
        }
    return list(deduplicated.values())


def _flag_set(value: object) -> frozenset[str]:
    if value is None or value == "" or value == "None":
        return frozenset()
    if not isinstance(value, str):
        raise ValueError("ACL flag payload is invalid")
    return frozenset(part.strip() for part in value.split(",") if part.strip())


def _exact_rule(
    rule: Mapping[str, Any],
    *,
    sid: str,
    rights: int,
    inherited: bool,
    inheritance: frozenset[str] = frozenset(),
    propagation: frozenset[str] = frozenset(),
) -> bool:
    return (
        str(rule.get("sid", "")) == sid
        and str(rule.get("type", "")) == "Allow"
        and int(rule.get("rights", 0)) == rights
        and bool(rule.get("inherited")) is inherited
        and _flag_set(rule.get("inheritance_flags")) == inheritance
        and _flag_set(rule.get("propagation_flags")) == propagation
    )


def _verify_authorization_acl(
    target: Mapping[str, Any], *, gateway_sid: str, automaton_sid: str
) -> None:
    path = str(target["path"])
    role = str(target["role"])
    rules = target.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError(f"ACL rules are invalid on {path}")
    if str(target.get("owner_sid", "")) != ADMINISTRATORS_SID:
        raise ValueError(f"unsafe owner on {path}")
    if target.get("reparse"):
        raise ValueError(f"ACL target cannot be a reparse point: {path}")
    if role == "authorization_directory":
        if not target.get("actual_is_directory", target.get("is_directory")):
            raise ValueError(f"authorization directory has the wrong type: {path}")
        if not target.get("protected"):
            raise ValueError(f"directory inheritance is not disabled: {path}")
        expected = (
            (SYSTEM_SID, FULL_CONTROL_RIGHTS, frozenset({"ContainerInherit", "ObjectInherit"}), frozenset()),
            (ADMINISTRATORS_SID, FULL_CONTROL_RIGHTS, frozenset({"ContainerInherit", "ObjectInherit"}), frozenset()),
            (gateway_sid, READ_EXECUTE_RIGHTS, frozenset(), frozenset()),
            (gateway_sid, READ_RIGHTS, frozenset({"ObjectInherit"}), frozenset({"InheritOnly"})),
        )
        if len(rules) != len(expected):
            raise ValueError(f"authorization directory ACE count is not exact on {path}")
        unmatched = list(rules)
        for sid, rights, inheritance, propagation in expected:
            match = next((
                rule for rule in unmatched
                if _exact_rule(
                    rule,
                    sid=sid,
                    rights=rights,
                    inherited=False,
                    inheritance=inheritance,
                    propagation=propagation,
                )
            ), None)
            if match is None:
                raise ValueError(f"authorization directory policy mismatch on {path}")
            unmatched.remove(match)
    elif role == "authorization_file":
        if target.get("actual_is_directory", target.get("is_directory")):
            raise ValueError(f"authorization artifact is not a regular file: {path}")
        if target.get("protected"):
            raise ValueError(f"authorization artifact must inherit the canonical parent ACL: {path}")
        expected = (
            (SYSTEM_SID, FULL_CONTROL_RIGHTS),
            (ADMINISTRATORS_SID, FULL_CONTROL_RIGHTS),
            (gateway_sid, READ_RIGHTS),
        )
        if len(rules) != len(expected):
            raise ValueError(f"authorization artifact ACE count is not exact on {path}")
        unmatched = list(rules)
        for sid, rights in expected:
            match = next((
                rule for rule in unmatched
                if _exact_rule(rule, sid=sid, rights=rights, inherited=True)
            ), None)
            if match is None:
                raise ValueError(f"authorization artifact inherited policy mismatch on {path}")
            unmatched.remove(match)
    else:
        raise ValueError(f"unknown authorization ACL role on {path}")
    if any(str(rule.get("sid", "")) == automaton_sid for rule in rules):
        raise ValueError(f"Automaton identity has access to authorization domain {path}")
    if any(str(rule.get("type", "")) != "Allow" for rule in rules):
        raise ValueError(f"authorization policy permits only exact Allow ACEs on {path}")


def evaluate_acl_snapshot(
    snapshot: dict[str, Any], *, maintenance_policy: WindowsAclPolicy,
    require_current_gateway: bool = False
) -> AclVerification:
    try:
        gateway_sid = str(snapshot["gateway_sid"])
        automaton_sid = str(snapshot["automaton_sid"])
        maintenance_identity = str(snapshot["maintenance_identity"])
        maintenance_sid = str(snapshot["maintenance_sid"])
        current_sid = str(snapshot["current_sid"])
        admin_members = {str(item) for item in snapshot["administrator_member_sids"]}
        targets = snapshot["targets"]
        if maintenance_identity != maintenance_policy.maintenance_identity:
            raise ValueError("ACL probe did not resolve the configured maintenance identity")
        if not gateway_sid.startswith("S-") or not automaton_sid.startswith("S-"):
            raise ValueError("configured identities did not resolve to Windows SIDs")
        if gateway_sid == automaton_sid:
            raise ValueError("gateway and Automaton resolve to the same SID")
        if gateway_sid in {SYSTEM_SID, ADMINISTRATORS_SID} or automaton_sid in {
            SYSTEM_SID, ADMINISTRATORS_SID,
        }:
            raise ValueError("laboratory identities cannot be privileged built-in identities")
        if maintenance_sid in {
            gateway_sid, automaton_sid, SYSTEM_SID, ADMINISTRATORS_SID
        }:
            raise ValueError("maintenance identity conflicts with a protected principal")
        if not snapshot.get("maintenance_local_user") or not snapshot.get("maintenance_enabled"):
            raise ValueError("maintenance identity must be an enabled local user")
        if maintenance_sid not in admin_members:
            raise ValueError("maintenance identity must be a direct local Administrator")
        if gateway_sid in admin_members or automaton_sid in admin_members:
            raise ValueError("laboratory identities cannot be local Administrators")
        if require_current_gateway and current_sid != gateway_sid:
            raise ValueError("gateway process is not running as the configured gateway identity")
        if not isinstance(targets, list) or not targets:
            raise ValueError("ACL probe returned no targets")

        for target in targets:
            role = str(target["role"])
            policy_key = str(target["policy_key"])
            path = str(target["path"])
            if policy_key not in KNOWN_TARGET_KEYS:
                raise ValueError(f"unknown ACL policy target: {policy_key}")
            if not target.get("exists"):
                raise ValueError(f"required ACL target is absent: {path}")
            if target.get("actual_is_directory", target.get("is_directory")) != target.get("is_directory"):
                raise ValueError(f"ACL target has the wrong filesystem type: {path}")
            if role in {"authorization_directory", "authorization_file"}:
                _verify_authorization_acl(
                    target,
                    gateway_sid=gateway_sid,
                    automaton_sid=automaton_sid,
                )
                continue
            if target.get("reparse"):
                raise ValueError(f"ACL target cannot be a reparse point: {path}")
            if target.get("require_protected", target.get("is_directory")) and not target.get("protected"):
                raise ValueError(f"directory inheritance is not disabled: {path}")
            if role in {"workspace_code", "shared_navigation", "ipc_file"}:
                required_sids = {gateway_sid, automaton_sid}
                forbidden_sid = None
            else:
                required_sid = automaton_sid if role == "automaton_state" else gateway_sid
                required_sids = {required_sid}
                forbidden_sid = gateway_sid if role == "automaton_state" else automaton_sid
            maintenance_access = maintenance_policy.maintenance_targets.get(policy_key)
            allowed_sids = {SYSTEM_SID, ADMINISTRATORS_SID, *required_sids}
            if maintenance_access is not None:
                allowed_sids.add(maintenance_sid)
            owner_sid = str(target.get("owner_sid", ""))
            if owner_sid != ADMINISTRATORS_SID:
                raise ValueError(f"unsafe owner on {path}")

            allow_rights = {sid: 0 for sid in required_sids}
            deny_rights = {sid: 0 for sid in required_sids}
            maintenance_rules: list[dict[str, Any]] = []
            for rule in target.get("rules", []):
                sid = str(rule.get("sid", ""))
                access_type = str(rule.get("type", ""))
                rights = int(rule.get("rights", 0))
                if rule.get("inherited") and (
                    target.get("require_protected") or target.get("protected")
                ):
                    raise ValueError(f"inherited ACE remains on protected target {path}")
                if access_type == "Allow":
                    if sid not in allowed_sids:
                        raise ValueError(f"unexpected allow SID {sid} on {path}")
                    if sid == forbidden_sid:
                        raise ValueError(f"forbidden identity has access to {path}")
                    if sid in required_sids:
                        allow_rights[sid] |= rights
                    if sid == maintenance_sid:
                        maintenance_rules.append(rule)
                elif access_type == "Deny":
                    raise ValueError(f"Deny ACE is forbidden by the explicit allowlist model on {path}")
                elif access_type not in {"Allow", "Deny"}:
                    raise ValueError(f"unknown ACL rule type on {path}")

            if maintenance_access is None:
                if maintenance_rules:
                    raise ValueError(f"maintenance identity is forbidden on {path}")
            else:
                if len(maintenance_rules) != 1:
                    raise ValueError(f"exactly one maintenance ACE is required on {path}")
                maintenance_rule = maintenance_rules[0]
                if int(maintenance_rule.get("rights", 0)) != maintenance_access.rights:
                    raise ValueError(f"maintenance rights mismatch on {path}")
                if (
                    _flag_set(maintenance_rule.get("inheritance_flags"))
                    != maintenance_access.inheritance_flags
                    or _flag_set(maintenance_rule.get("propagation_flags"))
                    != maintenance_access.propagation_flags
                ):
                    raise ValueError(f"maintenance inheritance mismatch on {path}")

            system_rights = 0
            administrator_rights = 0
            for rule in target.get("rules", []):
                if str(rule.get("type", "")) != "Allow":
                    continue
                sid = str(rule.get("sid", ""))
                if sid == SYSTEM_SID:
                    system_rights |= int(rule.get("rights", 0))
                elif sid == ADMINISTRATORS_SID:
                    administrator_rights |= int(rule.get("rights", 0))
            if system_rights & FULL_CONTROL_RIGHTS != FULL_CONTROL_RIGHTS:
                raise ValueError(f"SYSTEM lacks FullControl on {path}")
            if administrator_rights & FULL_CONTROL_RIGHTS != FULL_CONTROL_RIGHTS:
                raise ValueError(f"Administrators lack FullControl on {path}")

            if role in {"gateway_navigation", "append_directory"}:
                rights = allow_rights[gateway_sid]
                denied = deny_rights[gateway_sid]
                if rights & READ_EXECUTE_RIGHTS != READ_EXECUTE_RIGHTS:
                    raise ValueError(f"gateway lacks directory traversal access to {path}")
                if rights & WRITE_OR_SECURITY_RIGHTS:
                    raise ValueError(f"gateway can modify read-only directory {path}")
                if denied & READ_EXECUTE_RIGHTS:
                    raise ValueError(f"gateway read access is denied on {path}")
                if rights != READ_EXECUTE_RIGHTS:
                    raise ValueError(f"gateway directory rights exceed the exact policy on {path}")
            elif role == "control_file":
                rights = allow_rights[gateway_sid]
                if rights & READ_RIGHTS != READ_RIGHTS:
                    raise ValueError(f"gateway lacks read access to control file {path}")
                if rights & (WRITE_OR_SECURITY_RIGHTS | EXECUTE_RIGHT):
                    raise ValueError(f"gateway can modify or execute protected control file {path}")
                if rights != READ_RIGHTS:
                    raise ValueError(f"gateway control-file rights exceed the exact policy on {path}")
            elif role in {"gateway_modify", "automaton_state"}:
                principal = next(iter(required_sids))
                if allow_rights[principal] & MODIFY_RIGHTS != MODIFY_RIGHTS:
                    raise ValueError(f"required identity lacks modify access to {path}")
                if deny_rights[principal] & MODIFY_RIGHTS:
                    raise ValueError(f"required modify access is denied on {path}")
                if allow_rights[principal] != MODIFY_RIGHTS:
                    raise ValueError(f"modify rights exceed the exact policy on {path}")
            elif role in {"workspace_code", "shared_navigation"}:
                for principal in required_sids:
                    required = (
                        READ_EXECUTE_RIGHTS
                        if role == "workspace_code" or target.get("is_directory")
                        else READ_RIGHTS
                    )
                    if allow_rights[principal] & required != required:
                        raise ValueError(f"runtime identity lacks read access to protected target {path}")
                    if allow_rights[principal] & WRITE_OR_SECURITY_RIGHTS:
                        raise ValueError(f"runtime identity can modify protected target {path}")
                    if deny_rights[principal] & required:
                        raise ValueError(f"runtime identity read access is denied on {path}")
                    if allow_rights[principal] != required:
                        raise ValueError(f"runtime read rights exceed the exact policy on {path}")
            elif role == "ipc_file":
                for principal in required_sids:
                    rights = allow_rights[principal]
                    if rights & READ_RIGHTS != READ_RIGHTS:
                        raise ValueError(f"runtime identity lacks read access to IPC key {path}")
                    if rights & (WRITE_OR_SECURITY_RIGHTS | EXECUTE_RIGHT):
                        raise ValueError(f"runtime identity can modify or execute IPC key {path}")
                    if rights != READ_RIGHTS:
                        raise ValueError(f"IPC rights exceed the exact policy on {path}")
            elif role == "append_file":
                rights = allow_rights[gateway_sid]
                if rights & APPEND_ONLY_RIGHTS != APPEND_ONLY_RIGHTS:
                    raise ValueError(f"gateway lacks read/append access to append-only file {path}")
                if rights & (APPEND_FORBIDDEN_RIGHTS | EXECUTE_RIGHT):
                    raise ValueError(f"gateway has overwrite/delete/security rights on append-only file {path}")
                if rights != APPEND_ONLY_RIGHTS:
                    raise ValueError(f"append rights exceed the exact policy on {path}")
            else:
                raise ValueError(f"unknown ACL target role: {role}")
        return AclVerification(
            True,
            "Windows ACL separation is strict and least-privilege",
            gateway_sid=gateway_sid,
            automaton_sid=automaton_sid,
            current_sid=current_sid,
            maintenance_sid=maintenance_sid,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return AclVerification(False, str(exc))


def verify_windows_acl(
    config_path: str | Path,
    config: GatewayBootstrapConfig | SecurityConfig,
    *,
    include_automaton_state: bool = True,
    require_current_gateway: bool = False,
    kill_switch_present: bool | None = None,
    read_only_authorization_path: Path | None = None,
) -> AclVerification:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if powershell is None:
        return AclVerification(False, "PowerShell is unavailable for Windows ACL verification")
    try:
        if kill_switch_present is None:
            # Security callers must never infer absence through Path.exists(),
            # which collapses AccessDenied and some I/O failures into False.
            from .mt5_read_only_controls import KillSwitchState, probe_kill_switch

            kill_switch_present = (
                probe_kill_switch(config.kill_switch_path)
                is KillSwitchState.PRESENT_READABLE
            )
        policy = load_windows_acl_policy()
        request = {
            "gateway_identity": config.gateway_windows_identity,
            "automaton_identity": config.automaton_windows_identity,
            "maintenance_identity": policy.maintenance_identity,
            "targets": _targets(
                Path(config_path),
                config,
                include_automaton_state,
                kill_switch_present=kill_switch_present,
                read_only_authorization_path=read_only_authorization_path,
            ),
        }
        completed = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _ACL_PROBE],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            return AclVerification(False, "Windows ACL probe failed closed")
        snapshot = json.loads(completed.stdout)
        if not isinstance(snapshot, dict):
            return AclVerification(False, "Windows ACL probe returned an invalid payload")
        return evaluate_acl_snapshot(
            snapshot,
            maintenance_policy=policy,
            require_current_gateway=require_current_gateway,
        )
    except (
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return AclVerification(False, "Windows ACL verification failed closed")
