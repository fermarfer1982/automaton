from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import SecurityConfig


SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
READ_RIGHTS = 131209
MODIFY_RIGHTS = 197055
WRITE_OR_SECURITY_RIGHTS = 2 | 4 | 16 | 64 | 256 | 65536 | 262144 | 524288


@dataclass(frozen=True)
class AclVerification:
    passed: bool
    detail: str
    gateway_sid: str | None = None
    automaton_sid: str | None = None
    current_sid: str | None = None


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
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$adminMembers = @(Get-LocalGroupMember -SID $([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')) |
  ForEach-Object { $_.SID.Value })
$results = @()
foreach ($target in $request.targets) {
  $exists = Test-Path -LiteralPath $target.path
  if (-not $exists) {
    $results += [pscustomobject]@{
      path = $target.path; role = $target.role; is_directory = $target.is_directory
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
    }
  })
  $results += [pscustomobject]@{
    path = $target.path; role = $target.role; is_directory = $target.is_directory
    require_protected = $target.require_protected
    exists = $true; protected = [bool]$acl.AreAccessRulesProtected
    reparse = [bool]($fileSystemItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
    owner_sid = $ownerSid; rules = $rules
  }
}
[pscustomobject]@{
  gateway_sid = $gatewaySid
  automaton_sid = $automatonSid
  current_sid = $currentSid
  administrator_member_sids = $adminMembers
  targets = $results
} | ConvertTo-Json -Depth 8 -Compress
"""


def _targets(config_path: Path, config: SecurityConfig, include_automaton_state: bool) -> list[dict[str, Any]]:
    workspace = Path(__file__).resolve().parents[1]
    raw: list[tuple[Path, str, bool, bool]] = [
        (config_path, "gateway_control", False, False),
        (config_path.parent, "gateway_control", True, True),
        (config.demo_authorization_path.parent, "gateway_control", True, True),
        (config.audit_path.parent, "gateway_data", True, True),
        (workspace, "workspace_code", True, True),
    ]
    for relative in (
        "trading_lab", "src/trading", "src/index.ts", "src/config.ts",
        "src/agent/loop.ts", "src/agent/tools.ts", "src/conway/inference.ts",
        "src/identity/wallet.ts", "src/self-mod/code.ts", "src/types.ts",
        "scripts/Initialize-TradingLabAcl.ps1", "package.json",
        "config/trading.security.example.json", "requirements-mt5.txt",
    ):
        item = workspace / relative
        raw.append((item, "workspace_code", item.is_dir(), False))
    for item, role in (
        (config.demo_authorization_path, "gateway_control"),
        (config.kill_switch_path, "gateway_control"),
        (config.audit_path, "gateway_data"),
        (config.research_db_path, "gateway_data"),
    ):
        if item.exists():
            raw.append((item, role, item.is_dir(), False))
    if include_automaton_state:
        raw.append((config.automaton_state_dir, "automaton_state", True, True))
    deduplicated: dict[tuple[str, str], dict[str, Any]] = {}
    for path, role, is_directory, require_protected in raw:
        key = (str(path.resolve()), role)
        deduplicated[key] = {
            "path": str(path.resolve()),
            "role": role,
            "is_directory": is_directory,
            "require_protected": require_protected,
        }
    return list(deduplicated.values())


def evaluate_acl_snapshot(
    snapshot: dict[str, Any], *, require_current_gateway: bool = False
) -> AclVerification:
    try:
        gateway_sid = str(snapshot["gateway_sid"])
        automaton_sid = str(snapshot["automaton_sid"])
        current_sid = str(snapshot["current_sid"])
        admin_members = {str(item) for item in snapshot["administrator_member_sids"]}
        targets = snapshot["targets"]
        if not gateway_sid.startswith("S-") or not automaton_sid.startswith("S-"):
            raise ValueError("configured identities did not resolve to Windows SIDs")
        if gateway_sid == automaton_sid:
            raise ValueError("gateway and Automaton resolve to the same SID")
        if gateway_sid in {SYSTEM_SID, ADMINISTRATORS_SID} or automaton_sid in {
            SYSTEM_SID, ADMINISTRATORS_SID,
        }:
            raise ValueError("laboratory identities cannot be privileged built-in identities")
        if gateway_sid in admin_members or automaton_sid in admin_members:
            raise ValueError("laboratory identities cannot be local Administrators")
        if require_current_gateway and current_sid != gateway_sid:
            raise ValueError("gateway process is not running as the configured gateway identity")
        if not isinstance(targets, list) or not targets:
            raise ValueError("ACL probe returned no targets")

        for target in targets:
            role = str(target["role"])
            path = str(target["path"])
            if not target.get("exists"):
                raise ValueError(f"required ACL target is absent: {path}")
            if target.get("reparse"):
                raise ValueError(f"ACL target cannot be a reparse point: {path}")
            if target.get("require_protected", target.get("is_directory")) and not target.get("protected"):
                raise ValueError(f"directory inheritance is not disabled: {path}")
            if role == "workspace_code":
                required_sids = {gateway_sid, automaton_sid}
                forbidden_sid = None
            else:
                required_sid = automaton_sid if role == "automaton_state" else gateway_sid
                required_sids = {required_sid}
                forbidden_sid = gateway_sid if role == "automaton_state" else automaton_sid
            allowed_sids = {SYSTEM_SID, ADMINISTRATORS_SID, *required_sids}
            owner_sid = str(target.get("owner_sid", ""))
            safe_owners = {SYSTEM_SID, ADMINISTRATORS_SID}
            if role in {"gateway_data", "automaton_state"}:
                safe_owners.update(required_sids)
            if owner_sid not in safe_owners:
                raise ValueError(f"unsafe owner on {path}")

            allow_rights = {sid: 0 for sid in required_sids}
            deny_rights = {sid: 0 for sid in required_sids}
            for rule in target.get("rules", []):
                sid = str(rule.get("sid", ""))
                access_type = str(rule.get("type", ""))
                rights = int(rule.get("rights", 0))
                if access_type == "Allow":
                    if sid not in allowed_sids:
                        raise ValueError(f"unexpected allow SID {sid} on {path}")
                    if sid == forbidden_sid:
                        raise ValueError(f"forbidden identity has access to {path}")
                    if sid in required_sids:
                        allow_rights[sid] |= rights
                elif access_type == "Deny" and sid in required_sids:
                    deny_rights[sid] |= rights
                elif access_type not in {"Allow", "Deny"}:
                    raise ValueError(f"unknown ACL rule type on {path}")

            if role == "gateway_control":
                rights = allow_rights[gateway_sid]
                denied = deny_rights[gateway_sid]
                if rights & READ_RIGHTS != READ_RIGHTS:
                    raise ValueError(f"gateway lacks read access to control target {path}")
                if rights & WRITE_OR_SECURITY_RIGHTS:
                    raise ValueError(f"gateway can modify protected control target {path}")
                if denied & READ_RIGHTS:
                    raise ValueError(f"gateway read access is denied on {path}")
            elif role in {"gateway_data", "automaton_state"}:
                principal = next(iter(required_sids))
                if allow_rights[principal] & MODIFY_RIGHTS != MODIFY_RIGHTS:
                    raise ValueError(f"required identity lacks modify access to {path}")
                if deny_rights[principal] & MODIFY_RIGHTS:
                    raise ValueError(f"required modify access is denied on {path}")
            elif role == "workspace_code":
                for principal in required_sids:
                    if allow_rights[principal] & READ_RIGHTS != READ_RIGHTS:
                        raise ValueError(f"runtime identity lacks read access to code target {path}")
                    if allow_rights[principal] & WRITE_OR_SECURITY_RIGHTS:
                        raise ValueError(f"runtime identity can modify protected code target {path}")
                    if deny_rights[principal] & READ_RIGHTS:
                        raise ValueError(f"runtime identity read access is denied on {path}")
            else:
                raise ValueError(f"unknown ACL target role: {role}")
        return AclVerification(
            True,
            "Windows ACL separation is strict and least-privilege",
            gateway_sid=gateway_sid,
            automaton_sid=automaton_sid,
            current_sid=current_sid,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return AclVerification(False, str(exc))


def verify_windows_acl(
    config_path: str | Path,
    config: SecurityConfig,
    *,
    include_automaton_state: bool = True,
    require_current_gateway: bool = False,
) -> AclVerification:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if powershell is None:
        return AclVerification(False, "PowerShell is unavailable for Windows ACL verification")
    request = {
        "gateway_identity": config.gateway_windows_identity,
        "automaton_identity": config.automaton_windows_identity,
        "targets": _targets(Path(config_path), config, include_automaton_state),
    }
    try:
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
            snapshot, require_current_gateway=require_current_gateway
        )
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, TypeError, ValueError):
        return AclVerification(False, "Windows ACL verification failed closed")
