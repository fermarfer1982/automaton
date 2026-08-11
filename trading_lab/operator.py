from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from .config import load_security_config, security_config_hash
from .domain import TradingMode
from .process_lock import GatewayProcessLock
from .windows_acl import verify_windows_acl


def _load_yaml_module():
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML from the reviewed hash lock is required") from exc
    return yaml


def verify_gateway_role(config_path: Path) -> None:
    config = load_security_config(config_path)
    result = verify_windows_acl(
        config_path,
        config,
        # The Gateway deliberately has no access to Agent state.  Full cross-domain
        # verification is performed only by the elevated human readiness command.
        include_automaton_state=False,
        require_current_gateway=True,
    )
    if not result.passed:
        raise PermissionError(result.detail)


def _read_readiness(path: Path) -> tuple[dict[str, object], str]:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Readiness artifact must be an absolute non-symlink file")
    raw = path.read_bytes()
    if len(raw) > 2_000_000:
        raise ValueError("Readiness artifact is too large")
    digest = hashlib.sha256(raw).hexdigest()
    digest_path = path.with_name(f"{path.name}.sha256")
    if not digest_path.is_file() or digest_path.is_symlink():
        raise PermissionError("Detached readiness digest is missing or unsafe")
    expected_line = f"{digest}  {path.name}"
    if digest_path.read_text(encoding="ascii").strip() != expected_line:
        raise PermissionError("Detached readiness digest does not match the artifact")
    payload = json.loads(raw)
    required_true = {
        "AUTOMATON_MT5_LAB_READY", "MT5_CONNECTED", "DEMO_VERIFIED",
        "ACCOUNT_ALLOWED", "SERVER_ALLOWED", "XAUUSD_AVAILABLE",
        "GATEWAY_HEALTH", "AUTOMATON_TOOLS_READY", "AUDIT_READY",
        "RISK_TESTS", "SECURITY_TESTS",
    }
    if (
        not isinstance(payload, dict)
        or any(payload.get(field) is not True for field in required_true)
        or payload.get("TRADING_MODE") != TradingMode.OBSERVE_ONLY.value
    ):
        raise PermissionError("A complete OBSERVE_ONLY readiness artifact is required")
    return payload, digest


def _write_yaml_mode(config_path: Path, mode: TradingMode) -> None:
    if config_path.suffix.lower() not in {".yaml", ".yml"} or config_path.is_symlink():
        raise ValueError("Protected mode changes require a non-symlink YAML configuration")
    yaml = _load_yaml_module()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Protected configuration root is invalid")
    raw["trading_mode"] = mode.value
    temporary = config_path.with_name(f"{config_path.stem}.{os.getpid()}.tmp.yaml")
    temporary.write_text(
        yaml.safe_dump(raw, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
        newline="\n",
    )
    # Validate all schema/path invariants before replacing protected state.
    load_security_config(temporary)
    temporary.replace(config_path)


def _reject_symlink_targets(*paths: Path) -> None:
    for path in paths:
        if path.is_symlink():
            raise PermissionError(f"Protected control path cannot be a symlink: {path.name}")


def enable_demo(
    config_path: Path,
    readiness_path: Path,
    *,
    apply: bool,
    clear_kill_switch: bool,
) -> dict[str, object]:
    if config_path.suffix.lower() not in {".yaml", ".yml"}:
        raise ValueError("DEMO enablement requires the protected YAML configuration")
    config = load_security_config(config_path)
    _reject_symlink_targets(
        config_path, config.demo_authorization_path, config.kill_switch_path
    )
    acl = verify_windows_acl(config_path, config, include_automaton_state=True)
    if not acl.passed:
        raise PermissionError(f"Protected ACL readiness failed: {acl.detail}")
    if config.trading_mode is not TradingMode.OBSERVE_ONLY:
        raise PermissionError("Enablement must start from OBSERVE_ONLY")
    readiness, readiness_hash = _read_readiness(readiness_path)
    if readiness.get("SECURITY_CONFIG_SHA256") != security_config_hash(config):
        raise PermissionError("Readiness artifact is not bound to this OBSERVE_ONLY configuration")
    plan = {
        "apply": apply,
        "action": "ENABLE_DEMO_EXECUTION",
        "account_binding_present": config.authorized_account > 0,
        "server_binding_present": bool(config.authorized_server),
        "readiness_sha256": readiness_hash,
        "clear_kill_switch": clear_kill_switch,
    }
    if not apply:
        return plan
    if config.kill_switch_path.exists() and not clear_kill_switch:
        raise PermissionError("Kill switch is engaged; clearing it requires an explicit flag")
    if config.gateway_lock_path is None:
        raise RuntimeError("Gateway process lock path is missing")
    with GatewayProcessLock(config.gateway_lock_path):
        if config.kill_switch_path.exists():
            if config.kill_switch_path.is_symlink():
                raise PermissionError("Kill switch cannot be a symlink")
            config.kill_switch_path.unlink()
        raw = _load_yaml_module().safe_load(config_path.read_text(encoding="utf-8"))
        raw["trading_mode"] = TradingMode.DEMO_EXECUTION.value
        temporary = config_path.with_name(f"{config_path.stem}.{os.getpid()}.candidate.yaml")
        temporary.write_text(
            _load_yaml_module().safe_dump(raw, sort_keys=False, allow_unicode=False),
            encoding="utf-8", newline="\n",
        )
        demo_config = load_security_config(temporary)
        authorization = {
            "schema_version": 1,
            "authorization": "ALLOW_DEMO_EXECUTION",
            "authorized_account": demo_config.authorized_account,
            "authorized_server": demo_config.authorized_server,
            "config_sha256": security_config_hash(demo_config),
            "readiness_sha256": readiness_hash,
        }
        demo_config.demo_authorization_path.write_text(
            json.dumps(authorization, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8", newline="\n",
        )
        temporary.replace(config_path)
    return {**plan, "applied": True}


def disable(config_path: Path, *, apply: bool) -> dict[str, object]:
    config = load_security_config(config_path)
    _reject_symlink_targets(
        config_path, config.demo_authorization_path, config.kill_switch_path
    )
    plan = {"apply": apply, "action": "DISABLE_TRADING", "target_mode": "OBSERVE_ONLY"}
    if not apply:
        return plan
    config.kill_switch_path.parent.mkdir(parents=True, exist_ok=True)
    config.kill_switch_path.write_text("HALT\n", encoding="ascii", newline="\n")
    if config.gateway_lock_path is None:
        raise RuntimeError("Gateway process lock path is missing")
    with GatewayProcessLock(config.gateway_lock_path):
        _write_yaml_mode(config_path, TradingMode.OBSERVE_ONLY)
        config.demo_authorization_path.write_text(
            "DISABLED\n", encoding="ascii", newline="\n"
        )
    return {**plan, "applied": True, "kill_switch": "ENGAGED"}


def emergency_stop(config_path: Path) -> dict[str, object]:
    config = load_security_config(config_path)
    _reject_symlink_targets(config.kill_switch_path)
    config.kill_switch_path.parent.mkdir(parents=True, exist_ok=True)
    config.kill_switch_path.write_text("HALT\n", encoding="ascii", newline="\n")
    return {"action": "EMERGENCY_STOP", "kill_switch": "ENGAGED"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Human-operated MT5 laboratory controls")
    parser.add_argument("--config", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-gateway")
    enable_parser = subparsers.add_parser("enable-demo")
    enable_parser.add_argument("--readiness", required=True, type=Path)
    enable_parser.add_argument("--apply", action="store_true")
    enable_parser.add_argument("--clear-kill-switch", action="store_true")
    disable_parser = subparsers.add_parser("disable")
    disable_parser.add_argument("--apply", action="store_true")
    subparsers.add_parser("emergency-stop")
    args = parser.parse_args()
    if args.command == "verify-gateway":
        verify_gateway_role(args.config)
        result = {"gateway_identity_verified": True}
    elif args.command == "enable-demo":
        result = enable_demo(
            args.config, args.readiness,
            apply=args.apply,
            clear_kill_switch=args.clear_kill_switch,
        )
    elif args.command == "disable":
        result = disable(args.config, apply=args.apply)
    else:
        result = emergency_stop(args.config)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
