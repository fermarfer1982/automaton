from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from .config import (
    ConfigError,
    _CREDENTIAL_KEYS,
    _TOP_LEVEL_KEYS,
    _build_mt5_security_config,
    load_mt5_security_config,
)
from .domain import TradingMode


TARGET_ACCOUNT = 107554164
TARGET_SERVER = "MetaQuotes-Demo"
TARGET_SYMBOL = "XAUUSD"
TARGET_TERMINAL = r"C:\Program Files\MetaTrader 5\terminal64.exe"
TARGET_MODE = "OBSERVE_ONLY"
CANONICAL_CONFIG_PATH = Path(
    r"C:\ProgramData\AutomatonMT5Lab\control\trading.yaml"
)
CANONICAL_WORKSPACE = Path(__file__).resolve().parents[1]
CONTROLLED_KEYS = frozenset({
    "authorized_account",
    "authorized_server",
    "mt5_access_enabled",
})


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_secrets(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).strip().casefold() in _CREDENTIAL_KEYS:
                raise ConfigError(f"credentials are forbidden at {path}.{key}")
            _reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]")


def parse_yaml_bytes(content: bytes) -> dict[str, Any]:
    if len(content) > 64 * 1024:
        raise ConfigError("protected config exceeds 64 KiB")
    try:
        raw = yaml.safe_load(content.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError("protected config is not valid UTF-8 YAML") from exc
    if not isinstance(raw, dict):
        raise ConfigError("protected config root must be an object")
    _reject_secrets(raw)
    unknown = set(raw) - _TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"unknown protected config fields: {', '.join(sorted(unknown))}")
    return raw


def plan_identity_update(raw: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if raw.get("trading_mode") != TARGET_MODE:
        raise ConfigError("trading_mode must remain exact OBSERVE_ONLY")
    if raw.get("allowed_symbol") != TARGET_SYMBOL:
        raise ConfigError("allowed_symbol must remain exact XAUUSD")
    if raw.get("mt5_terminal_path") != TARGET_TERMINAL:
        raise ConfigError("mt5_terminal_path is not the reviewed exact terminal path")
    access = raw.get("mt5_access_enabled", None)
    if access is not None and access is not False:
        raise ConfigError("mt5_access_enabled must be absent initially or explicit false")

    account = raw.get("authorized_account")
    server = raw.get("authorized_server")
    if account == 0 and server == "CHANGE_ME":
        state = "KNOWN_PLACEHOLDER"
    elif account == TARGET_ACCOUNT and server == TARGET_SERVER and access is False:
        state = "EXACT_TARGET"
    else:
        raise ConfigError("protected account/server state is neither the known placeholder nor exact target")

    candidate = copy.deepcopy(raw)
    candidate["authorized_account"] = TARGET_ACCOUNT
    candidate["authorized_server"] = TARGET_SERVER
    candidate["mt5_access_enabled"] = False
    return state, candidate


def render_candidate(raw: dict[str, Any]) -> bytes:
    _, candidate = plan_identity_update(raw)
    rendered = yaml.safe_dump(
        candidate,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=120,
    )
    return rendered.encode("utf-8")


def _read_exact_file(path: Path) -> bytes:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ConfigError("protected config path must be an absolute regular non-link file")
    return path.read_bytes()


def inspect(path: Path) -> dict[str, object]:
    content = _read_exact_file(path)
    raw = parse_yaml_bytes(content)
    state, candidate = plan_identity_update(raw)
    loaded_candidate = _build_mt5_security_config(
        candidate,
        CANONICAL_WORKSPACE,
    )
    if (
        loaded_candidate.trading_mode is not TradingMode.OBSERVE_ONLY
        or loaded_candidate.mt5_access_enabled is not False
        or loaded_candidate.authorized_account != TARGET_ACCOUNT
        or loaded_candidate.authorized_server != TARGET_SERVER
    ):
        raise ConfigError("candidate fails the real security config builder")
    return {
        "status": "PASS",
        "state": state,
        "source_sha256": _sha256(content),
        "candidate_sha256": _sha256(render_candidate(raw)),
        "candidate_schema_validated": True,
        "mt5_access_enabled_present": "mt5_access_enabled" in raw,
        "target": {
            "authorized_account": candidate["authorized_account"],
            "authorized_server": candidate["authorized_server"],
            "allowed_symbol": candidate["allowed_symbol"],
            "mt5_terminal_path": candidate["mt5_terminal_path"],
            "trading_mode": candidate["trading_mode"],
            "mt5_access_enabled": candidate["mt5_access_enabled"],
        },
    }


def write_candidate(source: Path, destination: Path) -> dict[str, object]:
    source_content = _read_exact_file(source)
    raw = parse_yaml_bytes(source_content)
    state, _ = plan_identity_update(raw)
    if (
        not destination.is_absolute()
        or os.path.abspath(destination.parent) != os.path.abspath(source.parent)
        or not destination.name.startswith(".trading.identity-")
        or not destination.name.endswith(".tmp")
    ):
        raise ConfigError("candidate path must be a confined same-directory maintenance temp")
    content = render_candidate(raw)
    with destination.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return {
        "status": "PASS",
        "state": state,
        "source_sha256": _sha256(source_content),
        "candidate_sha256": _sha256(content),
    }


def _expected_candidate(
    baseline: Path, candidate: Path
) -> tuple[dict[str, Any], bytes]:
    baseline_raw = parse_yaml_bytes(_read_exact_file(baseline))
    _, expected = plan_identity_update(baseline_raw)
    candidate_content = _read_exact_file(candidate)
    candidate_raw = parse_yaml_bytes(candidate_content)
    if candidate_raw != expected:
        raise ConfigError("candidate changes properties outside the exact identity transition")
    for key in set(baseline_raw) | set(candidate_raw):
        if key not in CONTROLLED_KEYS and baseline_raw.get(key) != candidate_raw.get(key):
            raise ConfigError(f"candidate unexpectedly changes protected property {key}")
    return candidate_raw, candidate_content


def _validated_result(loaded: Any, candidate_content: bytes, loader: str) -> dict[str, object]:
    if (
        loaded.trading_mode is not TradingMode.OBSERVE_ONLY
        or loaded.mt5_access_enabled is not False
        or loaded.authorized_account != TARGET_ACCOUNT
        or loaded.authorized_server != TARGET_SERVER
        or loaded.allowed_symbol != TARGET_SYMBOL
        or str(loaded.mt5_terminal_path) != TARGET_TERMINAL
    ):
        raise ConfigError("real protected config loader rejected the exact target identity")
    return {
        "status": "PASS",
        "candidate_sha256": _sha256(candidate_content),
        "loader": loader,
        "trading_mode": loaded.trading_mode.value,
        "mt5_access_enabled": loaded.mt5_access_enabled,
        "authorized_account": loaded.authorized_account,
        "authorized_server": loaded.authorized_server,
        "allowed_symbol": loaded.allowed_symbol,
        "mt5_terminal_path": str(loaded.mt5_terminal_path),
    }


def validate_candidate(baseline: Path, candidate: Path) -> dict[str, object]:
    """Validate a confined pre-replace temp without weakening the path loader."""
    candidate_raw, candidate_content = _expected_candidate(baseline, candidate)
    loaded = _build_mt5_security_config(
        candidate_raw,
        CANONICAL_WORKSPACE,
    )
    return _validated_result(loaded, candidate_content, "_build_mt5_security_config")


def validate_canonical_config(baseline: Path, candidate: Path) -> dict[str, object]:
    """Certify the final canonical file through the public runtime loader."""
    if os.path.normcase(os.path.abspath(candidate)) != os.path.normcase(
        os.path.abspath(CANONICAL_CONFIG_PATH)
    ):
        raise ConfigError("post-replace loader validation requires canonical trading.yaml")
    _, candidate_content = _expected_candidate(baseline, candidate)
    loaded = load_mt5_security_config(candidate)
    return _validated_result(loaded, candidate_content, "load_mt5_security_config")


def main() -> None:
    parser = argparse.ArgumentParser(description="Protected MT5 identity config transition helper")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--config", required=True, type=Path)
    render_parser = subparsers.add_parser("render")
    render_parser.add_argument("--config", required=True, type=Path)
    render_parser.add_argument("--output", required=True, type=Path)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument(
        "--mode", required=True, choices=("pre-replace", "post-replace")
    )
    validate_parser.add_argument("--baseline", required=True, type=Path)
    validate_parser.add_argument("--candidate", required=True, type=Path)
    args = parser.parse_args()
    if args.operation == "inspect":
        result = inspect(args.config)
    elif args.operation == "render":
        result = write_candidate(args.config, args.output)
    elif args.mode == "pre-replace":
        result = validate_candidate(args.baseline, args.candidate)
    else:
        result = validate_canonical_config(args.baseline, args.candidate)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
