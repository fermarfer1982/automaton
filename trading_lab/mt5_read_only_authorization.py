from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .config import load_mt5_security_config
from .domain import TradingMode
from .mt5_read_only_controls import (
    authorization_path,
    parse_authorization,
    read_authorization_file,
    render_authorization,
    validate_authorization,
)
from .windows_acl import verify_windows_acl


WORKSPACE = Path(__file__).resolve().parents[1]


def _uuid(value: str) -> str:
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError("value must be a UUID") from exc
    if parsed != value.casefold():
        raise argparse.ArgumentTypeError("UUID must use canonical form")
    return parsed


def _load_exact_config(path: Path):
    config = load_mt5_security_config(path)
    if config.trading_mode is not TradingMode.OBSERVE_ONLY:
        raise RuntimeError("Authorization creation requires OBSERVE_ONLY")
    if config.mt5_access_enabled:
        raise RuntimeError("Gateway MT5 access must remain disabled")
    if config.allowed_symbol != "XAUUSD":
        raise RuntimeError("Authorization creation requires exact XAUUSD")
    return config


def _acl(path: Path, config, *, authorization_file: Path | None = None):
    result = verify_windows_acl(
        path,
        config,
        include_automaton_state=False,
        require_current_gateway=False,
        read_only_authorization_path=authorization_file,
    )
    if (
        not result.passed
        or not result.current_sid
        or not result.maintenance_sid
        or not result.gateway_sid
    ):
        raise PermissionError("Protected authorization ACL verification failed closed")
    return result


def render(config_path: Path, run_id: str, authorization_id: str, issuer_sid: str) -> dict:
    config = _load_exact_config(config_path)
    acl = _acl(config_path, config)
    if acl.current_sid != acl.maintenance_sid or issuer_sid != acl.maintenance_sid:
        raise PermissionError("Authorization issuer is not the canonical maintenance SID")
    return render_authorization(
        config=config,
        config_path=config_path,
        workspace=WORKSPACE,
        run_id=run_id,
        authorization_id=authorization_id,
        issuer_sid=issuer_sid,
        gateway_sid=acl.gateway_sid,
        issued_at=datetime.now(UTC),
    )


def verify_artifact(config_path: Path, run_id: str) -> dict[str, object]:
    config = _load_exact_config(config_path)
    path = authorization_path(config, run_id)
    artifact = read_authorization_file(path)
    acl = _acl(config_path, config, authorization_file=path)
    if acl.current_sid != acl.maintenance_sid:
        raise PermissionError("Artifact verification requires canonical maintenance SID")
    authorization = parse_authorization(artifact.content)
    validate_authorization(
        authorization,
        config=config,
        config_path=config_path,
        workspace=WORKSPACE,
        run_id=run_id,
        issuer_sid=acl.maintenance_sid,
        gateway_sid=acl.gateway_sid,
        now=datetime.now(UTC),
    )
    return {
        "status": "PASS",
        "authorization_path": str(path),
        "authorization_id": authorization.authorization_id,
        "authorization_sha256": artifact.sha256,
        "gateway_sid": acl.gateway_sid,
        "maintenance_sid": acl.maintenance_sid,
        "content_verified": True,
        "acl_verified": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Human MT5 read-only authorization helper")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    render_parser = subparsers.add_parser("render")
    render_parser.add_argument("--config", required=True, type=Path)
    render_parser.add_argument("--run-id", required=True, type=_uuid)
    render_parser.add_argument("--authorization-id", required=True, type=_uuid)
    render_parser.add_argument("--issuer-sid", required=True)
    verify_parser = subparsers.add_parser("verify-artifact")
    verify_parser.add_argument("--config", required=True, type=Path)
    verify_parser.add_argument("--run-id", required=True, type=_uuid)
    args = parser.parse_args()

    if args.operation == "render":
        payload = render(args.config, args.run_id, args.authorization_id, args.issuer_sid)
    else:
        payload = verify_artifact(args.config, args.run_id)
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
