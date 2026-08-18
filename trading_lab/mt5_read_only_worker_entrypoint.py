from __future__ import annotations

import argparse
import os
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Any

from .config import SecurityConfig, load_mt5_security_config
from .domain import AccountKind, TradingMode
from .mt5_read_only import execute_mt5_read_only_preflight
from .mt5_read_only_data import (
    MT5ReadOnlyDataError,
    load_mt5_read_only_data_adapter,
)
from .mt5_read_only_worker_process import (
    WORKER_EXIT_OK,
    serve_streams,
)


WORKER_ENTRY_EXIT_SECURITY = 30
WORKER_ENTRY_EXIT_INITIALIZE = 31
WORKER_ENTRY_EXIT_RUNTIME = 32


def _canonical_run_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError(
            "run-id must be a UUID"
        ) from exc

    canonical = str(parsed)

    if value.casefold() != canonical:
        raise argparse.ArgumentTypeError(
            "run-id must use canonical UUID form"
        )

    return canonical


def _account_matches(
    config: SecurityConfig,
    account: Any,
) -> bool:
    if account.login != config.authorized_account:
        return False

    if account.server != config.authorized_server:
        return False

    if account.kind is not AccountKind.DEMO:
        return False

    if not account.connected:
        return False

    if account.terminal_trade_allowed:
        return False

    if (
        config.authorized_account_name is not None
        and account.account_name != config.authorized_account_name
    ):
        return False

    return True


def run_worker(
    config_path: Path,
    run_id: str,
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    config_loader: Callable[[str | Path], SecurityConfig] = (
        load_mt5_security_config
    ),
    preflight_runner: Callable[..., dict[str, object]] = (
        execute_mt5_read_only_preflight
    ),
    adapter_loader: Callable[..., Any] = (
        load_mt5_read_only_data_adapter
    ),
    stream_server: Callable[..., int] = serve_streams,
) -> int:
    adapter = None
    initialized = False
    result_code = WORKER_ENTRY_EXIT_RUNTIME

    try:
        config = config_loader(config_path)

        if config.trading_mode is not TradingMode.OBSERVE_ONLY:
            return WORKER_ENTRY_EXIT_SECURITY

        if config.mt5_access_enabled:
            return WORKER_ENTRY_EXIT_SECURITY

        security = preflight_runner(
            config_path,
            run_id,
            config_loader=lambda _: config,
        )

        if security.get("status") != "PASS":
            return WORKER_ENTRY_EXIT_SECURITY

        if not security.get("authorization_valid"):
            return WORKER_ENTRY_EXIT_SECURITY

        if not security.get("acl_verified"):
            return WORKER_ENTRY_EXIT_SECURITY

        if security.get("unexpected_capability_called"):
            return WORKER_ENTRY_EXIT_SECURITY

        if (
            security.get("order_check_called")
            or security.get("order_send_called")
        ):
            return WORKER_ENTRY_EXIT_SECURITY

        adapter = adapter_loader(
            config.mt5_terminal_path
        )

        adapter.assert_read_only_boundary()

        if not adapter.initialize():
            return WORKER_ENTRY_EXIT_INITIALIZE

        initialized = True

        account = adapter.account_snapshot()

        if not _account_matches(config, account):
            result_code = WORKER_ENTRY_EXIT_SECURITY
        else:
            result_code = stream_server(
                adapter,
                input_stream,
                output_stream,
            )

    except MT5ReadOnlyDataError:
        result_code = WORKER_ENTRY_EXIT_RUNTIME
    except Exception:
        result_code = WORKER_ENTRY_EXIT_RUNTIME
    finally:
        if initialized and adapter is not None:
            try:
                adapter.shutdown()
            except Exception:
                if result_code == WORKER_EXIT_OK:
                    result_code = WORKER_ENTRY_EXIT_RUNTIME

    return result_code


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Isolated fail-closed MT5 read-only worker"
        )
    )

    parser.add_argument(
        "--config",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--run-id",
        required=True,
        type=_canonical_run_id,
    )

    args = parser.parse_args()

    required_environment = {
        "TRADING_MODE": "OBSERVE_ONLY",
        "MT5_ACCESS_ENABLED": "false",
        "MT5_READ_ONLY_PREFLIGHT": "true",
        "MT5_READ_ONLY_DATA_ACCESS": "true",
    }

    for name, expected in required_environment.items():
        if os.environ.get(name) != expected:
            parser.error(
                f"{name} must be exactly {expected}"
            )

    exit_code = run_worker(
        args.config,
        args.run_id,
        sys.stdin.buffer,
        sys.stdout.buffer,
    )

    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
