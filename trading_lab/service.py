from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
from dataclasses import replace
from pathlib import Path

from .api_auth import ApiKeyVerifier
from .config import (
    ConfigError,
    SecurityConfig,
    load_gateway_bootstrap_config,
    load_mt5_security_config,
    resolve_mt5_access_enabled,
)
from .domain import TradingMode
from .health_only import build_health_only_application
from .logging_config import configure_gateway_logging
from .mt5_access import MT5AccessDisabled
from .process_lock import GatewayProcessLock
from .windows_acl import verify_windows_acl


def acquire_mt5_adapter(config: SecurityConfig, *, mt5_access_enabled: bool):
    """Acquire the live provider only after both protected controls allow it."""
    if not mt5_access_enabled or not config.mt5_access_enabled:
        raise MT5AccessDisabled()
    from .providers import MT5ExecutionProvider

    adapter = MT5ExecutionProvider(config.mt5_terminal_path)
    if not adapter.initialize():
        raise RuntimeError("MT5 initialization failed")
    return adapter


def _run_uvicorn(api, *, port: int, controlled_stdin_shutdown: bool) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("FastAPI/Uvicorn dependencies are unavailable") from exc
    if not controlled_stdin_shutdown:
        uvicorn.run(
            api,
            host="127.0.0.1",
            port=port,
            log_config=None,
            access_log=False,
        )
        return

    server = uvicorn.Server(uvicorn.Config(
        api,
        host="127.0.0.1",
        port=port,
        log_config=None,
        access_log=False,
    ))

    def stop_on_stdin() -> None:
        signal = sys.stdin.buffer.read(1)
        if signal in {b"Q", b""}:
            server.should_exit = True

    monitor = threading.Thread(
        target=stop_on_stdin,
        name="gateway-controlled-shutdown",
        daemon=True,
    )
    monitor.start()
    server.run()


def serve(
    config_path: str | Path,
    port: int = 8765,
    *,
    controlled_stdin_shutdown: bool = False,
    environment: dict[str, str] | None = None,
) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("Gateway port must be between 1024 and 65535")
    bootstrap_config = load_gateway_bootstrap_config(config_path)
    mt5_access_enabled = resolve_mt5_access_enabled(bootstrap_config, environment)
    if not mt5_access_enabled and bootstrap_config.trading_mode is not TradingMode.OBSERVE_ONLY:
        raise RuntimeError("MT5-disabled startup requires TRADING_MODE=OBSERVE_ONLY")
    if mt5_access_enabled:
        config = load_mt5_security_config(config_path)
        if not resolve_mt5_access_enabled(config, environment):
            raise ConfigError("Protected MT5 access changed during startup")
    else:
        config = bootstrap_config
    acl = verify_windows_acl(
        config_path,
        config,
        include_automaton_state=False,
        require_current_gateway=True,
    )
    if not acl.passed:
        raise PermissionError(f"Gateway ACL verification failed: {acl.detail}")
    configure_gateway_logging(config.log_dir, config.security_log_dir)
    logger = logging.getLogger("automaton.gateway")
    if config.api_key_path is None or config.gateway_lock_path is None:
        raise RuntimeError("Gateway IPC key or process lock path is missing")
    verifier = ApiKeyVerifier(config.api_key_path)
    with GatewayProcessLock(config.gateway_lock_path):
        logger.info(
            "gateway_start gateway_started=true trading_mode=%s "
            "mt5_access_enabled=%s mt5_imported=false mt5_accessed=false "
            "loopback_only=true",
            config.trading_mode.value,
            str(mt5_access_enabled).lower(),
        )
        adapter = None
        health_only = not mt5_access_enabled
        health_start_audit_completed = False
        primary_error: BaseException | None = None
        try:
            try:
                from .fastapi_service import create_fastapi_app
            except ImportError as exc:
                raise RuntimeError("FastAPI dependency is unavailable") from exc
            if health_only:
                from .observation_http import (
                    ObservationLatestClosedM1Provider,
                )

                application = build_health_only_application(
                    replace(config, mt5_access_enabled=False),
                    runtime_identity_verified=True,
                    latest_closed_m1_provider=(
                        ObservationLatestClosedM1Provider()
                    ),
                )
                application.record_gateway_started()
                health_start_audit_completed = True
            else:
                adapter = acquire_mt5_adapter(config, mt5_access_enabled=True)
                from .factory import build_application

                application = build_application(
                    config,
                    adapter,
                    runtime_identity_verified=True,
                )
            api = create_fastapi_app(application, verifier)
            _run_uvicorn(
                api,
                port=port,
                controlled_stdin_shutdown=controlled_stdin_shutdown,
            )
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            stop_audit_error: BaseException | None = None
            if health_only and health_start_audit_completed:
                try:
                    application.record_gateway_stopped()
                except BaseException as exc:
                    if primary_error is None:
                        stop_audit_error = exc
                    else:
                        logger.error(
                            "gateway_stop_audit_failed primary_error_preserved=true "
                            "secondary_error_type=%s",
                            type(exc).__name__,
                        )
            if adapter is not None:
                adapter.shutdown()
            logger.info(
                "gateway_shutdown mt5_shutdown_called=%s",
                str(adapter is not None).lower(),
            )
            if stop_audit_error is not None:
                raise stop_audit_error


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed local Automaton MT5 gateway")
    parser.add_argument(
        "--config",
        default=os.environ.get(
            "AUTOMATON_MT5_SECURITY_CONFIG",
            r"C:\ProgramData\AutomatonMT5Lab\control\trading.yaml",
        ),
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--controlled-stdin-shutdown",
        action="store_true",
        help="Exit gracefully after Q/EOF on stdin; intended for the reviewed startup harness",
    )
    args = parser.parse_args()
    serve(
        args.config,
        args.port,
        controlled_stdin_shutdown=args.controlled_stdin_shutdown,
    )


if __name__ == "__main__":
    main()
