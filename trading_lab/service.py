from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from .api_auth import ApiKeyVerifier
from .config import load_security_config
from .factory import build_application
from .logging_config import configure_gateway_logging
from .process_lock import GatewayProcessLock
from .providers import MT5ExecutionProvider
from .windows_acl import verify_windows_acl


def serve(config_path: str | Path, port: int = 8765) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("Gateway port must be between 1024 and 65535")
    config = load_security_config(config_path)
    acl = verify_windows_acl(
        config_path,
        config,
        include_automaton_state=False,
        require_current_gateway=True,
    )
    if not acl.passed:
        raise PermissionError(f"Gateway ACL verification failed: {acl.detail}")
    configure_gateway_logging(config.log_dir)
    logger = logging.getLogger("automaton.gateway")
    if config.api_key_path is None or config.gateway_lock_path is None:
        raise RuntimeError("Gateway IPC key or process lock path is missing")
    verifier = ApiKeyVerifier(config.api_key_path)
    with GatewayProcessLock(config.gateway_lock_path):
        logger.info("gateway_start mode=%s loopback_only=true", config.trading_mode.value)
        adapter = MT5ExecutionProvider(config.mt5_terminal_path)
        if not adapter.initialize():
            raise RuntimeError("MT5 initialization failed")
        application = build_application(config, adapter, runtime_identity_verified=True)
        try:
            try:
                import uvicorn
                from .fastapi_service import create_fastapi_app
            except ImportError as exc:
                raise RuntimeError("FastAPI/Uvicorn dependencies are unavailable") from exc
            api = create_fastapi_app(application, verifier)
            uvicorn.run(
                api,
                host="127.0.0.1",
                port=port,
                log_config=None,
                access_log=False,
            )
        finally:
            adapter.shutdown()
            logger.info("gateway_shutdown")


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
    args = parser.parse_args()
    serve(args.config, args.port)


if __name__ == "__main__":
    main()
