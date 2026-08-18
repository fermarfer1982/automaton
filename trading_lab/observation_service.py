from __future__ import annotations

import argparse
import os
import sys
import threading
import uuid
from pathlib import Path

from .api_auth import ApiKeyVerifier
from .config import load_mt5_security_config
from .domain import TradingMode
from .mt5_read_only_client import (
    MT5ReadOnlyClient,
)
from .observation_api import (
    create_observation_api,
)
from .observation_application import (
    ObservationApplication,
)
from .process_lock import GatewayProcessLock
from .windows_acl import verify_windows_acl


DEFAULT_CONFIG = Path(
    r"C:\ProgramData\AutomatonMT5Lab"
    r"\control\trading.yaml"
)

DEFAULT_OBSERVATION_KEY = Path(
    r"C:\ProgramData\AutomatonMT5Lab"
    r"\ipc\observation.key"
)

DEFAULT_OBSERVATION_LOCK = Path(
    r"C:\ProgramData\AutomatonMT5Lab"
    r"\operational\observation.lock"
)

DEFAULT_WORKSPACE = Path(
    r"C:\automaton"
)

DEFAULT_PYTHON = Path(
    r"C:\automaton\.venv\Scripts"
    r"\python.exe"
)


def _canonical_run_id(
    value: str,
) -> str:
    parsed = uuid.UUID(value)

    canonical = str(parsed)

    if canonical != value.lower():
        raise ValueError(
            "RunId must be canonical UUID"
        )

    return canonical


def _run_uvicorn(
    api,
    *,
    port: int,
    controlled_stdin_shutdown: bool,
) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            "FastAPI/Uvicorn dependencies "
            "are unavailable"
        ) from exc

    if not controlled_stdin_shutdown:
        uvicorn.run(
            api,
            host="127.0.0.1",
            port=port,
            log_config=None,
            access_log=False,
        )
        return

    server = uvicorn.Server(
        uvicorn.Config(
            api,
            host="127.0.0.1",
            port=port,
            log_config=None,
            access_log=False,
        )
    )

    def stop_on_stdin() -> None:
        signal = sys.stdin.buffer.read(1)

        if signal in {
            b"Q",
            b"",
        }:
            server.should_exit = True

    monitor = threading.Thread(
        target=stop_on_stdin,
        name=(
            "observation-controlled-shutdown"
        ),
        daemon=True,
    )

    monitor.start()
    server.run()


def serve(
    *,
    config_path: Path,
    run_id: str,
    port: int = 8766,
    observation_key_path: Path = (
        DEFAULT_OBSERVATION_KEY
    ),
    workspace: Path = DEFAULT_WORKSPACE,
    python_executable: Path = DEFAULT_PYTHON,
    controlled_stdin_shutdown: bool = False,
    environment: dict[str, str] | None = None,
    uvicorn_runner=_run_uvicorn,
    client_factory=MT5ReadOnlyClient,
) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError(
            "Observation port is invalid"
        )

    run_id = _canonical_run_id(
        run_id
    )

    env = (
        dict(os.environ)
        if environment is None
        else dict(environment)
    )

    if env.get(
        "TRADING_MODE"
    ) != "OBSERVE_ONLY":
        raise RuntimeError(
            "Observation service requires "
            "TRADING_MODE=OBSERVE_ONLY"
        )

    if env.get(
        "MT5_ACCESS_ENABLED"
    ) != "false":
        raise RuntimeError(
            "Observation service requires "
            "MT5_ACCESS_ENABLED=false"
        )

    if env.get(
        "MT5_READ_ONLY_DATA_ACCESS"
    ) != "true":
        raise RuntimeError(
            "Read-only data access must be "
            "explicitly enabled"
        )

    config = load_mt5_security_config(
        config_path
    )

    if (
        config.trading_mode
        is not TradingMode.OBSERVE_ONLY
    ):
        raise RuntimeError(
            "Protected mode must remain "
            "OBSERVE_ONLY"
        )

    if config.mt5_access_enabled:
        raise RuntimeError(
            "Protected execution MT5 access "
            "must remain disabled"
        )

    acl = verify_windows_acl(
        config_path,
        config,
        include_automaton_state=False,
        require_current_gateway=True,
    )

    if not acl.passed:
        raise PermissionError(
            "Observation Gateway ACL "
            "verification failed"
        )

    verifier = ApiKeyVerifier(
        observation_key_path
    )

    with GatewayProcessLock(
        DEFAULT_OBSERVATION_LOCK
    ):
        client = client_factory(
            python_executable=python_executable,
            workspace=workspace,
            config_path=config_path,
            run_id=run_id,
            timeout_seconds=60.0,
        )

        primary_error = None

        try:
            application = (
                ObservationApplication(
                    client,
                    authorized_account=(
                        config.authorized_account
                    ),
                    authorized_server=(
                        config.authorized_server
                    ),
                    allowed_symbol=(
                        config.allowed_symbol
                    ),
                )
            )

            api = create_observation_api(
                application,
                verifier,
            )

            uvicorn_runner(
                api,
                port=port,
                controlled_stdin_shutdown=(
                    controlled_stdin_shutdown
                ),
            )

        except BaseException as exc:
            primary_error = exc
            raise

        finally:
            try:
                client.close()
            except BaseException:
                if primary_error is None:
                    raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Fail-closed local MT5 "
            "observation service"
        )
    )

    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
    )

    parser.add_argument(
        "--run-id",
        required=True,
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8766,
    )

    parser.add_argument(
        "--observation-key",
        default=str(
            DEFAULT_OBSERVATION_KEY
        ),
    )

    parser.add_argument(
        "--controlled-stdin-shutdown",
        action="store_true",
    )

    args = parser.parse_args()

    serve(
        config_path=Path(args.config),
        run_id=args.run_id,
        port=args.port,
        observation_key_path=Path(
            args.observation_key
        ),
        controlled_stdin_shutdown=(
            args.controlled_stdin_shutdown
        ),
    )


if __name__ == "__main__":
    main()
