from __future__ import annotations

import os
import subprocess
import threading
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .mt5_read_only_framing import (
    MT5ReadOnlyFramingError,
    read_frame,
    write_frame,
)
from .mt5_read_only_protocol import (
    MAX_MESSAGE_BYTES,
    MAX_RESPONSE_BYTES,
    MT5ReadOnlyProtocolError,
    ReadOnlyRequest,
    decode_response,
    encode_request,
)


class MT5ReadOnlyClientError(RuntimeError):
    pass


class MT5ReadOnlyRemoteError(MT5ReadOnlyClientError):
    def __init__(
        self,
        code: str,
        message: str,
    ) -> None:
        super().__init__(
            f"{code}: {message}"
        )
        self.code = code


def _new_request_id() -> str:
    return str(uuid.uuid4())


def _canonical_run_id(value: str) -> str:
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise MT5ReadOnlyClientError(
            "run-id must be a canonical UUID"
        ) from exc

    if value.casefold() != canonical:
        raise MT5ReadOnlyClientError(
            "run-id must be a canonical UUID"
        )

    return canonical


class MT5ReadOnlyClient:
    def __init__(
        self,
        *,
        python_executable: Path,
        workspace: Path,
        config_path: Path,
        run_id: str,
        timeout_seconds: float = 15.0,
        process_factory: Callable[..., Any] = subprocess.Popen,
        request_id_factory: Callable[[], str] = _new_request_id,
    ) -> None:
        if timeout_seconds <= 0:
            raise MT5ReadOnlyClientError(
                "timeout_seconds must be positive"
            )

        if os.environ.get("TRADING_MODE") != "OBSERVE_ONLY":
            raise MT5ReadOnlyClientError(
                "Parent must remain OBSERVE_ONLY"
            )

        if os.environ.get("MT5_ACCESS_ENABLED") != "false":
            raise MT5ReadOnlyClientError(
                "Parent MT5 access must remain disabled"
            )

        self._python_executable = Path(
            python_executable
        )
        self._workspace = Path(workspace)
        self._config_path = Path(config_path)
        self._run_id = _canonical_run_id(run_id)
        self._timeout_seconds = float(
            timeout_seconds
        )
        self._request_id_factory = (
            request_id_factory
        )
        self._lock = threading.RLock()
        self._closed = False

        child_environment = os.environ.copy()

        child_environment.update({
            "TRADING_MODE": "OBSERVE_ONLY",
            "MT5_ACCESS_ENABLED": "false",
            "MT5_READ_ONLY_PREFLIGHT": "true",
            "MT5_READ_ONLY_DATA_ACCESS": "true",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(self._workspace),
        })

        command = [
            str(self._python_executable),
            "-B",
            "-m",
            (
                "trading_lab."
                "mt5_read_only_worker_entrypoint"
            ),
            "--config",
            str(self._config_path),
            "--run-id",
            self._run_id,
        ]

        try:
            self._process = process_factory(
                command,
                cwd=str(self._workspace),
                env=child_environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                shell=False,
                creationflags=getattr(
                    subprocess,
                    "CREATE_NO_WINDOW",
                    0,
                ),
            )
        except OSError as exc:
            raise MT5ReadOnlyClientError(
                "Unable to start read-only worker"
            ) from exc

        if (
            self._process.stdin is None
            or self._process.stdout is None
        ):
            self._terminate_process()
            raise MT5ReadOnlyClientError(
                "Worker IPC pipes are unavailable"
            )

    @property
    def pid(self) -> int | None:
        return getattr(
            self._process,
            "pid",
            None,
        )

    @property
    def closed(self) -> bool:
        return self._closed

    def _terminate_process(self) -> None:
        process = getattr(
            self,
            "_process",
            None,
        )

        if process is None:
            return

        try:
            if process.poll() is None:
                process.terminate()

                try:
                    process.wait(
                        timeout=2.0
                    )
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(
                        timeout=2.0
                    )
        except Exception:
            pass

    def _close_pipes(self) -> None:
        process = self._process

        for stream_name in (
            "stdin",
            "stdout",
            "stderr",
        ):
            stream = getattr(
                process,
                stream_name,
                None,
            )

            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass

    def _read_frame_with_timeout(
        self,
    ) -> bytes:
        result: dict[str, Any] = {}
        failure: dict[str, BaseException] = {}

        def reader() -> None:
            try:
                result["raw"] = read_frame(
                    self._process.stdout,
                    max_payload_bytes=(
                        MAX_RESPONSE_BYTES
                    ),
                )
            except BaseException as exc:
                failure["error"] = exc

        thread = threading.Thread(
            target=reader,
            name="mt5-read-only-client-reader",
            daemon=True,
        )
        thread.start()
        thread.join(
            self._timeout_seconds
        )

        if thread.is_alive():
            self._terminate_process()
            thread.join(2.0)

            raise MT5ReadOnlyClientError(
                "Timed out waiting for read-only worker"
            )

        if "error" in failure:
            raise MT5ReadOnlyClientError(
                "Failed to read worker response"
            ) from failure["error"]

        raw = result.get("raw")

        if raw is None:
            exit_code = self._process.poll()

            raise MT5ReadOnlyClientError(
                "Read-only worker closed IPC "
                f"without response; exit={exit_code}"
            )

        if not isinstance(raw, bytes):
            raise MT5ReadOnlyClientError(
                "Worker response is not bytes"
            )

        return raw

    def request(
        self,
        operation: str,
        params: dict[str, Any],
    ) -> Any:
        with self._lock:
            if self._closed:
                raise MT5ReadOnlyClientError(
                    "Read-only client is closed"
                )

            if self._process.poll() is not None:
                raise MT5ReadOnlyClientError(
                    "Read-only worker is not running"
                )

            request_id = (
                self._request_id_factory()
            )

            request = ReadOnlyRequest(
                request_id=request_id,
                operation=operation,
                params=params,
            )

            try:
                encoded = encode_request(
                    request
                )

                write_frame(
                    self._process.stdin,
                    encoded,
                    max_payload_bytes=(
                        MAX_MESSAGE_BYTES
                    ),
                )
            except (
                MT5ReadOnlyProtocolError,
                MT5ReadOnlyFramingError,
                OSError,
            ) as exc:
                self._terminate_process()

                raise MT5ReadOnlyClientError(
                    "Failed to send read-only request"
                ) from exc

            raw_response = (
                self._read_frame_with_timeout()
            )

            try:
                response = decode_response(
                    raw_response,
                    expected_request_id=request_id,
                )
            except MT5ReadOnlyProtocolError as exc:
                self._terminate_process()

                raise MT5ReadOnlyClientError(
                    "Worker response failed protocol validation"
                ) from exc

            if not response.ok:
                error = response.error or {
                    "code": "INTERNAL_ERROR",
                    "message": (
                        "Read-only worker failed"
                    ),
                }

                raise MT5ReadOnlyRemoteError(
                    error["code"],
                    error["message"],
                )

            return response.result

    def ping(self) -> dict[str, Any]:
        result = self.request(
            "PING",
            {},
        )

        if not isinstance(result, dict):
            raise MT5ReadOnlyClientError(
                "PING result is invalid"
            )

        return result

    def account(self) -> dict[str, Any]:
        result = self.request(
            "ACCOUNT",
            {},
        )

        if not isinstance(result, dict):
            raise MT5ReadOnlyClientError(
                "ACCOUNT result is invalid"
            )

        return result

    def symbol(
        self,
        symbol: str = "XAUUSD",
    ) -> dict[str, Any]:
        result = self.request(
            "SYMBOL",
            {
                "symbol": symbol,
            },
        )

        if not isinstance(result, dict):
            raise MT5ReadOnlyClientError(
                "SYMBOL result is invalid"
            )

        return result

    def candles(
        self,
        timeframe: str,
        count: int,
        *,
        symbol: str = "XAUUSD",
        start_pos: int = 1,
    ) -> list[dict[str, Any]]:
        params = {
            "symbol": symbol,
            "timeframe": timeframe,
            "count": count,
        }

        if start_pos != 1:
            params["start_pos"] = start_pos

        result = self.request(
            "CANDLES",
            params,
        )

        if not isinstance(result, list):
            raise MT5ReadOnlyClientError(
                "CANDLES result is invalid"
            )

        return result

    def positions(self) -> dict[str, Any]:
        result = self.request(
            "POSITIONS",
            {},
        )

        if not isinstance(result, dict):
            raise MT5ReadOnlyClientError(
                "POSITIONS result is invalid"
            )

        return result

    def active_orders(self) -> dict[str, Any]:
        result = self.request(
            "ACTIVE_ORDERS",
            {},
        )

        if not isinstance(result, dict):
            raise MT5ReadOnlyClientError(
                "ACTIVE_ORDERS result is invalid"
            )

        return result

    def history(
        self,
        *,
        from_utc: str,
        to_utc: str,
        limit: int = 100,
        symbol: str = "XAUUSD",
    ) -> list[dict[str, Any]]:
        result = self.request(
            "HISTORY",
            {
                "symbol": symbol,
                "from_utc": from_utc,
                "to_utc": to_utc,
                "limit": limit,
            },
        )

        if not isinstance(result, list):
            raise MT5ReadOnlyClientError(
                "HISTORY result is invalid"
            )

        return result

    def daily_pnl(self) -> dict[str, Any]:
        result = self.request(
            "DAILY_PNL",
            {},
        )

        if not isinstance(result, dict):
            raise MT5ReadOnlyClientError(
                "DAILY_PNL result is invalid"
            )

        return result

    def shutdown(self) -> None:
        if self._closed:
            return

        result = self.request(
            "SHUTDOWN",
            {},
        )

        if result != {
            "shutdown": True,
        }:
            self._terminate_process()
            self._close_pipes()
            self._closed = True

            raise MT5ReadOnlyClientError(
                "Worker shutdown response is invalid"
            )

        try:
            exit_code = self._process.wait(
                timeout=self._timeout_seconds
            )
        except subprocess.TimeoutExpired as exc:
            self._terminate_process()
            self._close_pipes()
            self._closed = True

            raise MT5ReadOnlyClientError(
                "Read-only worker did not stop"
            ) from exc

        self._close_pipes()
        self._closed = True

        if exit_code != 0:
            raise MT5ReadOnlyClientError(
                "Read-only worker exited unsuccessfully: "
                f"{exit_code}"
            )

    def close(self) -> None:
        if self._closed:
            return

        try:
            self.shutdown()
        except Exception:
            self._terminate_process()
            self._close_pipes()
            self._closed = True

    def __enter__(
        self,
    ) -> "MT5ReadOnlyClient":
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        self.close()
