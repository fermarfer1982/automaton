from __future__ import annotations

import os
import subprocess
import sys
from io import BytesIO
from pathlib import Path

import pytest

from trading_lab.mt5_read_only_client import (
    MT5ReadOnlyClient,
    MT5ReadOnlyRemoteError,
)
from trading_lab.mt5_read_only_framing import (
    read_frame,
    write_frame,
)
from trading_lab.mt5_read_only_protocol import (
    MAX_MESSAGE_BYTES,
    MAX_RESPONSE_BYTES,
    ReadOnlyResponse,
    decode_request,
    encode_response,
)


RUN_ID = "22222222-2222-2222-2222-222222222222"


class NonClosingBytesIO(BytesIO):
    def close(self):
        pass


class FakeProcess:
    def __init__(
        self,
        stdout_data: bytes,
    ) -> None:
        self.stdin = NonClosingBytesIO()
        self.stdout = NonClosingBytesIO(
            stdout_data
        )
        self.stderr = NonClosingBytesIO()
        self.returncode = None
        self.pid = 4321

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


def framed_responses(
    *responses: ReadOnlyResponse,
) -> bytes:
    stream = BytesIO()

    for response in responses:
        write_frame(
            stream,
            encode_response(response),
            max_payload_bytes=MAX_RESPONSE_BYTES,
        )

    return stream.getvalue()


def test_client_ping_and_shutdown(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "TRADING_MODE",
        "OBSERVE_ONLY",
    )
    monkeypatch.setenv(
        "MT5_ACCESS_ENABLED",
        "false",
    )

    stdout = framed_responses(
        ReadOnlyResponse(
            request_id="request-1",
            ok=True,
            result={
                "service": "mt5-read-only-worker",
                "execution_capable": False,
            },
        ),
        ReadOnlyResponse(
            request_id="request-2",
            ok=True,
            result={
                "shutdown": True,
            },
        ),
    )

    fake = FakeProcess(stdout)
    launched = {}

    def factory(command, **kwargs):
        launched["command"] = command
        launched["kwargs"] = kwargs
        return fake

    request_ids = iter([
        "request-1",
        "request-2",
    ])

    client = MT5ReadOnlyClient(
        python_executable=Path(
            sys.executable
        ),
        workspace=tmp_path,
        config_path=(
            tmp_path / "trading.yaml"
        ),
        run_id=RUN_ID,
        process_factory=factory,
        request_id_factory=(
            lambda: next(request_ids)
        ),
    )

    ping = client.ping()

    assert ping == {
        "service": "mt5-read-only-worker",
        "execution_capable": False,
    }

    client.shutdown()

    assert client.closed is True

    command = launched["command"]

    assert command[1:4] == [
        "-B",
        "-m",
        (
            "trading_lab."
            "mt5_read_only_worker_entrypoint"
        ),
    ]

    assert launched["kwargs"]["shell"] is False

    child_env = launched[
        "kwargs"
    ]["env"]

    assert (
        child_env["TRADING_MODE"]
        == "OBSERVE_ONLY"
    )
    assert (
        child_env["MT5_ACCESS_ENABLED"]
        == "false"
    )
    assert (
        child_env["MT5_READ_ONLY_PREFLIGHT"]
        == "true"
    )
    assert (
        child_env["MT5_READ_ONLY_DATA_ACCESS"]
        == "true"
    )

    fake.stdin.seek(0)

    raw_ping = read_frame(
        fake.stdin,
        max_payload_bytes=MAX_MESSAGE_BYTES,
    )
    raw_shutdown = read_frame(
        fake.stdin,
        max_payload_bytes=MAX_MESSAGE_BYTES,
    )

    ping_request = decode_request(
        raw_ping
    )
    shutdown_request = decode_request(
        raw_shutdown
    )

    assert ping_request.operation == "PING"
    assert shutdown_request.operation == "SHUTDOWN"


def test_client_surfaces_sanitized_remote_error(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "TRADING_MODE",
        "OBSERVE_ONLY",
    )
    monkeypatch.setenv(
        "MT5_ACCESS_ENABLED",
        "false",
    )

    stdout = framed_responses(
        ReadOnlyResponse(
            request_id="request-error",
            ok=False,
            error={
                "code": "MT5_ERROR",
                "message": (
                    "Read-only MT5 operation failed"
                ),
            },
        ),
        ReadOnlyResponse(
            request_id="request-shutdown",
            ok=True,
            result={
                "shutdown": True,
            },
        ),
    )

    fake = FakeProcess(stdout)

    request_ids = iter([
        "request-error",
        "request-shutdown",
    ])

    client = MT5ReadOnlyClient(
        python_executable=Path(
            sys.executable
        ),
        workspace=tmp_path,
        config_path=(
            tmp_path / "trading.yaml"
        ),
        run_id=RUN_ID,
        process_factory=(
            lambda *args, **kwargs: fake
        ),
        request_id_factory=(
            lambda: next(request_ids)
        ),
    )

    with pytest.raises(
        MT5ReadOnlyRemoteError
    ) as exc:
        client.account()

    assert exc.value.code == "MT5_ERROR"

    client.shutdown()


def test_client_import_does_not_import_worker_backend():
    workspace = Path(
        r"C:\automaton"
    )

    script = (
        "import sys\n"
        "import trading_lab.mt5_read_only_client\n"
        "names = [\n"
        " 'MetaTrader5',\n"
        " 'trading_lab.mt5_read_only_data',\n"
        " 'trading_lab.mt5_read_only_worker',\n"
        " 'trading_lab.mt5_read_only_worker_process',\n"
        " 'trading_lab.mt5_read_only_worker_entrypoint',\n"
        "]\n"
        "for name in names:\n"
        " print(name + '=' + str(name in sys.modules))\n"
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = str(
        workspace
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"

    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            script,
        ],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )

    assert completed.returncode == 0

    expected = {
        "MetaTrader5=False",
        "trading_lab.mt5_read_only_data=False",
        "trading_lab.mt5_read_only_worker=False",
        (
            "trading_lab."
            "mt5_read_only_worker_process=False"
        ),
        (
            "trading_lab."
            "mt5_read_only_worker_entrypoint=False"
        ),
    }

    assert set(
        completed.stdout.splitlines()
    ) == expected


def test_client_source_has_no_backend_import():
    source = Path(
        r"C:\automaton\trading_lab\mt5_read_only_client.py"
    ).read_text(
        encoding="utf-8"
    )

    forbidden = (
        "from .mt5_read_only_data import",
        "from .mt5_read_only_worker import",
        "from .mt5_read_only_worker_process import",
        "import MetaTrader5",
        "import_module(",
        ".order_check(",
        ".order_send(",
        ".login(",
        "TRADE_ACTION_",
    )

    for marker in forbidden:
        assert marker not in source
