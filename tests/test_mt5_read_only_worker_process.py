from __future__ import annotations

from io import BytesIO
from pathlib import Path

from trading_lab.mt5_read_only_framing import (
    read_frame,
    write_frame,
)
from trading_lab.mt5_read_only_protocol import (
    MAX_MESSAGE_BYTES,
    MAX_RESPONSE_BYTES,
    ReadOnlyRequest,
    decode_response,
    encode_request,
)
from trading_lab.mt5_read_only_worker_process import (
    WORKER_EXIT_OK,
    WORKER_EXIT_PROTOCOL,
    serve_streams,
)


class NoCallAdapter:
    def __getattr__(self, name):
        raise AssertionError(
            f"Adapter must not be called: {name}"
        )


def add_request(
    stream: BytesIO,
    request: ReadOnlyRequest,
) -> None:
    write_frame(
        stream,
        encode_request(request),
        max_payload_bytes=MAX_MESSAGE_BYTES,
    )


def test_ping_then_shutdown_over_framed_stream():
    input_stream = BytesIO()

    add_request(
        input_stream,
        ReadOnlyRequest(
            request_id="ping-1",
            operation="PING",
            params={},
        ),
    )

    add_request(
        input_stream,
        ReadOnlyRequest(
            request_id="shutdown-1",
            operation="SHUTDOWN",
            params={},
        ),
    )

    input_stream.seek(0)
    output_stream = BytesIO()

    exit_code = serve_streams(
        NoCallAdapter(),
        input_stream,
        output_stream,
    )

    assert exit_code == WORKER_EXIT_OK

    output_stream.seek(0)

    ping_raw = read_frame(
        output_stream,
        max_payload_bytes=MAX_RESPONSE_BYTES,
    )

    ping = decode_response(
        ping_raw,
        expected_request_id="ping-1",
    )

    assert ping.ok is True
    assert ping.result == {
        "service": "mt5-read-only-worker",
        "execution_capable": False,
    }

    shutdown_raw = read_frame(
        output_stream,
        max_payload_bytes=MAX_RESPONSE_BYTES,
    )

    shutdown = decode_response(
        shutdown_raw,
        expected_request_id="shutdown-1",
    )

    assert shutdown.ok is True
    assert shutdown.result == {
        "shutdown": True,
    }

    assert read_frame(
        output_stream,
        max_payload_bytes=MAX_RESPONSE_BYTES,
    ) is None


def test_malformed_protocol_terminates_without_response():
    input_stream = BytesIO()
    output_stream = BytesIO()

    malformed = (
        b'{"protocol_version":1,'
        b'"request_id":"bad",'
        b'"operation":"ORDER_SEND",'
        b'"params":{}}'
    )

    write_frame(
        input_stream,
        malformed,
        max_payload_bytes=MAX_MESSAGE_BYTES,
    )

    input_stream.seek(0)

    exit_code = serve_streams(
        NoCallAdapter(),
        input_stream,
        output_stream,
    )

    assert exit_code == WORKER_EXIT_PROTOCOL
    assert output_stream.getvalue() == b""


def test_invalid_frame_terminates_without_response():
    oversized_length = (
        MAX_MESSAGE_BYTES + 1
    ).to_bytes(4, "big")

    input_stream = BytesIO(
        oversized_length
    )
    output_stream = BytesIO()

    exit_code = serve_streams(
        NoCallAdapter(),
        input_stream,
        output_stream,
    )

    assert exit_code == WORKER_EXIT_PROTOCOL
    assert output_stream.getvalue() == b""


def test_process_source_has_no_execution_surface():
    source = Path(
        r"C:\automaton\trading_lab\mt5_read_only_worker_process.py"
    ).read_text(
        encoding="utf-8"
    )

    forbidden = (
        "getattr(",
        "setattr(",
        "eval(",
        "exec(",
        "__import__",
        "import_module",
        "MetaTrader5",
        ".login(",
        ".symbol_select(",
        ".order_calc_profit(",
        ".order_check(",
        ".order_send(",
        "TRADE_ACTION_",
        "subprocess",
        "Popen",
    )

    for marker in forbidden:
        assert marker not in source


def test_process_has_only_reviewed_pipeline():
    source = Path(
        r"C:\automaton\trading_lab\mt5_read_only_worker_process.py"
    ).read_text(
        encoding="utf-8"
    )

    required = (
        "read_frame(",
        "decode_request(",
        "dispatch_request(",
        "encode_response(",
        "write_frame(",
    )

    for marker in required:
        assert source.count(marker) == 1