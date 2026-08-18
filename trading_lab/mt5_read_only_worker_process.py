from __future__ import annotations

from typing import BinaryIO

from .mt5_read_only_framing import (
    MT5ReadOnlyFramingError,
    read_frame,
    write_frame,
)
from .mt5_read_only_protocol import (
    MAX_MESSAGE_BYTES,
    MAX_RESPONSE_BYTES,
    MT5ReadOnlyProtocolError,
    decode_request,
    encode_response,
)
from .mt5_read_only_worker import (
    MT5ReadOnlyWorkerAdapter,
    dispatch_request,
)


WORKER_EXIT_OK = 0
WORKER_EXIT_PROTOCOL = 20
WORKER_EXIT_IO = 21
WORKER_EXIT_INTERNAL = 22


def serve_streams(
    adapter: MT5ReadOnlyWorkerAdapter,
    input_stream: BinaryIO,
    output_stream: BinaryIO,
) -> int:
    while True:
        try:
            raw_request = read_frame(
                input_stream,
                max_payload_bytes=MAX_MESSAGE_BYTES,
            )
        except MT5ReadOnlyFramingError:
            return WORKER_EXIT_PROTOCOL
        except OSError:
            return WORKER_EXIT_IO

        if raw_request is None:
            return WORKER_EXIT_OK

        try:
            request = decode_request(
                raw_request
            )
        except MT5ReadOnlyProtocolError:
            # A malformed request has no trustworthy request_id.
            # Fail closed without fabricating a response.
            return WORKER_EXIT_PROTOCOL

        response, should_shutdown = dispatch_request(
            adapter,
            request,
        )

        try:
            encoded = encode_response(
                response
            )
        except MT5ReadOnlyProtocolError:
            return WORKER_EXIT_INTERNAL

        try:
            write_frame(
                output_stream,
                encoded,
                max_payload_bytes=MAX_RESPONSE_BYTES,
            )
        except MT5ReadOnlyFramingError:
            return WORKER_EXIT_IO
        except OSError:
            return WORKER_EXIT_IO

        if should_shutdown:
            return WORKER_EXIT_OK