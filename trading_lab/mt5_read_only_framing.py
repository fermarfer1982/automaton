from __future__ import annotations

from typing import BinaryIO


FRAME_HEADER_BYTES = 4


class MT5ReadOnlyFramingError(RuntimeError):
    pass


def _read_exact(
    stream: BinaryIO,
    size: int,
    *,
    allow_initial_eof: bool,
) -> bytes | None:
    if size < 0:
        raise MT5ReadOnlyFramingError(
            "Negative frame read size"
        )

    chunks: list[bytes] = []
    remaining = size

    while remaining:
        chunk = stream.read(remaining)

        if chunk is None:
            raise MT5ReadOnlyFramingError(
                "IPC stream returned no read result"
            )

        if chunk == b"":
            if allow_initial_eof and not chunks:
                return None

            raise MT5ReadOnlyFramingError(
                "IPC frame ended unexpectedly"
            )

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def read_frame(
    stream: BinaryIO,
    *,
    max_payload_bytes: int,
) -> bytes | None:
    if max_payload_bytes < 1:
        raise MT5ReadOnlyFramingError(
            "Invalid frame size limit"
        )

    header = _read_exact(
        stream,
        FRAME_HEADER_BYTES,
        allow_initial_eof=True,
    )

    if header is None:
        return None

    size = int.from_bytes(
        header,
        byteorder="big",
        signed=False,
    )

    if size < 1:
        raise MT5ReadOnlyFramingError(
            "Empty IPC frame is not permitted"
        )

    if size > max_payload_bytes:
        raise MT5ReadOnlyFramingError(
            "IPC frame exceeds size limit"
        )

    payload = _read_exact(
        stream,
        size,
        allow_initial_eof=False,
    )

    if payload is None:
        raise MT5ReadOnlyFramingError(
            "IPC frame payload is missing"
        )

    return payload


def _write_all(
    stream: BinaryIO,
    data: bytes,
) -> None:
    view = memoryview(data)
    offset = 0

    while offset < len(view):
        written = stream.write(view[offset:])

        if (
            written is None
            or isinstance(written, bool)
            or not isinstance(written, int)
            or written <= 0
        ):
            raise MT5ReadOnlyFramingError(
                "IPC stream write failed"
            )

        offset += written


def write_frame(
    stream: BinaryIO,
    payload: bytes,
    *,
    max_payload_bytes: int,
) -> None:
    if not isinstance(payload, bytes):
        raise MT5ReadOnlyFramingError(
            "IPC payload must be bytes"
        )

    if not payload:
        raise MT5ReadOnlyFramingError(
            "Empty IPC frame is not permitted"
        )

    if len(payload) > max_payload_bytes:
        raise MT5ReadOnlyFramingError(
            "IPC frame exceeds size limit"
        )

    header = len(payload).to_bytes(
        FRAME_HEADER_BYTES,
        byteorder="big",
        signed=False,
    )

    _write_all(stream, header)
    _write_all(stream, payload)

    stream.flush()