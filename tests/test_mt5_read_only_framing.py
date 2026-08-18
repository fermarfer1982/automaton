from __future__ import annotations

from io import BytesIO

import pytest

from trading_lab.mt5_read_only_framing import (
    MT5ReadOnlyFramingError,
    read_frame,
    write_frame,
)


def test_frame_round_trip():
    stream = BytesIO()

    payload = b'{"request_id":"abc"}'

    write_frame(
        stream,
        payload,
        max_payload_bytes=1024,
    )

    stream.seek(0)

    assert read_frame(
        stream,
        max_payload_bytes=1024,
    ) == payload


def test_clean_eof_is_not_an_error():
    assert read_frame(
        BytesIO(b""),
        max_payload_bytes=100,
    ) is None


def test_zero_length_frame_fails_closed():
    stream = BytesIO(
        (0).to_bytes(4, "big")
    )

    with pytest.raises(
        MT5ReadOnlyFramingError,
        match="Empty IPC frame",
    ):
        read_frame(
            stream,
            max_payload_bytes=100,
        )


def test_oversized_frame_header_fails_before_payload():
    stream = BytesIO(
        (101).to_bytes(4, "big")
    )

    with pytest.raises(
        MT5ReadOnlyFramingError,
        match="size limit",
    ):
        read_frame(
            stream,
            max_payload_bytes=100,
        )


def test_truncated_header_fails_closed():
    stream = BytesIO(b"\x00\x00")

    with pytest.raises(
        MT5ReadOnlyFramingError,
        match="ended unexpectedly",
    ):
        read_frame(
            stream,
            max_payload_bytes=100,
        )


def test_truncated_payload_fails_closed():
    stream = BytesIO(
        (10).to_bytes(4, "big")
        + b"abc"
    )

    with pytest.raises(
        MT5ReadOnlyFramingError,
        match="ended unexpectedly",
    ):
        read_frame(
            stream,
            max_payload_bytes=100,
        )


def test_write_rejects_empty_payload():
    with pytest.raises(
        MT5ReadOnlyFramingError,
        match="Empty IPC frame",
    ):
        write_frame(
            BytesIO(),
            b"",
            max_payload_bytes=100,
        )


def test_write_rejects_oversized_payload():
    with pytest.raises(
        MT5ReadOnlyFramingError,
        match="size limit",
    ):
        write_frame(
            BytesIO(),
            b"x" * 101,
            max_payload_bytes=100,
        )


class ChunkedReader:
    def __init__(
        self,
        raw: bytes,
    ) -> None:
        self._stream = BytesIO(raw)

    def read(
        self,
        size: int,
    ) -> bytes:
        return self._stream.read(
            min(size, 1)
        )


def test_partial_reads_are_handled_exactly():
    payload = b"abcdef"

    raw = (
        len(payload).to_bytes(4, "big")
        + payload
    )

    stream = ChunkedReader(raw)

    assert read_frame(
        stream,
        max_payload_bytes=100,
    ) == payload


class ChunkedWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.flushed = False

    def write(
        self,
        data,
    ) -> int:
        raw = bytes(data)
        piece = raw[:2]

        self.data.extend(piece)

        return len(piece)

    def flush(self) -> None:
        self.flushed = True


def test_partial_writes_are_handled_exactly():
    stream = ChunkedWriter()
    payload = b"abcdef"

    write_frame(
        stream,
        payload,
        max_payload_bytes=100,
    )

    assert bytes(stream.data) == (
        len(payload).to_bytes(4, "big")
        + payload
    )

    assert stream.flushed is True