from __future__ import annotations

import json

import pytest

from trading_lab.mt5_read_only_protocol import (
    ALLOWED_ERROR_CODES,
    ALLOWED_OPERATIONS,
    MAX_MESSAGE_BYTES,
    MAX_RESPONSE_BYTES,
    MT5ReadOnlyProtocolError,
    PROTOCOL_VERSION,
    ReadOnlyRequest,
    ReadOnlyResponse,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)


def raw_request(
    operation: str,
    params: dict,
    *,
    request_id: str = "test-1",
    protocol_version: int = PROTOCOL_VERSION,
) -> bytes:
    return json.dumps({
        "protocol_version": protocol_version,
        "request_id": request_id,
        "operation": operation,
        "params": params,
    }).encode("utf-8")


def test_allowed_operations_are_exact():
    assert ALLOWED_OPERATIONS == {
        "PING",
        "ACCOUNT",
        "SYMBOL",
        "CANDLES",
        "POSITIONS",
        "ACTIVE_ORDERS",
        "HISTORY",
        "DAILY_PNL",
        "SHUTDOWN",
    }

    assert "ORDER_CHECK" not in ALLOWED_OPERATIONS
    assert "ORDER_SEND" not in ALLOWED_OPERATIONS
    assert "LOGIN" not in ALLOWED_OPERATIONS
    assert "CALL_METHOD" not in ALLOWED_OPERATIONS


@pytest.mark.parametrize(
    "operation",
    [
        "ORDER_CHECK",
        "ORDER_SEND",
        "LOGIN",
        "SYMBOL_SELECT",
        "CALL_METHOD",
        "EXEC",
        "EVAL",
        "IMPORT",
    ],
)
def test_forbidden_operations_fail_closed(
    operation: str,
):
    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="not authorized",
    ):
        decode_request(
            raw_request(
                operation,
                {},
            )
        )


def test_unknown_top_level_field_fails_closed():
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": "test",
        "operation": "PING",
        "params": {},
        "method": "order_send",
    }

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="keys are not exact",
    ):
        decode_request(
            json.dumps(payload).encode()
        )


def test_ping_requires_empty_params():
    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="keys are not exact",
    ):
        decode_request(
            raw_request(
                "PING",
                {"method": "order_send"},
            )
        )


def test_symbol_is_exact_xauusd():
    request = decode_request(
        raw_request(
            "SYMBOL",
            {"symbol": "XAUUSD"},
        )
    )

    assert request.params == {
        "symbol": "XAUUSD"
    }

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="Only XAUUSD",
    ):
        decode_request(
            raw_request(
                "SYMBOL",
                {"symbol": "EURUSD"},
            )
        )


@pytest.mark.parametrize(
    ("timeframe", "count"),
    [
        ("M1", 1),
        ("M5", 100),
        ("M15", 500),
        ("H1", 20),
    ],
)
def test_candle_request_accepts_reviewed_bounds(
    timeframe: str,
    count: int,
):
    request = decode_request(
        raw_request(
            "CANDLES",
            {
                "symbol": "XAUUSD",
                "timeframe": timeframe,
                "count": count,
            },
        )
    )

    assert request.params["timeframe"] == timeframe
    assert request.params["count"] == count


@pytest.mark.parametrize(
    ("timeframe", "count"),
    [
        ("M2", 10),
        ("M1", 0),
        ("M1", 501),
        ("M1", True),
    ],
)
def test_candle_request_rejects_invalid_bounds(
    timeframe,
    count,
):
    with pytest.raises(
        MT5ReadOnlyProtocolError,
    ):
        decode_request(
            raw_request(
                "CANDLES",
                {
                    "symbol": "XAUUSD",
                    "timeframe": timeframe,
                    "count": count,
                },
            )
        )


def test_history_request_is_structurally_bounded():
    request = decode_request(
        raw_request(
            "HISTORY",
            {
                "symbol": "XAUUSD",
                "from_utc": "2026-08-17T00:00:00+00:00",
                "to_utc": "2026-08-18T00:00:00+00:00",
                "limit": 1000,
            },
        )
    )

    assert request.params["symbol"] == "XAUUSD"
    assert request.params["limit"] == 1000


@pytest.mark.parametrize(
    "limit",
    [0, 1001, True],
)
def test_history_limit_fails_closed(limit):
    with pytest.raises(
        MT5ReadOnlyProtocolError,
    ):
        decode_request(
            raw_request(
                "HISTORY",
                {
                    "symbol": "XAUUSD",
                    "from_utc": "2026-08-17T00:00:00+00:00",
                    "to_utc": "2026-08-18T00:00:00+00:00",
                    "limit": limit,
                },
            )
        )


def test_protocol_version_must_be_exact():
    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="protocol version",
    ):
        decode_request(
            raw_request(
                "PING",
                {},
                protocol_version=2,
            )
        )


def test_oversized_message_fails_closed():
    raw = b"x" * (
        MAX_MESSAGE_BYTES + 1
    )

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="size limit",
    ):
        decode_request(raw)


def test_encode_round_trip():
    original = ReadOnlyRequest(
        request_id="abc-123",
        operation="CANDLES",
        params={
            "symbol": "XAUUSD",
            "timeframe": "M5",
            "count": 100,
        },
    )

    raw = encode_request(original)
    decoded = decode_request(raw)

    assert decoded == original


def test_injection_shaped_fields_are_rejected():
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": "inject",
        "operation": "CANDLES",
        "params": {
            "symbol": "XAUUSD",
            "timeframe": "M1",
            "count": 1,
            "method": "order_send",
        },
    }

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="keys are not exact",
    ):
        decode_request(
            json.dumps(payload).encode()
        )

@pytest.mark.parametrize(
    "timestamp",
    [
        "not-a-date",
        "2026-08-18T10:00:00",
        "2026-08-18T10:00:00+02:00",
    ],
)
def test_history_timestamp_requires_exact_utc(
    timestamp: str,
):
    with pytest.raises(
        MT5ReadOnlyProtocolError,
    ):
        decode_request(
            raw_request(
                "HISTORY",
                {
                    "symbol": "XAUUSD",
                    "from_utc": timestamp,
                    "to_utc": "2026-08-18T12:00:00+00:00",
                    "limit": 100,
                },
            )
        )


@pytest.mark.parametrize(
    ("from_utc", "to_utc"),
    [
        (
            "2026-08-18T10:00:00+00:00",
            "2026-08-18T10:00:00+00:00",
        ),
        (
            "2026-08-18T11:00:00+00:00",
            "2026-08-18T10:00:00+00:00",
        ),
    ],
)
def test_history_range_must_increase(
    from_utc: str,
    to_utc: str,
):
    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="must increase",
    ):
        decode_request(
            raw_request(
                "HISTORY",
                {
                    "symbol": "XAUUSD",
                    "from_utc": from_utc,
                    "to_utc": to_utc,
                    "limit": 100,
                },
            )
        )


def test_history_range_cannot_exceed_31_days():
    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="exceeds 31 days",
    ):
        decode_request(
            raw_request(
                "HISTORY",
                {
                    "symbol": "XAUUSD",
                    "from_utc": "2026-07-01T00:00:00+00:00",
                    "to_utc": "2026-08-02T00:00:00+00:00",
                    "limit": 100,
                },
            )
        )


def test_history_exactly_31_days_is_allowed():
    request = decode_request(
        raw_request(
            "HISTORY",
            {
                "symbol": "XAUUSD",
                "from_utc": "2026-07-18T00:00:00Z",
                "to_utc": "2026-08-18T00:00:00Z",
                "limit": 100,
            },
        )
    )

    assert request.params == {
        "symbol": "XAUUSD",
        "from_utc": "2026-07-18T00:00:00+00:00",
        "to_utc": "2026-08-18T00:00:00+00:00",
        "limit": 100,
    }


def test_success_response_round_trip():
    original = ReadOnlyResponse(
        request_id="response-1",
        ok=True,
        result={
            "symbol": "XAUUSD",
            "bid": 3333.25,
        },
    )

    raw = encode_response(original)

    decoded = decode_response(
        raw,
        expected_request_id="response-1",
    )

    assert decoded == original


def test_error_response_round_trip():
    original = ReadOnlyResponse(
        request_id="response-2",
        ok=False,
        error={
            "code": "MT5_ERROR",
            "message": "Read-only MT5 operation failed",
        },
    )

    raw = encode_response(original)

    decoded = decode_response(
        raw,
        expected_request_id="response-2",
    )

    assert decoded == original


def test_response_request_id_must_match():
    raw = encode_response(
        ReadOnlyResponse(
            request_id="correct-id",
            ok=True,
            result={},
        )
    )

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="request_id mismatch",
    ):
        decode_response(
            raw,
            expected_request_id="wrong-id",
        )


def test_success_response_rejects_error_field():
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": "response-3",
        "ok": True,
        "result": {},
        "error": {
            "code": "MT5_ERROR",
            "message": "must not be here",
        },
    }

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="keys are not exact",
    ):
        decode_response(
            json.dumps(payload).encode()
        )


def test_failed_response_rejects_result_field():
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": "response-4",
        "ok": False,
        "result": {},
        "error": {
            "code": "MT5_ERROR",
            "message": "failure",
        },
    }

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="keys are not exact",
    ):
        decode_response(
            json.dumps(payload).encode()
        )


def test_response_ok_must_be_boolean():
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": "response-5",
        "ok": 1,
        "result": {},
    }

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="must be a boolean",
    ):
        decode_response(
            json.dumps(payload).encode()
        )


def test_response_error_code_is_closed():
    assert ALLOWED_ERROR_CODES == {
        "MT5_UNAVAILABLE",
        "MT5_ERROR",
        "INTERNAL_ERROR",
    }

    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": "response-6",
        "ok": False,
        "error": {
            "code": "ORDER_SEND",
            "message": "not authorized",
        },
    }

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="code is not authorized",
    ):
        decode_response(
            json.dumps(payload).encode()
        )


@pytest.mark.parametrize(
    "message",
    [
        "",
        "line one\nline two",
        "x" * 513,
    ],
)
def test_response_error_message_is_bounded(
    message: str,
):
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": "response-7",
        "ok": False,
        "error": {
            "code": "MT5_ERROR",
            "message": message,
        },
    }

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="message is invalid",
    ):
        decode_response(
            json.dumps(payload).encode()
        )


def test_response_size_is_bounded():
    raw = b"x" * (
        MAX_RESPONSE_BYTES + 1
    )

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="size limit",
    ):
        decode_response(raw)


def test_request_rejects_duplicate_keys():
    raw = (
        b'{"protocol_version":1,'
        b'"request_id":"one",'
        b'"request_id":"two",'
        b'"operation":"PING",'
        b'"params":{}}'
    )

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="duplicate keys",
    ):
        decode_request(raw)


def test_response_rejects_duplicate_keys():
    raw = (
        b'{"protocol_version":1,'
        b'"request_id":"one",'
        b'"request_id":"two",'
        b'"ok":true,'
        b'"result":{}}'
    )

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="duplicate keys",
    ):
        decode_response(raw)


def test_request_rejects_non_finite_json():
    raw = (
        b'{"protocol_version":1,'
        b'"request_id":"nan-request",'
        b'"operation":"PING",'
        b'"params":{"value":NaN}}'
    )

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="non-finite",
    ):
        decode_request(raw)


def test_response_rejects_non_finite_json():
    raw = (
        b'{"protocol_version":1,'
        b'"request_id":"nan-response",'
        b'"ok":true,'
        b'"result":{"value":NaN}}'
    )

    with pytest.raises(
        MT5ReadOnlyProtocolError,
        match="non-finite",
    ):
        decode_response(raw)

