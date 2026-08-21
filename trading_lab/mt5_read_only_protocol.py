from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any


PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024

ALLOWED_OPERATIONS = frozenset({
    "PING",
    "ACCOUNT",
    "SYMBOL",
    "CANDLES",
    "POSITIONS",
    "ACTIVE_ORDERS",
    "HISTORY",
    "DAILY_PNL",
    "SHUTDOWN",
})


ALLOWED_ERROR_CODES = frozenset({
    "MT5_UNAVAILABLE",
    "MT5_ERROR",
    "INTERNAL_ERROR",
})


class MT5ReadOnlyProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReadOnlyRequest:
    request_id: str
    operation: str
    params: dict[str, Any]


@dataclass(frozen=True)
class ReadOnlyResponse:
    request_id: str
    ok: bool
    result: Any | None = None
    error: dict[str, str] | None = None


def _require_exact_keys(
    value: dict[str, Any],
    expected: set[str],
    *,
    context: str,
) -> None:
    actual = set(value)

    if actual != expected:
        raise MT5ReadOnlyProtocolError(
            f"{context} keys are not exact"
        )


def _reject_duplicate_object_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise MT5ReadOnlyProtocolError(
                "JSON object contains duplicate keys"
            )

        result[key] = value

    return result


def _reject_non_finite_json(
    value: str,
) -> None:
    raise MT5ReadOnlyProtocolError(
        f"JSON contains non-finite number: {value}"
    )


def _decode_json_message(
    raw: bytes,
    *,
    max_bytes: int,
    kind: str,
) -> object:
    if not raw:
        raise MT5ReadOnlyProtocolError(
            f"Empty {kind}"
        )

    if len(raw) > max_bytes:
        raise MT5ReadOnlyProtocolError(
            f"{kind} exceeds size limit"
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MT5ReadOnlyProtocolError(
            f"{kind} is not valid UTF-8"
        ) from exc

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_pairs,
            parse_constant=_reject_non_finite_json,
        )
    except json.JSONDecodeError as exc:
        raise MT5ReadOnlyProtocolError(
            f"{kind} is not valid JSON"
        ) from exc


def _require_request_id(value: object) -> str:
    if not isinstance(value, str):
        raise MT5ReadOnlyProtocolError(
            "request_id must be a string"
        )

    if not value or len(value) > 128:
        raise MT5ReadOnlyProtocolError(
            "request_id length is invalid"
        )

    return value


def _require_symbol(value: object) -> str:
    if value != "XAUUSD":
        raise MT5ReadOnlyProtocolError(
            "Only XAUUSD is permitted"
        )

    return "XAUUSD"


def _require_utc_timestamp(
    value: object,
    *,
    field_name: str,
) -> datetime:
    if not isinstance(value, str) or not value:
        raise MT5ReadOnlyProtocolError(
            f"{field_name} must be a UTC timestamp"
        )

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise MT5ReadOnlyProtocolError(
            f"{field_name} must be a valid UTC timestamp"
        ) from exc

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
    ):
        raise MT5ReadOnlyProtocolError(
            f"{field_name} must use UTC"
        )

    return parsed.astimezone(UTC)


def _validate_params(
    operation: str,
    params: object,
) -> dict[str, Any]:
    if not isinstance(params, dict):
        raise MT5ReadOnlyProtocolError(
            "params must be an object"
        )

    if operation in {
        "PING",
        "ACCOUNT",
        "POSITIONS",
        "ACTIVE_ORDERS",
        "DAILY_PNL",
        "SHUTDOWN",
    }:
        _require_exact_keys(
            params,
            set(),
            context=operation,
        )
        return {}

    if operation == "SYMBOL":
        _require_exact_keys(
            params,
            {"symbol"},
            context=operation,
        )

        return {
            "symbol": _require_symbol(
                params["symbol"]
            )
        }

    if operation == "CANDLES":
        actual_keys = frozenset(params)
        legacy_keys = frozenset({
            "symbol",
            "timeframe",
            "count",
        })
        paged_keys = frozenset({
            "symbol",
            "timeframe",
            "count",
            "start_pos",
        })

        if actual_keys not in {
            legacy_keys,
            paged_keys,
        }:
            raise MT5ReadOnlyProtocolError(
                "CANDLES keys are not exact"
            )

        symbol = _require_symbol(
            params["symbol"]
        )

        timeframe = params["timeframe"]

        if timeframe not in {
            "M1",
            "M5",
            "M15",
            "H1",
        }:
            raise MT5ReadOnlyProtocolError(
                "Unsupported timeframe"
            )

        count = params["count"]

        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 1
            or count > 500
        ):
            raise MT5ReadOnlyProtocolError(
                "Candle count is invalid"
            )

        result = {
            "symbol": symbol,
            "timeframe": timeframe,
            "count": count,
        }

        if "start_pos" in params:
            start_pos = params["start_pos"]

            if (
                isinstance(start_pos, bool)
                or not isinstance(start_pos, int)
                or start_pos < 1
                or start_pos > 100_000
            ):
                raise MT5ReadOnlyProtocolError(
                    "Candle start_pos is invalid"
                )

            result["start_pos"] = start_pos

        return result

    if operation == "HISTORY":
        _require_exact_keys(
            params,
            {
                "symbol",
                "from_utc",
                "to_utc",
                "limit",
            },
            context=operation,
        )

        symbol = _require_symbol(
            params["symbol"]
        )

        from_utc = _require_utc_timestamp(
            params["from_utc"],
            field_name="from_utc",
        )

        to_utc = _require_utc_timestamp(
            params["to_utc"],
            field_name="to_utc",
        )

        if to_utc <= from_utc:
            raise MT5ReadOnlyProtocolError(
                "History range must increase"
            )

        if to_utc - from_utc > timedelta(days=31):
            raise MT5ReadOnlyProtocolError(
                "History range exceeds 31 days"
            )

        limit = params["limit"]

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
            or limit > 1000
        ):
            raise MT5ReadOnlyProtocolError(
                "History limit is invalid"
            )

        return {
            "symbol": symbol,
            "from_utc": from_utc.isoformat(),
            "to_utc": to_utc.isoformat(),
            "limit": limit,
        }

    raise MT5ReadOnlyProtocolError(
        "Operation is not authorized"
    )


def decode_request(
    raw: bytes,
) -> ReadOnlyRequest:
    payload = _decode_json_message(
        raw,
        max_bytes=MAX_MESSAGE_BYTES,
        kind="IPC message",
    )

    if not isinstance(payload, dict):
        raise MT5ReadOnlyProtocolError(
            "IPC message root must be an object"
        )

    _require_exact_keys(
        payload,
        {
            "protocol_version",
            "request_id",
            "operation",
            "params",
        },
        context="request",
    )

    if payload["protocol_version"] != PROTOCOL_VERSION:
        raise MT5ReadOnlyProtocolError(
            "Unsupported protocol version"
        )

    request_id = _require_request_id(
        payload["request_id"]
    )

    operation = payload["operation"]

    if (
        not isinstance(operation, str)
        or operation not in ALLOWED_OPERATIONS
    ):
        raise MT5ReadOnlyProtocolError(
            "Operation is not authorized"
        )

    params = _validate_params(
        operation,
        payload["params"],
    )

    return ReadOnlyRequest(
        request_id=request_id,
        operation=operation,
        params=params,
    )


def encode_request(
    request: ReadOnlyRequest,
) -> bytes:
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request.request_id,
        "operation": request.operation,
        "params": request.params,
    }

    # Round-trip through the same validator.
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    decode_request(raw)

    if len(raw) > MAX_MESSAGE_BYTES:
        raise MT5ReadOnlyProtocolError(
            "IPC message exceeds size limit"
        )

    return raw


def _validate_error_object(
    value: object,
) -> dict[str, str]:
    if not isinstance(value, dict):
        raise MT5ReadOnlyProtocolError(
            "Response error must be an object"
        )

    _require_exact_keys(
        value,
        {"code", "message"},
        context="response error",
    )

    code = value["code"]
    message = value["message"]

    if (
        not isinstance(code, str)
        or code not in ALLOWED_ERROR_CODES
    ):
        raise MT5ReadOnlyProtocolError(
            "Response error code is not authorized"
        )

    if (
        not isinstance(message, str)
        or not message
        or len(message) > 512
        or "\n" in message
        or "\r" in message
    ):
        raise MT5ReadOnlyProtocolError(
            "Response error message is invalid"
        )

    return {
        "code": code,
        "message": message,
    }


def decode_response(
    raw: bytes,
    *,
    expected_request_id: str | None = None,
) -> ReadOnlyResponse:
    payload = _decode_json_message(
        raw,
        max_bytes=MAX_RESPONSE_BYTES,
        kind="IPC response",
    )

    if not isinstance(payload, dict):
        raise MT5ReadOnlyProtocolError(
            "IPC response root must be an object"
        )

    common_keys = {
        "protocol_version",
        "request_id",
        "ok",
    }

    if not common_keys.issubset(payload):
        raise MT5ReadOnlyProtocolError(
            "IPC response keys are not exact"
        )

    if payload["protocol_version"] != PROTOCOL_VERSION:
        raise MT5ReadOnlyProtocolError(
            "Unsupported protocol version"
        )

    request_id = _require_request_id(
        payload["request_id"]
    )

    if expected_request_id is not None:
        expected = _require_request_id(
            expected_request_id
        )

        if request_id != expected:
            raise MT5ReadOnlyProtocolError(
                "Response request_id mismatch"
            )

    ok = payload["ok"]

    if type(ok) is not bool:
        raise MT5ReadOnlyProtocolError(
            "Response ok must be a boolean"
        )

    if ok:
        _require_exact_keys(
            payload,
            {
                "protocol_version",
                "request_id",
                "ok",
                "result",
            },
            context="successful response",
        )

        return ReadOnlyResponse(
            request_id=request_id,
            ok=True,
            result=payload["result"],
            error=None,
        )

    _require_exact_keys(
        payload,
        {
            "protocol_version",
            "request_id",
            "ok",
            "error",
        },
        context="failed response",
    )

    error = _validate_error_object(
        payload["error"]
    )

    return ReadOnlyResponse(
        request_id=request_id,
        ok=False,
        result=None,
        error=error,
    )


def encode_response(
    response: ReadOnlyResponse,
) -> bytes:
    request_id = _require_request_id(
        response.request_id
    )

    if type(response.ok) is not bool:
        raise MT5ReadOnlyProtocolError(
            "Response ok must be a boolean"
        )

    if response.ok:
        if response.error is not None:
            raise MT5ReadOnlyProtocolError(
                "Successful response cannot contain error"
            )

        payload = {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": True,
            "result": response.result,
        }

    else:
        if response.result is not None:
            raise MT5ReadOnlyProtocolError(
                "Failed response cannot contain result"
            )

        error = _validate_error_object(
            response.error
        )

        payload = {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": False,
            "error": error,
        }

    try:
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MT5ReadOnlyProtocolError(
            "Response is not JSON serializable"
        ) from exc

    decode_response(
        raw,
        expected_request_id=request_id,
    )

    if len(raw) > MAX_RESPONSE_BYTES:
        raise MT5ReadOnlyProtocolError(
            "IPC response exceeds size limit"
        )

    return raw

