from __future__ import annotations

import json
import re
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from typing import Any


OBSERVATION_HOST = "127.0.0.1"
OBSERVATION_PORT = 8766

OBSERVATION_HEADER = (
    "X-AUTOMATON-OBSERVATION-KEY"
)

DEFAULT_OBSERVATION_KEY = Path(
    r"C:\ProgramData\AutomatonMT5Lab"
    r"\ipc\observation.key"
)

_ALLOWED_SYMBOL = "XAUUSD"

_LATEST_CLOSED_M1_TARGET = (
    "/v1/candles/XAUUSD"
    "?timeframe=M1&count=1"
)

_MAX_RESPONSE_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 3.0

_KEY_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{43,128}$"
)


class ObservationHTTPError(RuntimeError):
    pass


def _read_observation_key(
    path: Path,
) -> str:
    try:
        if path.is_symlink():
            raise ObservationHTTPError(
                "Observation credential path cannot be a symlink"
            )

        value = path.read_text(
            encoding="ascii"
        )

    except ObservationHTTPError:
        raise

    except (OSError, UnicodeError) as exc:
        raise ObservationHTTPError(
            "Observation credential is unavailable"
        ) from exc

    if (
        value != value.strip()
        or _KEY_PATTERN.fullmatch(value) is None
    ):
        raise ObservationHTTPError(
            "Observation credential format is invalid"
        )

    return value


def _reject_duplicate_object_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(
                "duplicate JSON key"
            )

        result[key] = value

    return result


def _reject_non_finite_json(
    value: str,
):
    raise ValueError(
        f"non-finite JSON constant: {value}"
    )


def _decode_json_object(
    body: bytes,
) -> dict[str, Any]:
    try:
        text = body.decode("utf-8")

        payload = json.loads(
            text,
            object_pairs_hook=(
                _reject_duplicate_object_pairs
            ),
            parse_constant=(
                _reject_non_finite_json
            ),
        )

    except (
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise ObservationHTTPError(
            "Observation response is not valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise ObservationHTTPError(
            "Observation response root is invalid"
        )

    return payload


class ObservationLatestClosedM1Provider:
    """
    Narrow fail-closed HTTP client for one specific
    Observation Service read.

    Construction performs no filesystem or network I/O.
    The protected credential is read only when a research
    decision actually requires latest-M1 validation.
    """

    def __init__(
        self,
        key_path: str | Path = (
            DEFAULT_OBSERVATION_KEY
        ),
    ) -> None:
        resolved = Path(key_path)

        if not resolved.is_absolute():
            raise ValueError(
                "Observation key path must be absolute"
            )

        self._key_path = resolved

    def latest_closed_m1(
        self,
        symbol: str,
    ) -> dict[str, Any]:
        if symbol != _ALLOWED_SYMBOL:
            raise ValueError(
                "Observation research client permits only XAUUSD"
            )

        key = _read_observation_key(
            self._key_path
        )

        connection = HTTPConnection(
            OBSERVATION_HOST,
            OBSERVATION_PORT,
            timeout=_TIMEOUT_SECONDS,
        )

        try:
            connection.request(
                "GET",
                _LATEST_CLOSED_M1_TARGET,
                body=None,
                headers={
                    "Accept":
                        "application/json",
                    OBSERVATION_HEADER:
                        key,
                },
            )

            response = (
                connection.getresponse()
            )

            if response.status != 200:
                raise ObservationHTTPError(
                    "Observation service returned a non-success status"
                )

            content_type = (
                response.getheader(
                    "Content-Type"
                )
            )

            if (
                not isinstance(
                    content_type,
                    str,
                )
                or content_type
                .split(";", 1)[0]
                .strip()
                .lower()
                != "application/json"
            ):
                raise ObservationHTTPError(
                    "Observation response content type is invalid"
                )

            raw_length = (
                response.getheader(
                    "Content-Length"
                )
            )

            try:
                length = int(
                    raw_length or ""
                )
            except ValueError as exc:
                raise ObservationHTTPError(
                    "Observation response size is invalid"
                ) from exc

            if (
                length <= 0
                or length
                > _MAX_RESPONSE_BYTES
            ):
                raise ObservationHTTPError(
                    "Observation response size is invalid"
                )

            body = response.read(
                _MAX_RESPONSE_BYTES + 1
            )

            if (
                len(body)
                > _MAX_RESPONSE_BYTES
                or len(body) != length
            ):
                raise ObservationHTTPError(
                    "Observation response length is invalid"
                )

        except ObservationHTTPError:
            raise

        except (
            OSError,
            HTTPException,
        ) as exc:
            raise ObservationHTTPError(
                "Observation service is unavailable"
            ) from exc

        finally:
            connection.close()

        payload = _decode_json_object(
            body
        )

        count = payload.get("count")
        candles = payload.get("candles")

        if (
            payload.get("symbol")
            != _ALLOWED_SYMBOL
            or payload.get("timeframe")
            != "M1"
            or isinstance(count, bool)
            or count != 1
            or payload.get(
                "execution_capable"
            )
            is not False
            or not isinstance(
                candles,
                list,
            )
            or len(candles) != 1
        ):
            raise ObservationHTTPError(
                "Observation M1 envelope is invalid"
            )

        candle = candles[0]

        if not isinstance(
            candle,
            dict,
        ):
            raise ObservationHTTPError(
                "Observation M1 candle is invalid"
            )

        time_msc = candle.get(
            "time_msc"
        )

        if (
            candle.get("symbol")
            != _ALLOWED_SYMBOL
            or candle.get("timeframe")
            != "M1"
            or isinstance(
                time_msc,
                bool,
            )
            or not isinstance(
                time_msc,
                int,
            )
            or time_msc <= 0
        ):
            raise ObservationHTTPError(
                "Observation M1 candle identity is invalid"
            )

        return dict(candle)