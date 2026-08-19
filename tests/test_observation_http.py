from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from trading_lab.observation_http import (
    OBSERVATION_HEADER,
    OBSERVATION_HOST,
    OBSERVATION_PORT,
    ObservationHTTPError,
    ObservationLatestClosedM1Provider,
)


TEST_KEY = "O" * 43


def valid_payload(
    *,
    time_msc: int = 1_700_000_000_000,
):
    return {
        "symbol": "XAUUSD",
        "timeframe": "M1",
        "count": 1,
        "candles": [
            {
                "symbol": "XAUUSD",
                "timeframe": "M1",
                "time_msc": time_msc,
                "open": 2400.0,
                "high": 2401.0,
                "low": 2399.0,
                "close": 2400.5,
                "tick_volume": 100,
                "spread": 20,
            }
        ],
        "execution_capable": False,
    }


class FakeResponse:
    def __init__(
        self,
        payload,
        *,
        status: int = 200,
        content_type: str = (
            "application/json"
        ),
        declared_length: int | None = None,
    ) -> None:
        if isinstance(payload, bytes):
            self.body = payload
        else:
            self.body = json.dumps(
                payload,
                separators=(",", ":"),
            ).encode("utf-8")

        self.status = status
        self._headers = {
            "Content-Type":
                content_type,
            "Content-Length":
                str(
                    len(self.body)
                    if declared_length is None
                    else declared_length
                ),
        }

    def getheader(
        self,
        name: str,
    ):
        return self._headers.get(
            name
        )

    def read(
        self,
        size: int = -1,
    ) -> bytes:
        if size < 0:
            return self.body

        return self.body[:size]


class ObservationHTTPProviderTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temp = (
            tempfile.TemporaryDirectory()
        )

        self.key_path = (
            Path(self.temp.name)
            / "observation.key"
        )

        self.key_path.write_text(
            TEST_KEY,
            encoding="ascii",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def provider(self):
        return (
            ObservationLatestClosedM1Provider(
                self.key_path
            )
        )

    @patch(
        "trading_lab.observation_http.HTTPConnection"
    )
    def test_exact_loopback_get_returns_latest_m1(
        self,
        connection_class,
    ) -> None:
        connection = Mock()

        connection.getresponse.return_value = (
            FakeResponse(
                valid_payload()
            )
        )

        connection_class.return_value = (
            connection
        )

        result = (
            self.provider()
            .latest_closed_m1(
                "XAUUSD"
            )
        )

        connection_class.assert_called_once_with(
            OBSERVATION_HOST,
            OBSERVATION_PORT,
            timeout=3.0,
        )

        connection.request.assert_called_once_with(
            "GET",
            (
                "/v1/candles/XAUUSD"
                "?timeframe=M1&count=1"
            ),
            body=None,
            headers={
                "Accept":
                    "application/json",
                OBSERVATION_HEADER:
                    TEST_KEY,
            },
        )

        connection.close.assert_called_once()

        self.assertEqual(
            "XAUUSD",
            result["symbol"],
        )

        self.assertEqual(
            "M1",
            result["timeframe"],
        )

        self.assertEqual(
            1_700_000_000_000,
            result["time_msc"],
        )

    @patch(
        "trading_lab.observation_http.HTTPConnection"
    )
    def test_constructor_is_lazy_and_missing_key_fails_only_on_use(
        self,
        connection_class,
    ) -> None:
        missing = (
            Path(self.temp.name)
            / "missing.key"
        )

        provider = (
            ObservationLatestClosedM1Provider(
                missing
            )
        )

        connection_class.assert_not_called()

        with self.assertRaisesRegex(
            ObservationHTTPError,
            "credential is unavailable",
        ):
            provider.latest_closed_m1(
                "XAUUSD"
            )

        connection_class.assert_not_called()

    @patch(
        "trading_lab.observation_http.HTTPConnection"
    )
    def test_wrong_symbol_is_rejected_before_credential_or_network(
        self,
        connection_class,
    ) -> None:
        self.key_path.unlink()

        with self.assertRaisesRegex(
            ValueError,
            "only XAUUSD",
        ):
            self.provider().latest_closed_m1(
                "EURUSD"
            )

        connection_class.assert_not_called()

    @patch(
        "trading_lab.observation_http.HTTPConnection"
    )
    def test_redirect_status_fails_closed_and_is_not_followed(
        self,
        connection_class,
    ) -> None:
        connection = Mock()

        connection.getresponse.return_value = (
            FakeResponse(
                valid_payload(),
                status=302,
            )
        )

        connection_class.return_value = (
            connection
        )

        with self.assertRaisesRegex(
            ObservationHTTPError,
            "non-success status",
        ):
            self.provider().latest_closed_m1(
                "XAUUSD"
            )

        self.assertEqual(
            1,
            connection.request.call_count,
        )

        connection.close.assert_called_once()

    @patch(
        "trading_lab.observation_http.HTTPConnection"
    )
    def test_execution_capable_response_is_rejected(
        self,
        connection_class,
    ) -> None:
        payload = valid_payload()
        payload[
            "execution_capable"
        ] = True

        connection = Mock()

        connection.getresponse.return_value = (
            FakeResponse(payload)
        )

        connection_class.return_value = (
            connection
        )

        with self.assertRaisesRegex(
            ObservationHTTPError,
            "envelope is invalid",
        ):
            self.provider().latest_closed_m1(
                "XAUUSD"
            )

    @patch(
        "trading_lab.observation_http.HTTPConnection"
    )
    def test_wrong_identity_is_rejected(
        self,
        connection_class,
    ) -> None:
        payload = valid_payload()

        payload["candles"][0][
            "timeframe"
        ] = "M5"

        connection = Mock()

        connection.getresponse.return_value = (
            FakeResponse(payload)
        )

        connection_class.return_value = (
            connection
        )

        with self.assertRaisesRegex(
            ObservationHTTPError,
            "candle identity is invalid",
        ):
            self.provider().latest_closed_m1(
                "XAUUSD"
            )

    @patch(
        "trading_lab.observation_http.HTTPConnection"
    )
    def test_oversized_response_is_rejected_before_body_parse(
        self,
        connection_class,
    ) -> None:
        connection = Mock()

        connection.getresponse.return_value = (
            FakeResponse(
                valid_payload(),
                declared_length=(
                    64 * 1024 + 1
                ),
            )
        )

        connection_class.return_value = (
            connection
        )

        with self.assertRaisesRegex(
            ObservationHTTPError,
            "size is invalid",
        ):
            self.provider().latest_closed_m1(
                "XAUUSD"
            )

    @patch(
        "trading_lab.observation_http.HTTPConnection"
    )
    def test_non_json_response_is_rejected(
        self,
        connection_class,
    ) -> None:
        connection = Mock()

        connection.getresponse.return_value = (
            FakeResponse(
                b"not-json",
                content_type=(
                    "text/plain"
                ),
            )
        )

        connection_class.return_value = (
            connection
        )

        with self.assertRaisesRegex(
            ObservationHTTPError,
            "content type is invalid",
        ):
            self.provider().latest_closed_m1(
                "XAUUSD"
            )

    def test_service_wires_provider_only_inside_health_only_branch(
        self,
    ) -> None:
        root = (
            Path(__file__)
            .resolve()
            .parents[1]
        )

        source = (
            root
            / "trading_lab"
            / "service.py"
        ).read_text(
            encoding="utf-8"
        )

        branch = source.index(
            "if health_only:"
        )

        lazy_import = source.index(
            (
                "from .observation_http "
                "import ("
            ),
            branch,
        )

        builder = source.index(
            "build_health_only_application(",
            branch,
        )

        provider = source.index(
            (
                "ObservationLatestClosedM1Provider()"
            ),
            builder,
        )

        full_mode = source.index(
            "else:",
            builder,
        )

        self.assertLess(
            branch,
            lazy_import,
        )

        self.assertLess(
            lazy_import,
            builder,
        )

        self.assertLess(
            builder,
            provider,
        )

        self.assertLess(
            provider,
            full_mode,
        )

        prefix = source[:branch]

        self.assertNotIn(
            "observation_http",
            prefix,
        )


if __name__ == "__main__":
    unittest.main()