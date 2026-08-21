from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Protocol


_ALLOWED_SYMBOL = "XAUUSD"

_ALLOWED_TIMEFRAMES = frozenset({
    "M1",
    "M5",
    "M15",
    "H1",
})


class ObservationClient(Protocol):
    def ping(self) -> dict[str, Any]: ...

    def account(self) -> dict[str, Any]: ...

    def symbol(
        self,
        symbol: str = "XAUUSD",
    ) -> dict[str, Any]: ...

    def candles(
        self,
        timeframe: str,
        count: int,
        *,
        symbol: str = "XAUUSD",
        start_pos: int = 1,
    ) -> list[dict[str, Any]]: ...

    def positions(self) -> dict[str, Any]: ...

    def active_orders(self) -> dict[str, Any]: ...

    def history(
        self,
        *,
        from_utc: str,
        to_utc: str,
        limit: int = 100,
        symbol: str = "XAUUSD",
    ) -> list[dict[str, Any]]: ...

    def daily_pnl(self) -> dict[str, Any]: ...


def _require_utc_timestamp(
    value: str,
    *,
    field_name: str,
) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"{field_name} must be a UTC timestamp"
        )

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a valid UTC timestamp"
        ) from exc

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
    ):
        raise ValueError(
            f"{field_name} must use UTC"
        )

    return parsed.astimezone(UTC)


class ObservationApplication:
    """GET-only facade over the isolated MT5 read-only client."""

    def __init__(
        self,
        client: ObservationClient,
        *,
        authorized_account: int,
        authorized_server: str,
        allowed_symbol: str = _ALLOWED_SYMBOL,
    ) -> None:
        if (
            not isinstance(authorized_account, int)
            or isinstance(authorized_account, bool)
            or authorized_account <= 0
        ):
            raise ValueError(
                "Authorized account is invalid"
            )

        if (
            not isinstance(authorized_server, str)
            or not authorized_server.strip()
        ):
            raise ValueError(
                "Authorized server is invalid"
            )

        if allowed_symbol != _ALLOWED_SYMBOL:
            raise ValueError(
                "Observation service permits only XAUUSD"
            )

        self._client = client
        self._authorized_account = authorized_account
        self._authorized_server = authorized_server
        self._allowed_symbol = allowed_symbol

    def _validated_account(
        self,
    ) -> dict[str, Any]:
        account = self._client.account()

        if not isinstance(account, dict):
            raise RuntimeError(
                "Read-only account response is invalid"
            )

        if (
            account.get("login")
            != self._authorized_account
        ):
            raise RuntimeError(
                "Observation account identity mismatch"
            )

        if (
            account.get("server")
            != self._authorized_server
        ):
            raise RuntimeError(
                "Observation server identity mismatch"
            )

        if account.get("kind") != "DEMO":
            raise RuntimeError(
                "Observation account is not DEMO"
            )

        if account.get("connected") is not True:
            raise RuntimeError(
                "Observation account is disconnected"
            )

        if (
            account.get("terminal_trade_allowed")
            is not False
        ):
            raise RuntimeError(
                "Terminal trading must remain disabled"
            )

        return account

    def status(self) -> dict[str, Any]:
        ping = self._client.ping()

        if not isinstance(ping, dict):
            raise RuntimeError(
                "Read-only worker status is invalid"
            )

        if ping.get("execution_capable") is not False:
            raise RuntimeError(
                "Read-only worker boundary is invalid"
            )

        account = self._validated_account()

        return {
            "service":
            "automaton-mt5-observation",
            "mode": "OBSERVE_ONLY",
            "execution_capable": False,
            "allowed_symbol": self._allowed_symbol,
            "worker_execution_capable": False,
            "connected": True,
            "account_kind": account["kind"],
            "terminal_trade_allowed": False,
        }

    def account_state(self) -> dict[str, Any]:
        account = self._validated_account()

        # Account identity is checked but deliberately
        # not returned to Luna.
        return {
            "kind": account["kind"],
            "equity": account.get("equity"),
            "balance": account.get("balance"),
            "connected": True,
            "trade_allowed": account.get(
                "trade_allowed"
            ),
            "terminal_trade_allowed": False,
            "currency": account.get("currency"),
        }

    def symbol_state(
        self,
        symbol: str,
    ) -> dict[str, Any]:
        self._validated_account()

        if symbol != self._allowed_symbol:
            raise ValueError(
                "Only XAUUSD is permitted"
            )

        result = self._client.symbol(symbol)

        if not isinstance(result, dict):
            raise RuntimeError(
                "Read-only symbol response is invalid"
            )

        if result.get("symbol") != self._allowed_symbol:
            raise RuntimeError(
                "Read-only symbol identity mismatch"
            )

        return result

    def candles(
        self,
        symbol: str,
        timeframe: str,
        count: int,
        *,
        start_pos: int = 1,
    ) -> dict[str, Any]:
        self._validated_account()

        if symbol != self._allowed_symbol:
            raise ValueError(
                "Only XAUUSD is permitted"
            )

        if timeframe not in _ALLOWED_TIMEFRAMES:
            raise ValueError(
                "Unsupported observation timeframe"
            )

        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 1 <= count <= 500
        ):
            raise ValueError(
                "Observation candle count is invalid"
            )

        if (
            not isinstance(start_pos, int)
            or isinstance(start_pos, bool)
            or not 1 <= start_pos <= 100_000
        ):
            raise ValueError(
                "Observation candle start_pos is invalid"
            )

        if start_pos == 1:
            rows = self._client.candles(
                timeframe,
                count,
                symbol=symbol,
            )
        else:
            rows = self._client.candles(
                timeframe,
                count,
                symbol=symbol,
                start_pos=start_pos,
            )

        if not isinstance(rows, list):
            raise RuntimeError(
                "Read-only candles response is invalid"
            )

        return {
            "symbol": symbol,
            "timeframe": timeframe,
            "count": len(rows),
            "candles": rows,
            "execution_capable": False,
        }

    def market_snapshot(
        self,
        symbol: str,
    ) -> dict[str, Any]:
        market = self.symbol_state(symbol)

        timeframes: dict[str, Any] = {}

        for timeframe in (
            "M1",
            "M5",
            "M15",
            "H1",
        ):
            timeframes[timeframe] = (
                self.candles(
                    symbol,
                    timeframe,
                    20,
                )["candles"]
            )

        return {
            "symbol": symbol,
            "market": market,
            "timeframes": timeframes,
            "execution_capable": False,
        }

    def positions_state(self) -> dict[str, Any]:
        self._validated_account()

        result = self._client.positions()

        if (
            not isinstance(result, dict)
            or result.get("scope") != "ACCOUNT"
            or not isinstance(
                result.get("positions"),
                list,
            )
        ):
            raise RuntimeError(
                "Read-only positions response is invalid"
            )

        return {
            "scope": "account",
            "positions": result["positions"],
            "execution_capable": False,
        }

    def active_orders_state(
        self,
    ) -> dict[str, Any]:
        self._validated_account()

        result = self._client.active_orders()

        if (
            not isinstance(result, dict)
            or result.get("scope") != "ACCOUNT"
            or not isinstance(
                result.get("orders"),
                list,
            )
        ):
            raise RuntimeError(
                "Read-only active-orders response is invalid"
            )

        return {
            "scope": "account",
            "active_orders": result["orders"],
            "execution_capable": False,
        }

    def history_state(
        self,
        *,
        from_utc: str,
        to_utc: str,
        symbol: str,
        limit: int,
    ) -> dict[str, Any]:
        self._validated_account()

        if symbol != self._allowed_symbol:
            raise ValueError(
                "Only XAUUSD is permitted"
            )

        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 1000
        ):
            raise ValueError(
                "Observation history limit is invalid"
            )

        start = _require_utc_timestamp(
            from_utc,
            field_name="from_utc",
        )

        end = _require_utc_timestamp(
            to_utc,
            field_name="to_utc",
        )

        if end <= start:
            raise ValueError(
                "History range must increase"
            )

        if end - start > timedelta(days=31):
            raise ValueError(
                "History range exceeds 31 days"
            )

        canonical_from = start.isoformat()
        canonical_to = end.isoformat()

        rows = self._client.history(
            from_utc=canonical_from,
            to_utc=canonical_to,
            limit=limit,
            symbol=symbol,
        )

        if not isinstance(rows, list):
            raise RuntimeError(
                "Read-only history response is invalid"
            )

        return {
            "symbol": symbol,
            "from_utc": canonical_from,
            "to_utc": canonical_to,
            "count": len(rows),
            "deals": rows,
            "execution_capable": False,
        }

    def daily_stats(self) -> dict[str, Any]:
        account = self._validated_account()

        result = self._client.daily_pnl()

        if (
            not isinstance(result, dict)
            or result.get("scope") != "ACCOUNT"
        ):
            raise RuntimeError(
                "Read-only daily PnL response is invalid"
            )

        realized = result.get("realized_pnl")

        if not isinstance(
            realized,
            (int, float),
        ) or isinstance(realized, bool):
            raise RuntimeError(
                "Read-only daily PnL value is invalid"
            )

        return {
            "scope": "account",
            "currency": account.get("currency"),
            "realized_pnl": float(realized),
            "execution_capable": False,
        }
