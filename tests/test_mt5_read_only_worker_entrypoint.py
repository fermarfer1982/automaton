from __future__ import annotations

from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

from trading_lab.domain import (
    AccountKind,
    AccountSnapshot,
    TradingMode,
)
from trading_lab.mt5_read_only_worker_entrypoint import (
    WORKER_ENTRY_EXIT_SECURITY,
    run_worker,
)
from trading_lab.mt5_read_only_worker_process import (
    WORKER_EXIT_OK,
)


RUN_ID = "11111111-1111-1111-1111-111111111111"


class FakeAdapter:
    def __init__(
        self,
        *,
        login: int = 10012236003,
    ) -> None:
        self.login = login
        self.calls: list[str] = []

    def assert_read_only_boundary(self) -> None:
        self.calls.append(
            "boundary"
        )

    def initialize(self) -> bool:
        self.calls.append(
            "initialize"
        )
        return True

    def account_snapshot(self) -> AccountSnapshot:
        self.calls.append(
            "account"
        )

        return AccountSnapshot(
            login=self.login,
            server="MetaQuotes-Demo",
            kind=AccountKind.DEMO,
            equity=10000.0,
            balance=10000.0,
            connected=True,
            trade_allowed=True,
            terminal_trade_allowed=False,
            currency="EUR",
            account_name="Fernando Martinez",
        )

    def shutdown(self) -> None:
        self.calls.append(
            "shutdown"
        )


def config():
    return SimpleNamespace(
        trading_mode=TradingMode.OBSERVE_ONLY,
        mt5_access_enabled=False,
        mt5_terminal_path=Path(
            r"C:\Program Files\MetaTrader 5\terminal64.exe"
        ),
        authorized_account=10012236003,
        authorized_server="MetaQuotes-Demo",
        authorized_account_name="Fernando Martinez",
    )


def passed_security():
    return {
        "status": "PASS",
        "authorization_valid": True,
        "acl_verified": True,
        "unexpected_capability_called": False,
        "order_check_called": False,
        "order_send_called": False,
    }


def test_worker_runs_only_after_security_pass():
    cfg = config()
    adapter = FakeAdapter()
    events: list[str] = []

    def preflight(
        config_path,
        run_id,
        *,
        config_loader,
    ):
        events.append("preflight")
        assert run_id == RUN_ID
        assert config_loader(config_path) is cfg
        return passed_security()

    def loader(terminal_path):
        events.append("adapter_loader")
        assert (
            terminal_path
            == cfg.mt5_terminal_path
        )
        return adapter

    def server(
        actual_adapter,
        input_stream,
        output_stream,
    ):
        events.append("serve")
        assert actual_adapter is adapter
        return WORKER_EXIT_OK

    result = run_worker(
        Path("trading.yaml"),
        RUN_ID,
        BytesIO(),
        BytesIO(),
        config_loader=lambda _: cfg,
        preflight_runner=preflight,
        adapter_loader=loader,
        stream_server=server,
    )

    assert result == WORKER_EXIT_OK

    assert events == [
        "preflight",
        "adapter_loader",
        "serve",
    ]

    assert adapter.calls == [
        "boundary",
        "initialize",
        "account",
        "shutdown",
    ]


def test_failed_security_never_loads_adapter():
    cfg = config()
    loaded = False

    def preflight(*args, **kwargs):
        return {
            **passed_security(),
            "status": "FAIL",
        }

    def loader(*args, **kwargs):
        nonlocal loaded
        loaded = True
        raise AssertionError(
            "adapter must not load"
        )

    result = run_worker(
        Path("trading.yaml"),
        RUN_ID,
        BytesIO(),
        BytesIO(),
        config_loader=lambda _: cfg,
        preflight_runner=preflight,
        adapter_loader=loader,
    )

    assert result == WORKER_ENTRY_EXIT_SECURITY
    assert loaded is False


def test_account_mismatch_fails_and_shutdowns():
    cfg = config()
    adapter = FakeAdapter(
        login=99999999
    )
    served = False

    def server(*args, **kwargs):
        nonlocal served
        served = True
        return WORKER_EXIT_OK

    result = run_worker(
        Path("trading.yaml"),
        RUN_ID,
        BytesIO(),
        BytesIO(),
        config_loader=lambda _: cfg,
        preflight_runner=(
            lambda *args, **kwargs: passed_security()
        ),
        adapter_loader=lambda _: adapter,
        stream_server=server,
    )

    assert result == WORKER_ENTRY_EXIT_SECURITY
    assert served is False
    assert adapter.calls[-1] == "shutdown"


def test_entrypoint_source_has_no_execution_primitives():
    source = Path(
        r"C:\automaton\trading_lab\mt5_read_only_worker_entrypoint.py"
    ).read_text(
        encoding="utf-8"
    )

    forbidden = (
        ".login(",
        ".symbol_select(",
        ".order_calc_profit(",
        ".order_check(",
        ".order_send(",
        "TRADE_ACTION_",
        "eval(",
        "exec(",
        "__import__",
    )

    for marker in forbidden:
        assert marker not in source
