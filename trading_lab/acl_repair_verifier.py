from __future__ import annotations

import json
import sys
from pathlib import Path

from .config import load_mt5_security_config
from .domain import TradingMode
from .windows_acl import verify_windows_acl


CONFIG_PATH = Path(r"C:\ProgramData\AutomatonMT5Lab\control\trading.yaml")


def verify_repaired_acl() -> dict[str, object]:
    config = load_mt5_security_config(CONFIG_PATH)
    if config.trading_mode is not TradingMode.OBSERVE_ONLY:
        raise RuntimeError("ACL repair verification requires OBSERVE_ONLY")
    if config.mt5_access_enabled:
        raise RuntimeError("ACL repair verification requires MT5 access disabled")
    without_agent = verify_windows_acl(
        CONFIG_PATH,
        config,
        include_automaton_state=False,
        require_current_gateway=False,
    )
    with_agent = verify_windows_acl(
        CONFIG_PATH,
        config,
        include_automaton_state=True,
        require_current_gateway=False,
    )
    mt5_imported = "MetaTrader5" in sys.modules
    passed = without_agent.passed and with_agent.passed and not mt5_imported
    return {
        "status": "PASS" if passed else "FAIL_CLOSED",
        "without_automaton_state": {
            "passed": without_agent.passed,
            "detail": without_agent.detail,
        },
        "with_automaton_state": {
            "passed": with_agent.passed,
            "detail": with_agent.detail,
        },
        "mt5_imported": mt5_imported,
        "mt5_accessed": False,
    }


def main() -> int:
    try:
        result = verify_repaired_acl()
    except Exception as exc:  # fail closed with a bounded, non-secret diagnostic
        result = {
            "status": "FAIL_CLOSED",
            "error_type": type(exc).__name__,
            "error": str(exc)[:2048],
            "mt5_imported": "MetaTrader5" in sys.modules,
            "mt5_accessed": False,
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
