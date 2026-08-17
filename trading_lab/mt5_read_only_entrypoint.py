from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

from .mt5_read_only import execute_mt5_read_only_preflight


def _canonical_run_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError("run-id must be a UUID") from exc
    canonical = str(parsed)
    if value.casefold() != canonical:
        raise argparse.ArgumentTypeError("run-id must use canonical UUID form")
    return canonical


def main() -> None:
    parser = argparse.ArgumentParser(
        description="One-shot fail-closed MT5 read-only identity preflight"
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run-id", required=True, type=_canonical_run_id)
    args = parser.parse_args()

    if os.environ.get("TRADING_MODE") != "OBSERVE_ONLY":
        parser.error("TRADING_MODE must be exactly OBSERVE_ONLY")
    if os.environ.get("MT5_ACCESS_ENABLED") != "false":
        parser.error("MT5_ACCESS_ENABLED must remain exactly false for this diagnostic")
    if os.environ.get("MT5_READ_ONLY_PREFLIGHT") != "true":
        parser.error("MT5_READ_ONLY_PREFLIGHT must be explicitly true")

    report = execute_mt5_read_only_preflight(args.config, args.run_id)
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
