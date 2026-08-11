from __future__ import annotations

import argparse
import json
import math
import os
import re
from dataclasses import asdict
from enum import Enum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .config import load_security_config
from .domain import Side, TradeProposal
from .factory import build_application
from .mt5_adapter import MT5Adapter
from .windows_acl import verify_windows_acl


MAX_REQUEST_BYTES = 64 * 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROPOSAL_FIELDS = {
    "proposal_id", "hypothesis_id", "strategy_id", "setup_id", "strategy_version",
    "symbol", "side", "volume", "stop_loss", "take_profit", "magic_number",
    "position_management", "thesis", "session", "market_regime",
}


class ProposalValidationError(ValueError):
    pass


def _json_default(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _identifier(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProposalValidationError(f"{key} is invalid")
    return value


def _finite_number(payload: dict[str, Any], key: str, *, optional: bool = False) -> float | None:
    value = payload.get(key)
    if optional and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProposalValidationError(f"{key} must be numeric")
    number = float(value)
    if not math.isfinite(number):
        raise ProposalValidationError(f"{key} must be finite")
    return number


def parse_proposal(payload: Any) -> TradeProposal:
    if not isinstance(payload, dict):
        raise ProposalValidationError("Proposal must be a JSON object")
    if set(payload) != _PROPOSAL_FIELDS:
        unknown = sorted(set(payload) - _PROPOSAL_FIELDS)
        missing = sorted(_PROPOSAL_FIELDS - set(payload))
        raise ProposalValidationError(f"Proposal schema mismatch; unknown={unknown}, missing={missing}")
    try:
        side = Side(payload["side"])
    except (KeyError, ValueError) as exc:
        raise ProposalValidationError("side must be BUY or SELL") from exc
    if payload["symbol"] != "XAUUSD":
        raise ProposalValidationError("symbol must be exact XAUUSD")
    thesis = payload["thesis"]
    if not isinstance(thesis, str) or not thesis.strip() or len(thesis) > 4000:
        raise ProposalValidationError("thesis must contain 1..4000 characters")
    management = payload["position_management"]
    if not isinstance(management, str) or len(management) > 64:
        raise ProposalValidationError("position_management is invalid")
    magic = payload["magic_number"]
    if isinstance(magic, bool) or not isinstance(magic, int):
        raise ProposalValidationError("magic_number must be an integer")
    return TradeProposal(
        proposal_id=_identifier(payload, "proposal_id"),
        hypothesis_id=_identifier(payload, "hypothesis_id"),
        strategy_id=_identifier(payload, "strategy_id"),
        setup_id=_identifier(payload, "setup_id"),
        strategy_version=_identifier(payload, "strategy_version"),
        symbol="XAUUSD",
        side=side,
        volume=float(_finite_number(payload, "volume")),
        stop_loss=_finite_number(payload, "stop_loss", optional=True),
        take_profit=_finite_number(payload, "take_profit", optional=True),
        magic_number=magic,
        position_management=management,
        thesis=thesis.strip(),
        session=_identifier(payload, "session"),
        market_regime=_identifier(payload, "market_regime"),
    )


class _Handler(BaseHTTPRequestHandler):
    server_version = "AutomatonMT5Gateway/0.1"

    @property
    def app(self):
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        # HTTP access logs can contain untrusted input; durable domain audit is used instead.
        return

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _discard_small_body(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return
        if 0 < length <= MAX_REQUEST_BYTES:
            self.rfile.read(length)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/v1/health":
                self._json(HTTPStatus.OK, self.app.health())
                return
            if path == "/v1/research/metrics":
                self._json(HTTPStatus.OK, self.app.research_metrics())
                return
            prefix = "/v1/market/"
            if path.startswith(prefix):
                symbol = unquote(path[len(prefix):])
                self._json(HTTPStatus.OK, self.app.market_snapshot(symbol))
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        except Exception as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "fail_closed", "error_type": type(exc).__name__},
            )

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/v1/proposals":
            self._discard_small_body()
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_size"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            proposal = parse_proposal(payload)
            result = self.app.submit(proposal)
            self._json(HTTPStatus.OK, asdict(result))
        except (json.JSONDecodeError, ProposalValidationError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_proposal", "detail": str(exc)})
        except Exception as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "fail_closed", "error_type": type(exc).__name__},
            )


def create_server(app, port: int = 8765) -> ThreadingHTTPServer:
    if not 1024 <= port <= 65535:
        if port != 0:
            raise ValueError("port must be 0 for testing or between 1024 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    server.app = app  # type: ignore[attr-defined]
    return server


def serve(config_path: str | Path, port: int = 8765) -> None:
    config = load_security_config(config_path)
    acl = verify_windows_acl(
        config_path,
        config,
        include_automaton_state=False,
        require_current_gateway=True,
    )
    if not acl.passed:
        raise PermissionError(f"Gateway ACL verification failed: {acl.detail}")
    adapter = MT5Adapter(config.mt5_terminal_path)
    if not adapter.initialize():
        raise RuntimeError("MT5 initialization failed")
    app = build_application(config, adapter, runtime_identity_verified=True)
    server = create_server(app, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        adapter.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed local Automaton MT5 gateway")
    parser.add_argument(
        "--config",
        default=os.environ.get(
            "AUTOMATON_MT5_SECURITY_CONFIG",
            r"C:\ProgramData\AutomatonMT5Lab\control\security.json",
        ),
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    serve(args.config, args.port)


if __name__ == "__main__":
    main()
