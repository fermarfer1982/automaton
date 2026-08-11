from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .api_auth import ApiKeyVerifier
from .config import SecurityConfig, load_security_config, security_config_hash
from .domain import TradingMode
from .windows_acl import verify_windows_acl


GATEWAY_ORIGIN = "http://127.0.0.1:8765"
MAX_GATEWAY_RESPONSE_BYTES = 1_000_000
AUTOMATON_STATUS_MAX_AGE_SECONDS = 15 * 60


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    passed: bool
    detail: str


def _gateway_get(path: str, api_key: str) -> dict[str, object]:
    request = Request(
        GATEWAY_ORIGIN + path,
        headers={
            "Accept": "application/json",
            "X-AUTOMATON-KEY": api_key,
        },
        method="GET",
    )
    with build_opener(_NoRedirect()).open(request, timeout=5) as response:
        length = int(response.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_GATEWAY_RESPONSE_BYTES:
            raise RuntimeError("Gateway response size is invalid")
        body = response.read(MAX_GATEWAY_RESPONSE_BYTES + 1)
        if len(body) > MAX_GATEWAY_RESPONSE_BYTES:
            raise RuntimeError("Gateway response exceeds safety limit")
        payload = json.loads(body)
        if response.status != 200 or not isinstance(payload, dict):
            raise RuntimeError("Gateway response is invalid")
        return payload


def _gateway_rejects_unauthenticated(path: str = "/v1/health") -> bool:
    request = Request(
        GATEWAY_ORIGIN + path,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=5):
            return False
    except HTTPError as exc:
        try:
            return exc.code == 401
        finally:
            exc.close()


def _contains_protected_response_key(value: object) -> bool:
    forbidden = {
        "login", "server", "password", "credential", "credentials",
        "api_key", "apikey", "secret", "terminal_path", "mt5_terminal_path",
    }
    if isinstance(value, dict):
        return any(
            str(key).lower() in forbidden or _contains_protected_response_key(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_protected_response_key(item) for item in value)
    return False


def _fresh_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value)
        if timestamp.tzinfo is None:
            return False
        age = (datetime.now(UTC) - timestamp.astimezone(UTC)).total_seconds()
        return -30 <= age <= AUTOMATON_STATUS_MAX_AGE_SECONDS
    except ValueError:
        return False


def _past_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value)
        if timestamp.tzinfo is None:
            return False
        return (datetime.now(UTC) - timestamp.astimezone(UTC)).total_seconds() >= -30
    except ValueError:
        return False


def run_readiness(config_path: str | Path, *, run_tests: bool = True) -> dict[str, object]:
    checks: list[ReadinessCheck] = []
    config: SecurityConfig | None = None
    verified_automaton_sid: str | None = None
    mt5_connected = False
    demo_verified = False
    account_allowed = False
    server_allowed = False
    xauusd_available = False
    gateway_healthy = False
    audit_ready = False
    try:
        config = load_security_config(config_path)
        checks.append(ReadinessCheck("security_config", True, "valid schema without credentials"))
        checks.append(
            ReadinessCheck(
                "observe_only_mode",
                config.trading_mode is TradingMode.OBSERVE_ONLY,
                f"mode={config.trading_mode.value}",
            )
        )
        checks.append(
            ReadinessCheck(
                "terminal_path",
                config.mt5_terminal_path.is_file(),
                "configured terminal path exists" if config.mt5_terminal_path.is_file() else "terminal path missing",
            )
        )
        workspace = Path(__file__).resolve().parents[1]
        for name, path in (
            ("audit_outside_workspace", config.audit_path),
            ("audit_db_outside_workspace", config.audit_db_path),
            ("research_db_outside_workspace", config.research_db_path),
            ("api_key_outside_workspace", config.api_key_path),
            ("gateway_lock_outside_workspace", config.gateway_lock_path),
            ("logs_outside_workspace", config.log_dir),
            ("authorization_outside_workspace", config.demo_authorization_path),
            ("kill_switch_outside_workspace", config.kill_switch_path),
        ):
            try:
                outside = path is not None and not path.resolve().is_relative_to(workspace)
            except (AttributeError, OSError):
                outside = False
            checks.append(ReadinessCheck(name, outside, str(path)))

        acl = verify_windows_acl(config_path, config, include_automaton_state=True)
        verified_automaton_sid = acl.automaton_sid
        checks.append(ReadinessCheck("least_privilege_windows_acl", acl.passed, acl.detail))
        if not acl.passed:
            raise PermissionError("Windows ACL separation is not ready")

        if config.api_key_path is None:
            raise RuntimeError("Protected gateway API key path is missing")
        verifier = ApiKeyVerifier(config.api_key_path)
        api_key = config.api_key_path.read_text(encoding="ascii")
        if not verifier.verify(api_key):
            raise RuntimeError("Protected gateway API key is invalid")
        checks.append(
            ReadinessCheck(
                "gateway_api_key",
                True,
                "external protected IPC key validated without disclosure",
            )
        )

        try:
            if not _gateway_rejects_unauthenticated():
                raise RuntimeError("Gateway accepted an unauthenticated /v1 request")
            health = _gateway_get("/v1/health", api_key)
            status = _gateway_get("/v1/status", api_key)
            account = _gateway_get("/v1/account", api_key)
            market = _gateway_get("/v1/market/XAUUSD", api_key)
            positions = _gateway_get("/v1/positions", api_key)
            daily = _gateway_get("/v1/daily-stats", api_key)
            metrics = _gateway_get("/v1/research/metrics", api_key)
            memory = _gateway_get("/v1/research/memory?limit=1", api_key)
            candle_payloads = {
                timeframe: _gateway_get(
                    f"/v1/candles/XAUUSD?{urlencode({'timeframe': timeframe, 'count': 20})}",
                    api_key,
                )
                for timeframe in ("M1", "M5", "M15", "H1")
            }
            end = datetime.now(UTC)
            history_query = urlencode({
                "from": (end - timedelta(days=1)).isoformat(),
                "to": end.isoformat(),
                "symbol": "XAUUSD",
                "limit": 1000,
            })
            history = _gateway_get(f"/v1/history?{history_query}", api_key)
            checks.append(
                ReadinessCheck(
                    "gateway_authenticated_http",
                    True,
                    "missing key was rejected and all required authenticated /v1 routes responded",
                )
            )
        except Exception as exc:
            checks.append(
                ReadinessCheck("gateway_authenticated_http", False, f"{type(exc).__name__}")
            )
            raise RuntimeError("Loopback gateway is unavailable or invalid") from exc
        checks.append(ReadinessCheck(
            "gateway_runtime_identity",
            health.get("runtime_identity_verified") is True,
            "gateway process SID was verified before MT5 initialization",
        ))
        checks.append(ReadinessCheck(
            "sanitized_gateway_responses",
            not _contains_protected_response_key(account)
            and not _contains_protected_response_key(status),
            "account/status contain no protected identifiers or secret fields",
        ))
        checks.append(ReadinessCheck(
            "observe_only_gateway",
            health.get("mode") == TradingMode.OBSERVE_ONLY.value
            and status.get("mode") == TradingMode.OBSERVE_ONLY.value
            and status.get("trading_enabled") is False,
            f"gateway mode={health.get('mode')}; trading_enabled={status.get('trading_enabled')}",
        ))
        account_guard = health.get("account_guard", {})
        market_health = health.get("market_data", {})
        exposure = health.get("exposure", {})
        audit = health.get("audit", {})
        research = health.get("research_store", {})
        mt5_connected = account.get("connected") is True
        demo_verified = account.get("demo_verified") is True
        account_allowed = account.get("account_allowed") is True
        server_allowed = account.get("server_allowed") is True
        xauusd_available = (
            isinstance(market_health, dict)
            and market_health.get("available") is True
            and market.get("symbol") == "XAUUSD"
        )
        gateway_healthy = health.get("healthy") is True
        audit_ready = isinstance(audit, dict) and audit.get("valid") is True
        checks.append(ReadinessCheck(
            "mt5_connection_and_authorized_demo_account",
            bool(health.get("healthy")) and isinstance(account_guard, dict)
            and account_guard.get("allowed") is True
            and account.get("connected") is True
            and account.get("demo_verified") is True
            and account.get("account_allowed") is True
            and account.get("server_allowed") is True,
            "gateway health and exact DEMO account guard",
        ))
        checks.append(ReadinessCheck(
            "xauusd_market_data",
            isinstance(market_health, dict) and market_health.get("available") is True
            and market.get("symbol") == "XAUUSD",
            "live XAUUSD snapshot through the gateway",
        ))
        checks.append(ReadinessCheck(
            "closed_candles_all_timeframes",
            all(
                payload.get("symbol") == "XAUUSD"
                and payload.get("timeframe") == timeframe
                and payload.get("closed_only") is True
                and isinstance(payload.get("count"), int)
                and int(payload["count"]) >= 15
                for timeframe, payload in candle_payloads.items()
            ),
            "closed M1/M5/M15/H1 candles are available",
        ))
        session = market.get("session", {})
        checks.append(ReadinessCheck(
            "market_session_timezone_data",
            isinstance(session, dict) and session.get("available") is True,
            "IANA market session calculation is available",
        ))
        checks.append(ReadinessCheck(
            "zero_existing_exposure",
            isinstance(exposure, dict) and exposure.get("clear") is True,
            "no positions or active orders",
        ))
        checks.append(ReadinessCheck(
            "account_queries",
            positions.get("count") == 0
            and isinstance(history.get("deals"), list)
            and daily.get("currency") == account.get("currency"),
            "positions, bounded history and daily account data are available",
        ))
        checks.append(ReadinessCheck(
            "audit_chain",
            isinstance(audit, dict) and audit.get("valid") is True,
            "hash chain valid",
        ))
        checks.append(ReadinessCheck(
            "structured_research_memory",
            isinstance(research, dict) and research.get("available") is True
            and metrics.get("minimum_evidence_sample") == 30
            and isinstance(memory.get("items"), list),
            "research database and evidence threshold",
        ))
    except Exception as exc:
        checks.append(ReadinessCheck("live_integration", False, f"{type(exc).__name__}: {exc}"))

    if run_tests:
        dependency_modules = {
            "fastapi": "FastAPI",
            "pydantic": "Pydantic",
            "uvicorn": "Uvicorn",
            "pytest": "pytest",
            "MetaTrader5": "MetaTrader5",
            "yaml": "PyYAML",
            "tzdata": "tzdata",
        }
        missing_modules = [
            label for module, label in dependency_modules.items()
            if importlib.util.find_spec(module) is None
        ]
        checks.append(ReadinessCheck(
            "gateway_dependencies",
            not missing_modules,
            "all fixed gateway/runtime dependencies present"
            if not missing_modules else f"missing: {', '.join(missing_modules)}",
        ))
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        checks.append(
            ReadinessCheck(
                "security_tests",
                completed.returncode == 0,
                "all tests passed" if completed.returncode == 0 else "test suite failed",
            )
        )
        risk_completed = subprocess.run(
            [
                sys.executable, "-m", "pytest", "-q",
                "tests/test_risk_engine.py",
                "tests/test_position_sizer.py",
                "tests/test_position_management.py",
            ],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        checks.append(
            ReadinessCheck(
                "risk_tests",
                risk_completed.returncode == 0,
                "deterministic risk tests passed"
                if risk_completed.returncode == 0 else "risk test suite failed",
            )
        )
        workspace = Path(__file__).resolve().parents[1]
        pnpm = shutil.which("pnpm")
        pnpm_reviewed = False
        if pnpm is not None:
            try:
                version = subprocess.run(
                    [pnpm, "--version"], capture_output=True, text=True,
                    timeout=15, check=False,
                )
                pnpm_reviewed = version.returncode == 0 and version.stdout.strip() == "10.28.1"
            except (OSError, subprocess.TimeoutExpired):
                pnpm_reviewed = False
        node_dependencies = (
            (workspace / "node_modules").is_dir()
            and pnpm is not None
            and pnpm_reviewed
        )
        checks.append(
            ReadinessCheck(
                "automaton_dependencies",
                node_dependencies,
                "pnpm 10.28.1 dependencies present"
                if node_dependencies else "reviewed pnpm/node_modules unavailable",
            )
        )
        if node_dependencies and pnpm is not None:
            for name, command, timeout in (
                ("automaton_typecheck", [pnpm, "typecheck"], 180),
                ("automaton_build", [pnpm, "build"], 180),
                ("automaton_tests", [pnpm, "test"], 300),
            ):
                completed = subprocess.run(
                    command,
                    cwd=workspace,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                checks.append(
                    ReadinessCheck(
                        name,
                        completed.returncode == 0,
                        "passed" if completed.returncode == 0 else "failed",
                    )
                )
        automaton_dir = (
            config.automaton_state_dir if config is not None
            else Path.home() / ".automaton"
        )
        config_exists = (automaton_dir / "automaton.json").is_file()
        identity_path = automaton_dir / "trading-lab-identity.json"
        identity_exists = identity_path.is_file()
        identity_safe = False
        if identity_exists:
            try:
                identity_payload = json.loads(identity_path.read_text(encoding="utf-8"))
                identity_safe = (
                    isinstance(identity_payload, dict)
                    and set(identity_payload) == {"schemaVersion", "address", "createdAt"}
                    and identity_payload.get("schemaVersion") == 1
                    and isinstance(identity_payload.get("address"), str)
                    and re.fullmatch(r"0x[a-f0-9]{40}", identity_payload["address"]) is not None
                )
            except (OSError, ValueError, TypeError, AttributeError):
                identity_safe = False
        checks.append(
            ReadinessCheck(
                "automaton_external_identity",
                config_exists and identity_exists and identity_safe,
                "external config and non-signing public identity present"
                if config_exists and identity_exists and identity_safe
                else "Automaton config/non-signing identity not initialized",
            )
        )
        signing_wallet_absent = not (automaton_dir / "wallet.json").exists()
        checks.append(
            ReadinessCheck(
                "automaton_signing_wallet_absent",
                signing_wallet_absent,
                "no signing wallet is accessible to the laboratory identity"
                if signing_wallet_absent else "signing wallet exists in the laboratory profile",
            )
        )
        lab_policy_ok = False
        inference_ready = False
        if config_exists:
            try:
                automaton_config = json.loads(
                    (automaton_dir / "automaton.json").read_text(encoding="utf-8")
                )
                if not isinstance(automaton_config, dict):
                    raise ValueError("Automaton config root must be an object")
                treasury = automaton_config.get("treasuryPolicy", {})
                zero_treasury = all(
                    value == 0
                    for key, value in treasury.items()
                    if key != "x402AllowedDomains"
                ) and treasury.get("x402AllowedDomains") == []
                no_stored_provider_secrets = not any(
                    automaton_config.get(key)
                    for key in ("conwayApiKey", "openaiApiKey", "anthropicApiKey")
                )
                lab_policy_ok = (
                    automaton_config.get("registeredWithConway") is False
                    and automaton_config.get("maxChildren") == 0
                    and not automaton_config.get("socialRelayUrl")
                    and automaton_config.get("tradingLabProvider") in {"openai", "anthropic", "ollama"}
                    and Path(str(automaton_config.get("tradingLabStateDir", ""))).resolve()
                    == config.automaton_state_dir.resolve()
                    and automaton_config.get("tradingLabWindowsSid") == verified_automaton_sid
                    and zero_treasury
                    and no_stored_provider_secrets
                )
                provider = automaton_config.get("tradingLabProvider")
                provider_config_safe = provider in {"openai", "anthropic"}
                if provider == "ollama":
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(str(os.environ.get("OLLAMA_BASE_URL") or automaton_config.get("ollamaBaseUrl", "")))
                        provider_config_safe = (
                            parsed.scheme == "http"
                            and parsed.hostname in {"127.0.0.1", "::1"}
                            and not parsed.username
                            and not parsed.password
                            and parsed.path in {"", "/"}
                            and not parsed.query
                            and not parsed.fragment
                        )
                    except ValueError:
                        provider_config_safe = False
                status_path = automaton_dir / "trading-lab-runtime-status.json"
                runtime_status_ready = False
                try:
                    status = json.loads(status_path.read_text(encoding="utf-8"))
                    allowed_status_fields = {
                        "schemaVersion", "profile", "runtimeWindowsSid", "provider",
                        "model", "runtimeInstanceId", "processStartedAt",
                        "lastTurnAt", "lastInferenceAt", "lastGatewayHealthAt",
                        "lastMarketObservationAt", "lastResearchReviewAt", "lastProposalAt",
                    }
                    runtime_status_ready = (
                        isinstance(status, dict)
                        and set(status).issubset(allowed_status_fields)
                        and status.get("schemaVersion") == 1
                        and status.get("profile") == "trading_lab"
                        and status.get("runtimeWindowsSid") == verified_automaton_sid
                        and status.get("provider") == provider
                        and status.get("model") == automaton_config.get("inferenceModel")
                        and isinstance(status.get("runtimeInstanceId"), str)
                        and re.fullmatch(
                            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                            status["runtimeInstanceId"],
                        ) is not None
                        and _past_timestamp(status.get("processStartedAt"))
                        and _fresh_timestamp(status.get("lastTurnAt"))
                        and _fresh_timestamp(status.get("lastInferenceAt"))
                        and _fresh_timestamp(status.get("lastGatewayHealthAt"))
                        and _fresh_timestamp(status.get("lastMarketObservationAt"))
                        and _fresh_timestamp(status.get("lastResearchReviewAt"))
                    )
                except (OSError, ValueError, TypeError, AttributeError):
                    runtime_status_ready = False
                inference_ready = provider_config_safe and runtime_status_ready
            except (OSError, ValueError, TypeError, AttributeError):
                lab_policy_ok = False
                inference_ready = False
        checks.append(
            ReadinessCheck(
                "automaton_lab_policy",
                lab_policy_ok,
                "zero treasury, no registration/social/replication, no stored provider secrets"
                if lab_policy_ok else "Automaton lab policy is absent or unsafe",
            )
        )
        checks.append(
            ReadinessCheck(
                "automaton_inference_provider",
                inference_ready,
                "fresh Automaton inference plus guarded gateway/market tool evidence"
                if inference_ready else "fresh Automaton/provider/gateway tool evidence unavailable",
            )
        )
    else:
        checks.append(
            ReadinessCheck(
                "security_tests",
                False,
                "security tests were not run; readiness cannot be asserted",
            )
        )
        checks.append(
            ReadinessCheck(
                "risk_tests",
                False,
                "risk tests were not run; readiness cannot be asserted",
            )
        )
    ready = bool(checks) and all(check.passed for check in checks)
    by_name = {check.name: check.passed for check in checks}
    security_tests = by_name.get("security_tests", False)
    risk_tests = by_name.get("risk_tests", False)
    tools_ready = all(
        by_name.get(name, False)
        for name in (
            "gateway_authenticated_http",
            "automaton_dependencies",
            "automaton_typecheck",
            "automaton_build",
            "automaton_tests",
            "automaton_lab_policy",
            "automaton_inference_provider",
        )
    )
    return {
        "AUTOMATON_MT5_LAB_READY": ready,
        "MT5_CONNECTED": mt5_connected,
        "DEMO_VERIFIED": demo_verified,
        "ACCOUNT_ALLOWED": account_allowed,
        "SERVER_ALLOWED": server_allowed,
        "XAUUSD_AVAILABLE": xauusd_available,
        "GATEWAY_HEALTH": gateway_healthy,
        "AUTOMATON_TOOLS_READY": tools_ready,
        "AUDIT_READY": audit_ready,
        "RISK_TESTS": risk_tests,
        "SECURITY_TESTS": security_tests,
        "SECURITY_CONFIG_SHA256": security_config_hash(config) if config is not None else None,
        "TRADING_MODE": (
            TradingMode.OBSERVE_ONLY.value
            if by_name.get("observe_only_mode", False)
            and by_name.get("observe_only_gateway", False)
            else "UNVERIFIED"
        ),
        "required_mode": TradingMode.OBSERVE_ONLY.value,
        "checks": [asdict(check) for check in checks],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the OBSERVE_ONLY MT5 laboratory milestone")
    parser.add_argument(
        "--config",
        default=os.environ.get(
            "AUTOMATON_MT5_SECURITY_CONFIG",
            r"C:\ProgramData\AutomatonMT5Lab\control\trading.yaml",
        ),
    )
    parser.add_argument(
        "--output",
        help="Optional absolute external path for the sanitized readiness artifact",
    )
    args = parser.parse_args()
    report = run_readiness(args.config)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        workspace = Path(__file__).resolve().parents[1]
        try:
            safe = (
                output.is_absolute()
                and not output.resolve().is_relative_to(workspace)
                and not output.is_symlink()
            )
        except OSError:
            safe = False
        if not safe:
            raise SystemExit("Readiness output must be an absolute non-symlink path outside the workspace")
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(f"{output.name}.{os.getpid()}.tmp")
        temporary.write_text(encoded, encoding="utf-8", newline="\n")
        temporary.replace(output)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        digest_path = output.with_name(f"{output.name}.sha256")
        digest_path.write_text(f"{digest}  {output.name}\n", encoding="ascii", newline="\n")
    print(encoded, end="")
    print(f"AUTOMATON_MT5_LAB_READY={str(report['AUTOMATON_MT5_LAB_READY']).lower()}")
    raise SystemExit(0 if report["AUTOMATON_MT5_LAB_READY"] else 1)


if __name__ == "__main__":
    main()
