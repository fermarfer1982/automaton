from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import SecurityConfig, load_security_config
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


def _gateway_get(path: str) -> dict[str, object]:
    request = Request(
        GATEWAY_ORIGIN + path,
        headers={"Accept": "application/json"},
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
            ("research_db_outside_workspace", config.research_db_path),
            ("authorization_outside_workspace", config.demo_authorization_path),
            ("kill_switch_outside_workspace", config.kill_switch_path),
        ):
            try:
                outside = not path.resolve().is_relative_to(workspace)
            except OSError:
                outside = False
            checks.append(ReadinessCheck(name, outside, str(path)))

        acl = verify_windows_acl(config_path, config, include_automaton_state=True)
        verified_automaton_sid = acl.automaton_sid
        checks.append(ReadinessCheck("least_privilege_windows_acl", acl.passed, acl.detail))
        if not acl.passed:
            raise PermissionError("Windows ACL separation is not ready")

        try:
            health = _gateway_get("/v1/health")
            market = _gateway_get("/v1/market/XAUUSD")
            metrics = _gateway_get("/v1/research/metrics")
            checks.append(ReadinessCheck("gateway_http", True, "loopback gateway is responding"))
        except Exception as exc:
            checks.append(ReadinessCheck("gateway_http", False, f"{type(exc).__name__}"))
            raise RuntimeError("Loopback gateway is unavailable or invalid") from exc
        checks.append(ReadinessCheck(
            "gateway_runtime_identity",
            health.get("runtime_identity_verified") is True,
            "gateway process SID was verified before MT5 initialization",
        ))
        checks.append(ReadinessCheck(
            "observe_only_gateway",
            health.get("mode") == TradingMode.OBSERVE_ONLY.value,
            f"gateway mode={health.get('mode')}",
        ))
        account_guard = health.get("account_guard", {})
        market_health = health.get("market_data", {})
        exposure = health.get("exposure", {})
        audit = health.get("audit", {})
        research = health.get("research_store", {})
        checks.append(ReadinessCheck(
            "mt5_connection_and_authorized_demo_account",
            bool(health.get("healthy")) and isinstance(account_guard, dict)
            and account_guard.get("allowed") is True,
            "gateway health and exact DEMO account guard",
        ))
        checks.append(ReadinessCheck(
            "xauusd_market_data",
            isinstance(market_health, dict) and market_health.get("available") is True
            and market.get("symbol") == "XAUUSD",
            "live XAUUSD snapshot through the gateway",
        ))
        checks.append(ReadinessCheck(
            "zero_existing_exposure",
            isinstance(exposure, dict) and exposure.get("clear") is True,
            "no positions or active orders",
        ))
        checks.append(ReadinessCheck(
            "audit_chain",
            isinstance(audit, dict) and audit.get("valid") is True,
            "hash chain valid",
        ))
        checks.append(ReadinessCheck(
            "structured_research_memory",
            isinstance(research, dict) and research.get("available") is True
            and metrics.get("minimum_evidence_sample") == 30,
            "research database and evidence threshold",
        ))
    except Exception as exc:
        checks.append(ReadinessCheck("live_integration", False, f"{type(exc).__name__}: {exc}"))

    if run_tests:
        completed = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
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
        workspace = Path(__file__).resolve().parents[1]
        pnpm = shutil.which("pnpm")
        node_dependencies = (workspace / "node_modules").is_dir() and pnpm is not None
        checks.append(
            ReadinessCheck(
                "automaton_dependencies",
                node_dependencies,
                "pnpm dependencies present" if node_dependencies else "node_modules not installed",
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
    ready = bool(checks) and all(check.passed for check in checks)
    return {
        "AUTOMATON_MT5_LAB_READY": ready,
        "required_mode": TradingMode.OBSERVE_ONLY.value,
        "checks": [asdict(check) for check in checks],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the OBSERVE_ONLY MT5 laboratory milestone")
    parser.add_argument(
        "--config",
        default=os.environ.get(
            "AUTOMATON_MT5_SECURITY_CONFIG",
            r"C:\ProgramData\AutomatonMT5Lab\control\security.json",
        ),
    )
    args = parser.parse_args()
    report = run_readiness(args.config)
    print(json.dumps(report, indent=2))
    print(f"AUTOMATON_MT5_LAB_READY={str(report['AUTOMATON_MT5_LAB_READY']).lower()}")
    raise SystemExit(0 if report["AUTOMATON_MT5_LAB_READY"] else 1)


if __name__ == "__main__":
    main()
