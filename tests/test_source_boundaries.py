from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SourceBoundaryTests(unittest.TestCase):
    def test_automaton_defaults_to_restricted_trading_profile(self) -> None:
        source = (ROOT / "src" / "trading" / "runtime-profile.ts").read_text(encoding="utf-8")
        self.assertIn('return "trading_lab"', source)
        for forbidden in (
            "git_push", "transfer_credits", "topup_credits", "spawn_child",
            "fund_child", "install_npm_package", "install_mcp_server",
            "register_domain", "x402_fetch", "exec", "edit_own_file",
            "set_goal", "complete_goal", "remember_fact", "learn_procedure",
        ):
            self.assertNotRegex(source, re.compile(rf'^\s*"{forbidden}",?\s*$', re.MULTILINE))

    def test_trading_security_code_is_self_modification_protected(self) -> None:
        source = (ROOT / "src" / "self-mod" / "code.ts").read_text(encoding="utf-8")
        self.assertIn('"trading_lab"', source)
        self.assertIn('"trading"', source)
        self.assertIn('"trading.security.json"', source)
        self.assertIn('"trading.example.yaml"', source)
        self.assertIn('"trading.bootstrap-observe-only.yaml"', source)
        for protected in ('"index.ts"', '"agent/loop.ts"', '"config.ts"', '"identity/wallet.ts"'):
            self.assertIn(protected, source)
        self.assertIn('"conway/inference.ts"', source)
        self.assertIn('"scripts/Initialize-TradingLabAcl.ps1"', source)
        self.assertIn('"scripts/Apply-TradingLabAclGate.ps1"', source)
        self.assertIn('"scripts/TradingLabAclBootstrap.ps1"', source)
        self.assertIn('"scripts/New-TradingLabUsers.ps1"', source)
        self.assertIn('"scripts/Test-AgentRuntimeAcl.ps1"', source)
        self.assertIn('"scripts/Test-GatewayRuntimeAcl.ps1"', source)
        self.assertIn('"scripts/Collect-RuntimeAclResults.ps1"', source)
        self.assertIn('"scripts/Install-TradingLabPythonRuntime.ps1"', source)
        self.assertIn('"scripts/Initialize-GatewayPythonEnvironment.ps1"', source)
        self.assertIn('"scripts/Resolve-TradingLabNode.ps1"', source)
        self.assertIn('"docs/SECURITY_INVARIANTS.md"', source)
        self.assertIn('"docs/READINESS_AUDIT.md"', source)
        self.assertIn('"docs/WINDOWS_ACL_MODEL.md"', source)
        self.assertIn('"docs/PYTHON_RUNTIME_MIGRATION.md"', source)
        self.assertIn('"requirements-gateway-win-py314.lock"', source)
        invariants = (ROOT / "docs" / "SECURITY_INVARIANTS.md").read_text(encoding="utf-8")
        for invariant in range(1, 13):
            self.assertIn(f"S{invariant} —", invariants)

    def test_windows_local_identity_uses_native_home_not_root_fallback(self) -> None:
        wallet = (ROOT / "src" / "identity" / "wallet.ts").read_text(encoding="utf-8")
        config = (ROOT / "src" / "config.ts").read_text(encoding="utf-8")
        loop = (ROOT / "src" / "agent" / "loop.ts").read_text(encoding="utf-8")
        self.assertIn("homedir()", wallet)
        self.assertIn("homedir()", config)
        self.assertNotIn('process.env.HOME || "/root"', wallet)
        self.assertNotIn('process.env.HOME || "/root"', config)
        self.assertIn('const runtimeProfile = resolveRuntimeProfile()', config)
        self.assertIn('runtimeProfile === "trading_lab"', config)
        self.assertNotIn("process.env.HOME || process.cwd()", loop)

    def test_trading_profile_blocks_upstream_external_startup_actions(self) -> None:
        index = (ROOT / "src" / "index.ts").read_text(encoding="utf-8")
        loop = (ROOT / "src" / "agent" / "loop.ts").read_text(encoding="utf-8")
        wallet = (ROOT / "src" / "identity" / "wallet.ts").read_text(encoding="utf-8")
        self.assertIn('runtimeProfile === "upstream" && registrationState', index)
        self.assertIn('runtimeProfile === "upstream" && config.socialRelayUrl', index)
        self.assertIn('if (runtimeProfile === "upstream") {\n    try {\n      let bootstrapTimer', index)
        self.assertIn('const heartbeat = runtimeProfile === "upstream"', index)
        self.assertIn('forcedBackend: runtimeProfile === "trading_lab"', index)
        self.assertIn("Signing-wallet initialization is disabled", index)
        self.assertIn("loadTradingLabIdentity()", index)
        self.assertIn("AUTOMATON_STATE_DIR", wallet)
        self.assertIn("tradingLabStateDir", index)
        self.assertIn("getCurrentWindowsIdentityProof()", index)
        self.assertIn("windowsIdentity.isAdministrator", index)
        self.assertIn("Upstream setup is disabled", index)
        self.assertIn("Conway provisioning is disabled", index)
        self.assertIn('if (runtimeProfile === "trading_lab") {\n    // A neutral', loop)
        self.assertIn('if (runtimeProfile === "upstream" && hasTable(db.raw, "goals"))', loop)
        self.assertEqual(2, loop.count("getFinancialState("))

    def test_trading_profile_has_no_orchestration_or_external_model_discovery(self) -> None:
        source = (ROOT / "src" / "trading" / "runtime-profile.ts").read_text(encoding="utf-8")
        for forbidden in (
            "create_goal", "complete_task", "orchestrator_status", "list_models",
            "check_inference_spending",
        ):
            self.assertNotRegex(source, re.compile(rf'^\s*"{forbidden}",?\s*$', re.MULTILINE))
        network = (ROOT / "src" / "trading" / "network.ts").read_text(encoding="utf-8")
        client = (ROOT / "src" / "trading" / "gateway-client.ts").read_text(encoding="utf-8")
        self.assertIn('parsed.hostname === "127.0.0.1"', network)
        self.assertNotIn('parsed.hostname === "localhost"', network)
        self.assertNotIn("process.env.AUTOMATON_MT5_GATEWAY_URL", client)
        self.assertIn('redirect: "error"', client)

    def test_semantic_tool_cannot_supply_volume_magic_account_or_mode(self) -> None:
        source = (ROOT / "src" / "trading" / "tools.ts").read_text(encoding="utf-8")
        proposal = source.split('name: "propose_trade"', 1)[1].split('name: "close_position"', 1)[0]
        for forbidden in ("volume", "magic_number", "authorized_account", "server", "trading_mode"):
            self.assertNotIn(forbidden, proposal)
        auth = (ROOT / "src" / "trading" / "gateway-auth.ts").read_text(encoding="utf-8")
        self.assertIn("AUTOMATON_MT5_API_KEY_FILE", auth)
        self.assertIn("isSymbolicLink", auth)

    def test_mt5_adapter_never_logs_in_or_selects_an_account_or_symbol(self) -> None:
        source = (ROOT / "trading_lab" / "mt5_adapter.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, re.compile(r"\.login\s*\("))
        self.assertNotRegex(source, re.compile(r"symbol_select\s*\("))

    def test_raw_order_send_is_confined_to_mt5_adapter(self) -> None:
        offenders: list[str] = []
        for path in (ROOT / "trading_lab").glob("*.py"):
            if path.name in {"mt5_adapter.py", "execution_engine.py"}:
                continue
            source = path.read_text(encoding="utf-8")
            if re.search(r"\.order_send\s*\(", source):
                offenders.append(path.name)
        self.assertEqual([], offenders)

    def test_raw_order_check_is_confined_to_execution_boundary(self) -> None:
        offenders: list[str] = []
        for path in (ROOT / "trading_lab").glob("*.py"):
            if path.name in {"mt5_adapter.py", "execution_engine.py"}:
                continue
            if re.search(r"\.order_check\s*\(", path.read_text(encoding="utf-8")):
                offenders.append(path.name)
        self.assertEqual([], offenders)

    def test_production_http_transport_is_fastapi_only(self) -> None:
        service = (ROOT / "trading_lab" / "service.py").read_text(encoding="utf-8")
        fastapi_service = (ROOT / "trading_lab" / "fastapi_service.py").read_text(encoding="utf-8")
        self.assertNotIn("HTTPServer", service)
        self.assertNotIn("BaseHTTPRequestHandler", service)
        self.assertIn('host="127.0.0.1"', service)
        self.assertIn('request.url.path.startswith("/v1")', fastapi_service)

    def test_market_provider_facade_has_no_execution_capability(self) -> None:
        source = (ROOT / "trading_lab" / "providers.py").read_text(encoding="utf-8")
        facade = source.split("class LiveMT5MarketDataProvider", 1)[1].split(
            "class MT5ExecutionProvider", 1
        )[0]
        self.assertNotIn("order_check", facade)
        self.assertNotIn("order_send", facade)

    def test_no_credential_fields_exist_in_trade_proposal(self) -> None:
        source = (ROOT / "trading_lab" / "domain.py").read_text(encoding="utf-8").lower()
        proposal_source = source.split("class tradeproposal", 1)[1].split("class ordercheckresult", 1)[0]
        for forbidden in ("password", "credential", "api_key", "private_key"):
            self.assertNotIn(forbidden, proposal_source)

    def test_windows_scripts_pin_supported_node_and_pnpm_runtimes(self) -> None:
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual("^20.18.0 || ^22.0.0", package["engines"]["node"])
        self.assertIn("corepack pnpm@10.28.1 -r build", package["scripts"]["build"])
        workspace = (ROOT / "pnpm-workspace.yaml").read_text(encoding="utf-8")
        self.assertIn("onlyBuiltDependencies:", workspace)
        self.assertIn("  - better-sqlite3", workspace)
        self.assertIn("  - esbuild", workspace)
        resolver = (ROOT / "scripts" / "Resolve-TradingLabNode.ps1").read_text(encoding="utf-8")
        self.assertIn("node-v22.22.0-win-x64", resolver)
        self.assertIn("bae898add4643fcf890a83ad8ae56e20dce7e781cab161a53991ceba70c99ffb", resolver)
        self.assertIn("Get-FileHash", resolver)
        self.assertIn("ReparsePoint", resolver)
        self.assertGreaterEqual(resolver.count("$LASTEXITCODE"), 2)
        for script_name in ("setup.ps1", "test_gateway.ps1"):
            source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
            self.assertIn("Resolve-TradingLabNode.ps1", source)
            self.assertIn("pnpm@10.28.1", source)
            self.assertIn("$LASTEXITCODE", source)
        start = (ROOT / "scripts" / "start_automaton.ps1").read_text(encoding="utf-8")
        self.assertIn("Resolve-TradingLabNode.ps1", start)
        self.assertIn("-FilePath $nodeRuntime.Node", start)

    def test_windows_operator_scripts_check_native_exit_codes(self) -> None:
        for script_name in (
            "disable_trading.ps1",
            "enable_demo_trading.ps1",
            "start_gateway.ps1",
            "status.ps1",
        ):
            source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
            self.assertIn("$LASTEXITCODE", source, script_name)
        start_gateway = (ROOT / "scripts" / "start_gateway.ps1").read_text(encoding="utf-8")
        self.assertLess(start_gateway.index("$LASTEXITCODE"), start_gateway.index("Start-Process"))

    def test_manual_user_provisioning_never_persists_passwords_or_grants_privilege(self) -> None:
        source = (ROOT / "scripts" / "New-TradingLabUsers.ps1").read_text(encoding="utf-8")
        self.assertIn("#Requires -RunAsAdministrator", source)
        self.assertIn("Read-Host", source)
        self.assertIn("-AsSecureString", source)
        self.assertIn("S-1-5-32-545", source)
        self.assertIn("$unexpected.Count -gt 0", source)
        self.assertIn("$password.Length -eq 0", source)
        self.assertIn("-Member $localUser", source)
        self.assertNotIn("-Member $User.SID", source)
        self.assertIn("PrincipalSource.ToString() -ne 'Local'", source)
        descriptions = re.findall(r"Description\s*=\s*'([^']*)'", source)
        self.assertEqual(2, len(descriptions))
        self.assertTrue(all(len(description) <= 48 for description in descriptions))
        self.assertEqual(1, source.count("$definition.Description"))
        self.assertIn("-Description $definition.Description", source)
        self.assertNotIn("ConvertFrom-SecureString", source)
        self.assertNotIn("PasswordNeverExpires:$true", source)
        self.assertNotIn("Add-LocalGroupMember -Name 'Administrators'", source)

    def test_acl_dry_run_reports_explicit_allow_only_matrix(self) -> None:
        source = (ROOT / "scripts" / "Initialize-TradingLabAcl.ps1").read_text(encoding="utf-8")
        self.assertIn("acl_proposals", source)
        self.assertIn("inherited_aces_preserved = $false", source)
        self.assertIn("deny_aces = 0", source)
        self.assertIn("'STOP_TRADING'", source)
        self.assertIn("'demo-authorization'", source)
        self.assertIn("'operational'", source)
        self.assertIn("'research'", source)
        self.assertIn("'sqlite'", source)
        self.assertIn("'journal'", source)
        self.assertIn("'Read,AppendData,Synchronize'", source)
        self.assertIn("sqlite_immutable = $false", source)
        self.assertIn("$protectedSourceDirectories", source)
        self.assertIn("Protected source tree contains a reparse point", source)
        self.assertNotIn("gateway_writable_data", source)
        self.assertNotIn("WriteAllText($killSwitchFile", source)
        self.assertNotIn("WriteAllText($demoAuthorizationFile", source)
        dry_run_exit = source.index("if (-not $Apply)")
        self.assertLess(dry_run_exit, source.index("Initialize-TradingLabBootstrapState"))
        self.assertLess(dry_run_exit, source.index("Set-Acl -LiteralPath"))

    def test_runtime_acl_python_probes_compile_and_preserve_diagnostics(self) -> None:
        gateway = (ROOT / "scripts" / "Test-GatewayRuntimeAcl.ps1").read_text(encoding="utf-8")
        collector = (ROOT / "scripts" / "Collect-RuntimeAclResults.ps1").read_text(encoding="utf-8")
        pattern = re.compile(r"\$(?:\w+Source|source)\s*=\s*@'\n(.*?)\n'@", re.DOTALL)
        gateway_blocks = pattern.findall(gateway)
        collector_blocks = pattern.findall(collector)
        self.assertEqual(6, len(gateway_blocks))
        self.assertEqual(1, len(collector_blocks))
        for index, block in enumerate([*gateway_blocks, *collector_blocks], start=1):
            compile(block, f"<runtime-acl-inline-{index}>", "exec")
        self.assertNotIn("2>&1", gateway)
        self.assertIn("[System.Diagnostics.ProcessStartInfo]::new()", gateway)
        self.assertIn("New-FailureDiagnostic $_", gateway)
        for classification in (
            "TEST_FAILED_EXPECTATION",
            "TEST_INFRASTRUCTURE_ERROR",
            "CRITICAL_UNEXPECTED_ALLOW",
        ):
            self.assertIn(classification, gateway)

    def test_service_python_runtime_never_depends_on_a_user_profile(self) -> None:
        service_files = [
            ROOT / "scripts" / name
            for name in (
                "setup.ps1",
                "start_gateway.ps1",
                "status.ps1",
                "test_gateway.ps1",
                "enable_demo_trading.ps1",
                "disable_trading.ps1",
                "Test-GatewayRuntimeAcl.ps1",
                "Collect-RuntimeAclResults.ps1",
                "Install-TradingLabPythonRuntime.ps1",
                "Initialize-GatewayPythonEnvironment.ps1",
            )
        ]
        user_path = re.compile(r"(?i)[a-z]:\\users\\[^'\"\r\n]+")
        allowed_agent_state = re.compile(
            r"(?i)^c:\\users\\automatonagent\\\.automaton(?:\\|$)"
        )
        allowed_redaction = re.compile(r"(?i)^c:\\users\\\[redacted_profile\]")
        for path in service_files:
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("AppData\\Local\\Programs\\Python", source, path.name)
            for match in user_path.findall(source):
                self.assertTrue(
                    allowed_agent_state.match(match) or allowed_redaction.match(match),
                    f"service runtime dependency under a user profile in {path.name}: {match}",
                )
        installer = (ROOT / "scripts" / "Install-TradingLabPythonRuntime.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("C:\\Program Files\\AutomatonPython\\3.14.5", installer)
        self.assertIn("Assert-OutsideUserProfiles", installer)
        self.assertIn("& $basePython -I -m venv $stagingPath", installer)
        self.assertNotIn("WriteAllText((Join-Path $Root 'pyvenv.cfg')", installer)
        setup = service_files[0].read_text(encoding="utf-8")
        self.assertIn(
            "$machinePython = 'C:\\Program Files\\AutomatonPython\\3.14.5\\python.exe'",
            setup,
        )
        self.assertNotIn("& python -c", setup)
        gateway_start = (ROOT / "scripts" / "start_gateway.ps1").read_text(encoding="utf-8")
        environment = (
            ROOT / "scripts" / "Initialize-GatewayPythonEnvironment.ps1"
        ).read_text(encoding="utf-8")
        self.assertLess(
            gateway_start.index("Initialize-GatewayPythonEnvironment"),
            gateway_start.index("& $python"),
        )
        self.assertIn("AutomatonMT5Lab\\operational", environment)
        self.assertIn("$env:TEMP = $canonicalTemp", environment)
        self.assertIn("$env:TMP = $canonicalTemp", environment)
        self.assertIn("$env:PYTHONDONTWRITEBYTECODE = '1'", environment)
        self.assertNotIn("Windows\\TEMP", environment)

    def test_agent_trading_integration_has_no_direct_programdata_or_mt5_access(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "src" / "trading").glob("*.ts")
        )
        self.assertNotIn("ProgramData", sources)
        self.assertNotIn("AutomatonMT5Lab", sources)
        self.assertNotIn("MetaTrader5", sources)
        self.assertNotIn("DEMO_EXECUTION", (ROOT / "src" / "self-mod" / "code.ts").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
