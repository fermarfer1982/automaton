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
        self.assertIn('"scripts/Test-PythonBaseOnlyRuntimeAcl.ps1"', source)
        self.assertIn('"scripts/Collect-RuntimeAclResults.ps1"', source)
        self.assertIn('"scripts/Install-TradingLabPythonRuntime.ps1"', source)
        self.assertIn('"scripts/TradingLabPythonInventory.ps1"', source)
        self.assertIn('"scripts/TradingLabBuildVenvGate.ps1"', source)
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
        base_only = (ROOT / "scripts" / "Test-PythonBaseOnlyRuntimeAcl.ps1").read_text(
            encoding="utf-8"
        )
        collector = (ROOT / "scripts" / "Collect-RuntimeAclResults.ps1").read_text(encoding="utf-8")
        pattern = re.compile(r"\$(?:\w+Source|source)\s*=\s*@'\n(.*?)\n'@", re.DOTALL)
        gateway_blocks = pattern.findall(gateway)
        base_only_blocks = pattern.findall(base_only)
        collector_blocks = pattern.findall(collector)
        self.assertEqual(6, len(gateway_blocks))
        self.assertEqual(1, len(base_only_blocks))
        self.assertEqual(1, len(collector_blocks))
        for index, block in enumerate(
            [*gateway_blocks, *base_only_blocks, *collector_blocks], start=1
        ):
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
                "Test-PythonBaseOnlyRuntimeAcl.ps1",
                "Collect-RuntimeAclResults.ps1",
                "Install-TradingLabPythonRuntime.ps1",
                "TradingLabPythonInventory.ps1",
                "TradingLabBuildVenvGate.ps1",
                "TradingLabPythonAclPlan.ps1",
                "TradingLabFileSystemRights.ps1",
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
        self.assertIn(
            "Invoke-BuildVenvProcess $createStep.executable",
            installer,
        )
        self.assertIn("SAME_VERSION_TRADITIONAL_INSTALL_PRESENT=FAIL", installer)
        self.assertIn("INVENTORY_APPLY_FORBIDDEN", installer)
        self.assertIn("current_run_applied_phase", installer)
        self.assertNotIn("last_applied_phase", installer)
        self.assertIn("required_previous_phase", installer)
        self.assertIn("previous_phase_verified", installer)
        self.assertIn("previous_phase_report", installer)
        self.assertIn("PREVIOUS_PHASE_PREPARE_WHEELHOUSE", installer)
        self.assertIn("PREVIOUS_PHASE_UNINSTALL_TRADITIONAL", installer)
        self.assertIn("Get-VerifiedUninstallTraditionalEvidence", installer)
        self.assertIn("Get-VerifiedInstalledRuntimePendingEvidence", installer)
        self.assertIn("TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING", installer)
        self.assertIn("MUST_NOT_EXECUTE_INSTALLER", installer)
        self.assertIn("INSTALLER_REEXECUTED", installer)
        self.assertIn("ResumeMachineRuntime", installer)
        self.assertIn("PYTHON_AGENT_ACCESS_DENY", installer)
        self.assertIn("acl_plan", installer)
        self.assertIn("acl_apply_requested", installer)
        self.assertIn("ACL_TARGET_ONLY", installer)
        self.assertIn("ACL_OWNER_ADMINISTRATORS_PLANNED", installer)
        self.assertIn("GATEWAY_READ_EXECUTE_PLANNED", installer)
        self.assertIn("AGENT_ACCESS_ABSENT_PLANNED", installer)
        self.assertIn("DENY_ACES_PLANNED", installer)
        self.assertIn("TARGET_RUNTIME_ACL_ALREADY_APPLIED_VALIDATION_PENDING", installer)
        self.assertIn("MUST_NOT_CALL_SET_ACL", installer)
        self.assertIn("ACL_REAPPLIED", installer)
        self.assertIn("ACL_RECURSIVE_FINDINGS", installer)
        self.assertIn("ACL_REPARSE_POINTS", installer)
        self.assertIn("Assert-InstallMachinePreconditions", installer)
        self.assertIn("INSTALL_CPYTHON_MACHINE_WIDE_MINIMAL", installer)
        self.assertIn("INSTALL_ALL_USERS", installer)
        self.assertIn("TARGET_OUTSIDE_USER_PROFILE", installer)
        self.assertIn("DEVELOPMENT_LIBRARIES_DISABLED", installer)
        self.assertIn("PYTHON_RUNTIME_USER_PROFILE_DEPENDENCIES", installer)
        inventory = (ROOT / "scripts" / "TradingLabPythonInventory.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("$startInfo.Arguments = '-I -'", inventory)
        self.assertIn("RedirectStandardInput = $true", inventory)
        self.assertIn("$process.StandardInput.Write($Source)", inventory)
        self.assertIn("Invoke-TradingLabPythonRuntimeValidationMetadata", inventory)
        self.assertIn("Resolve-TradingLabRuntimeVerificationState", inventory)
        self.assertIn("ConvertTo-TradingLabVerifiedPythonInventory", inventory)
        self.assertIn("PRESENT_VERIFIED", inventory)
        self.assertIn("LIVE_READ_ONLY", inventory)
        self.assertIn("filesystem_modified = $false", inventory)
        self.assertIn("acl_modified = $false", inventory)
        self.assertIn("reports_written = $false", inventory)
        self.assertNotIn("-I -c", installer + inventory)
        self.assertNotIn("Invoke-Expression", installer + inventory)
        self.assertIn("if ($Phase -in @('Inventory', 'BuildVenv'))", installer)
        self.assertIn("Get-ReadOnlyVerifiedMachineRuntimeInventory", installer)
        self.assertIn("Assert-FinalVerifiedMachineRuntimeInventory", installer)
        inventory_start = installer.index("if ($Phase -eq 'Inventory')")
        inventory_end = installer.index("Assert-ExactServiceIdentity", inventory_start)
        inventory_phase = installer[inventory_start:inventory_end]
        for mutation in (
            "Set-Acl",
            "SetOwner",
            "Start-LoggedInstaller",
            "Invoke-LoggedProcess",
            "Remove-Item",
            "Move-Item",
            "Initialize-PhaseStorage",
            "Write-Report",
        ):
            self.assertNotIn(mutation, inventory_phase)
        build_start = installer.index("'BuildVenv' {")
        build_end = installer.index("'PromoteVenv' {", build_start)
        build = installer[build_start:build_end]
        self.assertLess(
            build.index("Assert-FinalVerifiedMachineRuntimeInventory $inventory"),
            build.index("Invoke-BuildVenvProcess $createStep.executable"),
        )
        self.assertIn("$report.required_previous_phase = 'ResumeMachineRuntime'", build)
        self.assertIn("Get-VerifiedPythonBaseRuntimeEvidence", build)
        self.assertIn("STAGING_VENV_ABSENT=FAIL", build)
        self.assertNotIn("Set-Acl", build)
        self.assertNotIn("import MetaTrader5", build)
        build_gate = (ROOT / "scripts" / "TradingLabBuildVenvGate.ps1").read_text(
            encoding="utf-8"
        )
        for required in (
            "PYTHON_BASE_ONLY",
            "BUILD_STAGING_VENV_OFFLINE_HASH_LOCKED",
            "--no-index",
            "--require-hashes",
            "--only-binary=:all:",
            "PIP_CONFIG_FILE",
            "PYTHONNOUSERSITE",
        ):
            self.assertIn(required, build_gate)
        for forbidden in (
            "import MetaTrader5",
            ".initialize(",
            ".login(",
            ".order_check(",
            ".order_send(",
            "https://",
            "Set-Acl",
        ):
            self.assertNotIn(forbidden, build_gate)
        self.assertIn("Assert-PythonManagerPreserved", installer)
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

    def test_machine_runtime_acl_resume_is_exact_target_and_dry_run_safe(self) -> None:
        installer = (ROOT / "scripts" / "Install-TradingLabPythonRuntime.ps1").read_text(
            encoding="utf-8"
        )
        plan_source = (ROOT / "scripts" / "TradingLabPythonAclPlan.ps1").read_text(
            encoding="utf-8"
        )
        rights_source = (ROOT / "scripts" / "TradingLabFileSystemRights.ps1").read_text(
            encoding="utf-8"
        )
        acl_gate = (ROOT / "scripts" / "Apply-TradingLabAclGate.ps1").read_text(
            encoding="utf-8"
        )
        for invariant in (
            "ACL_TARGET_NOT_EXACT_RUNTIME",
            "ACL_TARGET_REPARSE_POINT",
            "ACL_GATEWAY_RIGHTS_NOT_EXACT_RX",
            "ACL_FORBIDDEN_ALLOW",
            "ACL_DENY_ACE_PLANNED",
            "ACL_SYSTEM_NOT_EXACT_FULLCONTROL",
            "ACL_ADMINISTRATORS_NOT_EXACT_FULLCONTROL",
            "ACL_INHERITANCE_NOT_PROTECTED",
            "ACL_AUTHENTICATED_USERS_MODIFY",
            "ACL_USERS_MODIFY",
            "ACL_OTHER_DOMAIN_MUTATION",
        ):
            self.assertIn(invariant, plan_source)

        complete_start = installer.index("function Complete-InstalledMachineRuntime")
        complete_end = installer.index("function Write-Report", complete_start)
        complete = installer[complete_start:complete_end]
        dry_return = complete.index("if (-not $Apply) { return }")
        mutation = complete.index("Protect-ExactRuntimeTree $pythonBase $aclPlan")
        self.assertLess(dry_return, mutation)
        already_applied = complete.index("if ($aclState.state -eq 'EXACT')")
        already_return = complete.index("return", already_applied)
        self.assertLess(already_applied, already_return)
        self.assertLess(already_return, mutation)
        self.assertIn(
            "$report.must_not_call_set_acl = $true",
            complete[already_applied:already_return],
        )
        self.assertIn(
            "$report.acl_reapplied = $false",
            complete[already_applied:already_return],
        )
        self.assertNotIn("Set-Acl", complete[:dry_return])
        self.assertNotIn(".SetOwner(", complete[:dry_return])

        protect_start = installer.index("function Protect-ExactRuntimeTree")
        protect_end = installer.index("function New-AdministrativeMaintenanceSecurity", protect_start)
        protect = installer[protect_start:protect_end]
        self.assertIn("Assert-ExactRuntimeTarget $Root", protect)
        self.assertIn("Assert-MachineRuntimeAclPlan $Plan", protect)
        self.assertLess(
            protect.index("Assert-InMemoryRuntimeSecurity $fileSecurity $Plan"),
            protect.index("Set-Acl -LiteralPath $item.FullName"),
        )
        self.assertIn("REPARSE_POINT_FAIL_CLOSED", installer)
        self.assertIn("[System.IO.Directory]::EnumerateFileSystemEntries", installer)
        self.assertNotIn("AccessControlType]::Deny", installer)
        self.assertIn("Test-TradingLabRuntimeAclAudit", plan_source)
        self.assertIn("Get-TradingLabFileSystemRightsClassification", plan_source)
        for atomic_right in (
            "WriteData",
            "AppendData",
            "WriteExtendedAttributes",
            "WriteAttributes",
            "DeleteSubdirectoriesAndFiles",
            "Delete",
            "ChangePermissions",
            "TakeOwnership",
        ):
            self.assertIn(f"FileSystemRights]::{atomic_right}", rights_source)
        self.assertNotIn("FileSystemRights]::Modify", rights_source)
        self.assertNotIn("$modifyMask", installer)
        self.assertIn("Test-TradingLabFileSystemRightsMutation", installer)
        self.assertIn("Get-TradingLabProhibitedMutationRightsMask", acl_gate)
        self.assertIn("Test-TradingLabFileSystemRightsMutation", acl_gate)
        composite_partial = re.compile(
            r"-band\s+(?:\[[^\]]+\]::)?(?:Modify|Write|FullControl)\s*\)\s*-ne\s*0",
            re.IGNORECASE,
        )
        scripts = "\n".join(
            path.read_text(encoding="utf-8") for path in (ROOT / "scripts").glob("*.ps1")
        )
        self.assertIsNone(composite_partial.search(scripts))

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
