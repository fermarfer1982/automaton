from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SourceBoundaryTests(unittest.TestCase):
    def test_transactional_acl_repair_is_bounded_and_mt5_free(self) -> None:
        repair = (
            ROOT / "scripts" / "Repair-MT5ReadOnlyAuthorizationAclDrift.ps1"
        ).read_text(encoding="utf-8")
        helper = (
            ROOT / "scripts" / "MT5ReadOnlyAclRepairHelpers.ps1"
        ).read_text(encoding="utf-8")
        verifier = (
            ROOT / "trading_lab" / "acl_repair_verifier.py"
        ).read_text(encoding="utf-8")
        for required in (
            "Get-MT5AclRepairPlan",
            "Assert-FreshSecurityPreconditions",
            "Reserve-RepairReport",
            "Assert-RepairStateUnchanged",
            "Set-Acl -LiteralPath $controlPath -AclObject $controlCandidate",
            "Set-Acl -LiteralPath $demoAuthorizationPath -AclObject $demoCandidate",
            "Invoke-RepairRollback",
            "Invoke-FullCanonicalVerifier",
            "rollback_verified",
            "modified_content",
            "FileMode]::CreateNew",
            "TRADING_MODE'] = 'OBSERVE_ONLY'",
            "MT5_ACCESS_ENABLED'] = 'false'",
        ):
            self.assertIn(required, repair)
        combined = repair + helper + verifier
        for forbidden in (
            "import MetaTrader5",
            "MetaTrader5.initialize",
            ".order_check(",
            ".order_send(",
            "runas.exe",
            "icacls",
            "Invoke-Expression",
            "trading_lab.service",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("include_automaton_state=False", verifier)
        self.assertIn("include_automaton_state=True", verifier)
        self.assertNotRegex(
            verifier,
            re.compile(r"^\s*(?:from|import)\s+MetaTrader5", re.MULTILINE),
        )
        initial = repair.index("$initialState = Get-RepairState")
        reservation = repair.index("Reserve-RepairReport", initial)
        fresh_preconditions = repair.index("Assert-FreshSecurityPreconditions", reservation)
        main = repair.index("$freshState = Get-RepairState", fresh_preconditions)
        dry = repair.index("if (-not $Apply)", main)
        apply_branch = repair.index("} else {", dry)
        dry_source = repair[dry:apply_branch]
        self.assertNotIn("Set-Acl", dry_source)
        self.assertNotIn("Invoke-FullCanonicalVerifier", dry_source)
        control = repair.index("Set-Acl -LiteralPath $controlPath", apply_branch)
        demo = repair.index("Set-Acl -LiteralPath $demoAuthorizationPath", control)
        specialized = repair.index("$postState = Get-RepairState", demo)
        full = repair.index("Invoke-FullCanonicalVerifier", specialized)
        rollback = repair.index("Invoke-RepairRollback", full)
        self.assertLess(reservation, fresh_preconditions)
        self.assertLess(fresh_preconditions, main)
        self.assertLess(main, control)
        self.assertLess(control, demo)
        self.assertLess(demo, specialized)
        self.assertLess(specialized, full)
        self.assertLess(full, rollback)

    def test_audit_jsonl_uses_only_shared_win32_append_boundary(self) -> None:
        audit = (ROOT / "trading_lab" / "audit.py").read_text(encoding="utf-8")
        primitive = (
            ROOT / "trading_lab" / "windows_append_log.py"
        ).read_text(encoding="utf-8")
        self.assertIn("with WindowsAppendOnlyFile(self.path) as writer:", audit)
        self.assertIn("writer.append(encoded_record)", audit)
        for forbidden in (
            'self.path.open("a"', 'open("a"', "io.open(", "GENERIC_WRITE",
            "FILE_WRITE_DATA", "FlushFileBuffers", ".seek(", ".truncate(",
            ".replace(", ".rename(", ".mkdir(", ".touch(",
            "MetaTrader5", "Set-Acl", "icacls",
        ):
            self.assertNotIn(forbidden, audit + primitive)

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
        acl_source = (ROOT / "trading_lab" / "windows_acl.py").read_text(encoding="utf-8")
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
        self.assertIn('"scripts/Set-MT5ReadOnlyAuthorizationAcl.ps1"', source)
        self.assertIn('"scripts/Repair-MT5ReadOnlyAuthorizationAclDrift.ps1"', source)
        self.assertIn('"scripts/MT5ReadOnlyAclRepairHelpers.ps1"', source)
        self.assertIn('"scripts/Set-MT5ReadOnlyProtectedIdentity.ps1"', source)
        self.assertIn('"scripts/ProtectedIdentityGateHelpers.ps1"', source)
        self.assertIn('"trading_lab/acl_repair_verifier.py"', source)
        for protected_acl_source in (
            '"scripts/Repair-MT5ReadOnlyAuthorizationAclDrift.ps1"',
            '"scripts/MT5ReadOnlyAclRepairHelpers.ps1"',
            '"trading_lab/acl_repair_verifier.py"',
        ):
            self.assertIn(protected_acl_source, acl_source)
        self.assertIn('"scripts/New-TradingLabUsers.ps1"', source)
        self.assertIn('"scripts/Test-AgentRuntimeAcl.ps1"', source)
        self.assertIn('"scripts/Test-GatewayRuntimeAcl.ps1"', source)
        self.assertIn('"scripts/Test-PythonBaseOnlyRuntimeAcl.ps1"', source)
        self.assertIn('"scripts/Test-PythonStagingOnlyRuntimeAcl.ps1"', source)
        self.assertIn('"scripts/Test-PythonFinalOnlyRuntimeAcl.ps1"', source)
        self.assertIn('"scripts/Test-GatewayHealthOnly.ps1"', source)
        self.assertIn('"scripts/Test-SecurityAppendOnly.ps1"', source)
        self.assertIn('"scripts/Test-AuditJournalAppendOnly.ps1"', source)
        self.assertIn('"scripts/Collect-RuntimeAclResults.ps1"', source)
        self.assertIn('"scripts/Install-TradingLabPythonRuntime.ps1"', source)
        self.assertIn('"scripts/TradingLabPythonInventory.ps1"', source)
        self.assertIn('"scripts/TradingLabBuildVenvGate.ps1"', source)
        self.assertIn('"scripts/TradingLabPromoteVenvGate.ps1"', source)
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
        staging_only = (
            ROOT / "scripts" / "Test-PythonStagingOnlyRuntimeAcl.ps1"
        ).read_text(encoding="utf-8")
        security_append_only = (
            ROOT / "scripts" / "Test-SecurityAppendOnly.ps1"
        ).read_text(encoding="utf-8")
        audit_append_only = (
            ROOT / "scripts" / "Test-AuditJournalAppendOnly.ps1"
        ).read_text(encoding="utf-8")
        collector = (ROOT / "scripts" / "Collect-RuntimeAclResults.ps1").read_text(encoding="utf-8")
        pattern = re.compile(r"\$(?:\w+Source|source)\s*=\s*@'\n(.*?)\n'@", re.DOTALL)
        gateway_blocks = pattern.findall(gateway)
        base_only_blocks = pattern.findall(base_only)
        staging_only_blocks = pattern.findall(staging_only)
        security_append_only_blocks = pattern.findall(security_append_only)
        audit_append_only_blocks = pattern.findall(audit_append_only)
        collector_blocks = pattern.findall(collector)
        self.assertEqual(6, len(gateway_blocks))
        self.assertEqual(1, len(base_only_blocks))
        self.assertEqual(1, len(staging_only_blocks))
        self.assertEqual(1, len(security_append_only_blocks))
        self.assertEqual(1, len(audit_append_only_blocks))
        self.assertEqual(1, len(collector_blocks))
        for index, block in enumerate(
            [
                *gateway_blocks,
                *base_only_blocks,
                *staging_only_blocks,
                *security_append_only_blocks,
                *audit_append_only_blocks,
                *collector_blocks,
            ],
            start=1,
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
                "Test-PythonStagingOnlyRuntimeAcl.ps1",
                "Test-PythonFinalOnlyRuntimeAcl.ps1",
                "Test-SecurityAppendOnly.ps1",
                "Test-AuditJournalAppendOnly.ps1",
                "Collect-RuntimeAclResults.ps1",
                "Install-TradingLabPythonRuntime.ps1",
                "TradingLabPythonInventory.ps1",
                "TradingLabBuildVenvGate.ps1",
                "TradingLabPromoteVenvGate.ps1",
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
        self.assertIn("$startInfo.Arguments = '-B -I -'", inventory)
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
        self.assertNotIn("$startInfo.Arguments = '-I -'", inventory)
        self.assertIn("@('-B', '-I', '-m', 'venv', $stagingVenvPath)", installer)
        self.assertIn("@('-B', '-I', '-m', 'venv', $venvPath)", installer)
        self.assertIn("@('-B', '-I', '-')", installer)
        self.assertNotIn("Invoke-Expression", installer + inventory)
        self.assertIn("if ($Phase -in @('Inventory', 'BuildVenv', 'PromoteVenv'))", installer)
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
        promote_gate = (ROOT / "scripts" / "TradingLabPromoteVenvGate.ps1").read_text(
            encoding="utf-8"
        )
        for required in (
            "Test-TradingLabBuildVenvEvidenceRecord",
            "Test-TradingLabPythonStagingEvidenceRecord",
            "Resolve-TradingLabPromoteArtifactState",
            "Test-TradingLabProcessUsesVenv",
            "Resolve-TradingLabPromoteVenvPlanState",
            "Resolve-TradingLabRollbackExpectation",
            "REBUILD_AT_FINAL_PATH_TRANSACTIONALLY",
            "PRESERVE_READ_ONLY",
            "--no-index",
            "--require-hashes",
            "--only-binary=:all:",
        ):
            self.assertIn(required, promote_gate)
        for forbidden in (
            "import MetaTrader5",
            ".initialize(",
            ".login(",
            ".order_check(",
            ".order_send(",
            "https://",
            "Set-Acl",
            "Remove-Item",
        ):
            self.assertNotIn(forbidden, promote_gate)
        promote = installer[installer.index("'PromoteVenv' {") :]
        self.assertIn("REBUILD_AT_FINAL_PATH_TRANSACTIONALLY", promote)
        self.assertIn("Get-VerifiedBuildVenvEvidence", promote)
        self.assertIn("Get-VerifiedPythonStagingRuntimeEvidence", promote)
        self.assertIn("Assert-ExactVenvLiveReadOnly", promote)
        self.assertIn("Assert-PromotionArtifactsAbsent", promote)
        self.assertIn("Get-FinalNonRelocationAudit", promote)
        self.assertIn("Invoke-PromoteVenvRollback", promote)
        dry_stop = promote.index("if (-not $Apply) { break }")
        self.assertLess(dry_stop, promote.index("Initialize-PhaseStorage"))
        self.assertLess(
            dry_stop,
            promote.index(
                "[System.IO.Directory]::Move($venvPath, $report.promote_venv_plan.backup_path)"
            ),
        )
        self.assertNotIn(
            "[System.IO.Directory]::Move($stagingVenvPath", promote
        )
        self.assertNotIn("[System.IO.Directory]::Delete", promote)
        self.assertNotIn("Set-Acl", promote)
        self.assertNotIn("import MetaTrader5", promote)
        self.assertNotIn("Start-Service", promote)
        self.assertNotIn("Start-LoggedInstaller", promote)
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

    def test_python_staging_runtime_gate_has_strict_boundaries(self) -> None:
        staging = (
            ROOT / "scripts" / "Test-PythonStagingOnlyRuntimeAcl.ps1"
        ).read_text(encoding="utf-8")
        gateway = (ROOT / "scripts" / "Test-GatewayRuntimeAcl.ps1").read_text(
            encoding="utf-8"
        )
        agent = (ROOT / "scripts" / "Test-AgentRuntimeAcl.ps1").read_text(
            encoding="utf-8"
        )
        for harness, role in ((gateway, "AutomatonGateway"), (agent, "AutomatonAgent")):
            self.assertIn("[switch] $PythonStagingOnly", harness)
            self.assertIn("$isolatedModeCount -gt 1", harness)
            self.assertIn("Test-PythonStagingOnlyRuntimeAcl.ps1", harness)
            self.assertIn(f"-Role '{role}'", harness)
        self.assertIn("C:\\automaton\\.venv.new\\Scripts\\python.exe", staging)
        self.assertIn("$script:PythonStagingOnlyIsFinal = $false", staging)
        self.assertIn("UseShellExecute = $false", staging)
        self.assertIn("RedirectStandardInput = $true", staging)
        self.assertIn('importlib.metadata.version("MetaTrader5")', staging)
        self.assertNotIn("import MetaTrader5", staging)
        self.assertNotIn('importlib.import_module("MetaTrader5")', staging)
        self.assertNotIn("Set-Acl", staging)
        self.assertNotIn("Start-Service", staging)
        self.assertNotIn(".order_check(", staging)
        self.assertNotIn(".order_send(", staging)
        for boundary in (
            "build_venv = $false",
            "promote_venv = $false",
            "active_venv_accessed = $false",
            "active_venv_modified = $false",
            "mt5_imported = $false",
            "mt5_accessed = $false",
            "order_check_called = $false",
            "order_send_called = $false",
            "gateway_started = $false",
            "automaton_started = $false",
            "acl_modified = $false",
        ):
            self.assertIn(boundary, staging)

    def test_python_final_runtime_gate_has_strict_boundaries(self) -> None:
        shared = (
            ROOT / "scripts" / "Test-PythonStagingOnlyRuntimeAcl.ps1"
        ).read_text(encoding="utf-8")
        final = (
            ROOT / "scripts" / "Test-PythonFinalOnlyRuntimeAcl.ps1"
        ).read_text(encoding="utf-8")
        implementation = shared + "\n" + final
        gateway = (ROOT / "scripts" / "Test-GatewayRuntimeAcl.ps1").read_text(
            encoding="utf-8"
        )
        agent = (ROOT / "scripts" / "Test-AgentRuntimeAcl.ps1").read_text(
            encoding="utf-8"
        )
        for harness, role in ((gateway, "AutomatonGateway"), (agent, "AutomatonAgent")):
            self.assertIn("[switch] $PythonFinalOnly", harness)
            self.assertIn("if ($PythonFinalOnly)", harness)
            self.assertIn("Test-PythonFinalOnlyRuntimeAcl.ps1", harness)
            self.assertIn(f"-Role '{role}'", harness)
        self.assertIn("$script:PythonStagingOnlyMode = 'PYTHON_FINAL_ONLY'", final)
        self.assertIn("$script:PythonStagingOnlyRoot = 'C:\\automaton\\.venv'", final)
        self.assertIn(
            "$script:PythonStagingOnlyExecutable = "
            "'C:\\automaton\\.venv\\Scripts\\python.exe'",
            final,
        )
        self.assertNotIn("C:\\automaton\\.venv.new", final)
        self.assertNotIn("C:\\automaton\\.venv.backup.", final)
        self.assertIn('importlib.metadata.version("MetaTrader5")', shared)
        for forbidden in (
            "import MetaTrader5",
            'importlib.import_module("MetaTrader5")',
            "Set-Acl",
            "Start-Service",
            ".order_check(",
            ".order_send(",
        ):
            self.assertNotIn(forbidden, implementation)
        for boundary in (
            "build_venv = $false",
            "promote_venv = $false",
            "cleanup = $false",
            "staging_venv_accessed = $false",
            "staging_venv_modified = $false",
            "backup_venv_accessed = $false",
            "backup_venv_modified = $false",
            "mt5_imported = $false",
            "mt5_accessed = $false",
            "order_check_called = $false",
            "order_send_called = $false",
            "gateway_started = $false",
            "automaton_started = $false",
            "acl_modified = $false",
            "filesystem_final_modified =",
        ):
            self.assertIn(boundary, implementation)

    def test_gateway_health_only_startup_has_no_import_time_mt5_coupling(self) -> None:
        service = (ROOT / "trading_lab" / "service.py").read_text(encoding="utf-8")
        health_only = (ROOT / "trading_lab" / "health_only.py").read_text(
            encoding="utf-8"
        )
        adapter = (ROOT / "trading_lab" / "mt5_adapter.py").read_text(encoding="utf-8")
        harness = (ROOT / "scripts" / "Test-GatewayHealthOnly.ps1").read_text(
            encoding="utf-8"
        )
        config = (ROOT / "trading_lab" / "config.py").read_text(encoding="utf-8")
        service_tree = ast.parse(service)
        top_level_imports = {
            node.module
            for node in service_tree.body
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertNotIn("factory", top_level_imports)
        self.assertNotIn("providers", top_level_imports)
        self.assertNotIn("mt5_adapter", top_level_imports)
        self.assertNotIn("import MetaTrader5", service + health_only + adapter)
        self.assertNotIn("from MetaTrader5", service + health_only + adapter)
        self.assertNotIn('importlib.import_module("MetaTrader5")', service + health_only)
        self.assertNotIn("load_security_config(", service)
        bootstrap_load = service.index("load_gateway_bootstrap_config(config_path)")
        access_resolution = service.index(
            "resolve_mt5_access_enabled(bootstrap_config, environment)"
        )
        enabled_branch = service.index("if mt5_access_enabled:", access_resolution)
        complete_mt5_load = service.index("load_mt5_security_config(config_path)")
        self.assertLess(bootstrap_load, access_resolution)
        self.assertLess(access_resolution, enabled_branch)
        self.assertLess(enabled_branch, complete_mt5_load)
        disabled_guard = service.index(
            "if not mt5_access_enabled or not config.mt5_access_enabled"
        )
        lazy_provider = service.index("from .providers import MT5ExecutionProvider")
        self.assertLess(disabled_guard, lazy_provider)
        self.assertIn('raw["mt5_access_enabled"]', config)
        self.assertIn('if "mt5_access_enabled" not in raw:', config)
        self.assertIn("MT5_ACCESS_ENABLED=true requires", config)
        bootstrap_builder = config[
            config.index("def _build_gateway_bootstrap_config("):
            config.index("def load_gateway_bootstrap_config(")
        ]
        for mt5_only_field in (
            "authorized_account",
            "authorized_server",
            "authorized_account_name",
            "allowed_symbol",
            "magic_number",
            "mt5_terminal_path",
            "risk_raw",
        ):
            self.assertNotIn(mt5_only_field, bootstrap_builder)
        complete_loader = config[
            config.index("def _build_mt5_security_config("):
            config.index("def load_security_config(")
        ]
        for required_mt5_gate in (
            '_positive_int(raw.get("authorized_account")',
            '_required_string(raw, "authorized_server")',
            '_required_string(raw, "mt5_terminal_path")',
            '_required_string(raw, "allowed_symbol")',
            '_positive_int(raw.get("magic_number")',
            "_build_risk_limits(raw)",
        ):
            self.assertIn(required_mt5_gate, complete_loader)
        public_loader = config[
            config.index("def load_mt5_security_config("):
            config.index("def load_security_config(")
        ]
        self.assertIn("return _build_mt5_security_config(raw, workspace)", public_loader)
        self.assertIn('"MetaTrader5" in sys.modules', health_only)
        self.assertIn('metadata.version("MetaTrader5")', health_only)
        self.assertIn('"mt5_status": "IMPORTED_UNEXPECTEDLY"', health_only)
        self.assertIn('else "DISABLED_NOT_ACCESSED"', health_only)
        self.assertIn('@app.get("/health", dependencies=protected)', (
            ROOT / "trading_lab" / "fastapi_service.py"
        ).read_text(encoding="utf-8"))
        for forbidden in (
            "runas.exe", "Start-Process", "TaskKill", "Set-Acl", "0.0.0.0",
            "import MetaTrader5", ".order_check(", ".order_send(",
            "System.Net.Http", "HttpClient", "Add-Type -AssemblyName",
        ):
            self.assertNotIn(forbidden, harness)
        for required in (
            "C:\\automaton\\.venv\\Scripts\\python.exe",
            "$listenAddress = '127.0.0.1'",
            "MT5_ACCESS_ENABLED'] = 'false'",
            "--controlled-stdin-shutdown",
            "gateway-health-only-$normalizedRunId.json",
            "filesystem_runtime_modified",
            "acl_modified",
            "Invoke-WebRequest",
            "-UseBasicParsing",
            "-TimeoutSec 3",
            "$report = [ordered]@{",
            "status = 'FAIL_INITIALIZING'",
            "# BEGIN_RUNTIME_GUARD",
            "# BEGIN_DURABLE_REPORT_FINALLY",
            "Write-ExclusiveJson $reportPath $report",
            "Get-SanitizedRuntimeError",
            "$process.StandardOutput.ReadToEndAsync()",
            "$process.StandardError.ReadToEndAsync()",
            "Resolve-GatewayEarlyExit",
            "GATEWAY_PROCESS_EARLY_EXIT",
            "GATEWAY_HEALTH_ONLY_PROCESS_EARLY_EXIT",
            "gateway_process_exit_observed",
            "gateway_process_exit_code",
            "gateway_exit_before_health",
            "gateway_stdout_captured",
            "gateway_stderr_captured",
            "gateway_stdout_sanitized",
            "gateway_stderr_sanitized",
            "Get-SanitizedBoundedProcessText",
            "...[TRUNCATED]",
        ):
            self.assertIn(required, harness)
        self.assertNotRegex(harness, r"\.ReadToEnd\s*\(")
        self.assertLess(
            harness.index("$report = [ordered]@{"),
            harness.index("# BEGIN_RUNTIME_GUARD"),
        )
        self.assertLess(
            harness.index("# BEGIN_RUNTIME_GUARD"),
            harness.index(
                "$effectiveIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()"
            ),
        )
        self.assertGreater(
            harness.rindex("Write-ExclusiveJson $reportPath $report"),
            harness.index("# BEGIN_DURABLE_REPORT_FINALLY"),
        )
        process_start = harness.index("if (-not $process.Start())")
        health_probe = harness.index("Invoke-WebRequest", process_start)
        self.assertLess(
            harness.index("$process.StandardOutput.ReadToEndAsync()", process_start),
            health_probe,
        )
        self.assertLess(
            harness.index("$process.StandardError.ReadToEndAsync()", process_start),
            health_probe,
        )
        self.assertLess(
            harness.index("if ($process.HasExited) {", process_start),
            health_probe,
        )

    def test_mt5_read_only_preflight_has_a_structural_capability_boundary(self) -> None:
        adapter = (ROOT / "trading_lab" / "mt5_read_only.py").read_text(
            encoding="utf-8"
        )
        entrypoint = (
            ROOT / "trading_lab" / "mt5_read_only_entrypoint.py"
        ).read_text(encoding="utf-8")
        harness = (
            ROOT / "scripts" / "Test-MT5ReadOnlyPreflight.ps1"
        ).read_text(encoding="utf-8")
        controls = (
            ROOT / "trading_lab" / "mt5_read_only_controls.py"
        ).read_text(encoding="utf-8")
        authorization_helper = (
            ROOT / "trading_lab" / "mt5_read_only_authorization.py"
        ).read_text(encoding="utf-8")
        authorization_script = (
            ROOT / "scripts" / "New-MT5ReadOnlyAuthorization.ps1"
        ).read_text(encoding="utf-8")
        tree = ast.parse(adapter)
        entrypoint_tree = ast.parse(entrypoint)
        controls_tree = ast.parse(controls)
        authorization_tree = ast.parse(authorization_helper)

        forbidden_invocations = {
            "login", "symbol_select", "market_book_add", "market_book_release",
            "copy_ticks_from", "order_check", "order_send",
        }
        for source_tree, label in (
            (tree, "adapter"),
            (entrypoint_tree, "entrypoint"),
            (controls_tree, "controls"),
            (authorization_tree, "authorization"),
        ):
            invoked_attributes = {
                node.func.attr
                for node in ast.walk(source_tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            }
            self.assertTrue(
                forbidden_invocations.isdisjoint(invoked_attributes),
                f"forbidden MT5 invocation in {label}",
            )

        self.assertIn("class MT5ReadOnlyAdapter", adapter)
        self.assertIn("class MT5ReadOnlyBindings", adapter)
        self.assertIn('__slots__ = ("_bindings", "_ledger")', adapter)
        self.assertIn('module = importlib.import_module("MetaTrader5")', adapter)
        self.assertIn("bindings = _bindings_from_module(module)", adapter)
        self.assertNotIn("self._mt5", adapter)
        self.assertNotIn("getattr(", adapter)
        for capability in (
            "initialize", "version", "terminal_info", "account_info",
            "symbol_info", "symbol_info_tick", "shutdown", "last_error",
        ):
            self.assertIn(f'"{capability}"', adapter)
        for prohibited in forbidden_invocations:
            self.assertNotIn(f"def {prohibited}(", adapter)
            self.assertNotIn(f".{prohibited}(", adapter + entrypoint + harness)

        self.assertIn("TradingMode.OBSERVE_ONLY", adapter)
        self.assertIn("account.trade_mode) == adapter.demo_trade_mode", adapter)
        self.assertIn("int(account.login) == config.authorized_account", adapter)
        self.assertIn("str(account.server) == config.authorized_server", adapter)
        self.assertIn("adapter.symbol_info(EXACT_SYMBOL)", adapter)
        self.assertIn("adapter.symbol_info_tick(EXACT_SYMBOL)", adapter)
        self.assertNotIn("GOLD", adapter + entrypoint + harness)
        self.assertNotIn("XAUUSDm", adapter + entrypoint + harness)
        self.assertIn("mt5_read_only_preflight_started", adapter)
        self.assertIn("mt5_identity_verified", adapter)
        self.assertIn("mt5_read_only_preflight_stopped", adapter)
        self.assertIn("mt5_read_only_authorization_accepted", adapter)
        self.assertIn("probe_kill_switch", controls)
        self.assertNotIn("initialized_attempted", adapter)
        self.assertIn("if adapter is not None and mt5_initialize_succeeded:", adapter)
        for binding in (
            "purpose", "run_id", "authorization_id", "issued_at_utc",
            "expires_at_utc", "issuer_sid", "gateway_sid", "authorized_account",
            "authorized_server", "authorized_symbol", "terminal_path", "git_commit",
            "config_sha256", "entrypoint_sha256", "runner_sha256", "harness_sha256",
        ):
            self.assertIn(binding, controls)

        for forbidden_harness in (
            "runas.exe", "Start-Process", "Stop-Process", "taskkill",
            "Set-Acl", "Invoke-WebRequest", "HttpClient", "0.0.0.0",
            "import MetaTrader5", ".login(", ".symbol_select(",
            ".order_check(", ".order_send(",
        ):
            self.assertNotIn(forbidden_harness, harness)
        for forbidden_authorization in (
            "Set-Acl", "icacls", "takeown", "runas.exe", "Start-Process",
            "import MetaTrader5", ".initialize(", ".login(", ".symbol_select(",
            ".order_check(", ".order_send(", "DEMO_EXECUTION",
        ):
            self.assertNotIn(forbidden_authorization, authorization_script)
        self.assertIn("[System.IO.FileMode]::CreateNew", authorization_script)
        self.assertIn("Get-LocalUser -Name", authorization_script)
        self.assertIn("S-1-5-32-544", authorization_script)
        self.assertIn("status --porcelain=v1 --untracked-files=all", authorization_script)
        self.assertIn("AUTHORIZATION_LIFETIME_MINUTES=15", authorization_script)
        self.assertIn(
            "mt5-read-only-authorization-$normalizedRunId.json",
            authorization_script,
        )
        for required_harness in (
            "S-1-5-21-568964486-193631783-1609210587-1007",
            "C:\\automaton\\.venv\\Scripts\\python.exe",
            "MT5_READ_ONLY_PREFLIGHT", "Get-FinalRuntimeFingerprint",
            "$process.StandardOutput.ReadToEndAsync()",
            "$process.StandardError.ReadToEndAsync()",
            "$process.Kill()", "[System.IO.FileMode]::CreateNew",
            "filesystem_runtime_modified", "acl_modified", "orphan_processes",
            "authorization_required", "authorization_present", "authorization_valid",
            "authorization_run_id_match", "authorization_not_expired",
            "authorization_issuer_match", "authorization_gateway_sid_match",
            "authorization_config_hash_match", "authorization_code_hash_match",
            "kill_switch_readable", "mt5_initialize_succeeded",
            "mt5-read-only-authorization-$normalizedRunId.json",
        ):
            self.assertIn(required_harness, harness)
        self.assertNotRegex(harness, r"\.ReadToEnd\s*\(")
        self.assertLess(
            harness.index("$beforeFingerprint = Get-FinalRuntimeFingerprint"),
            harness.index("if (-not $process.Start())"),
        )
        self.assertGreater(
            harness.index("$afterFingerprint = Get-FinalRuntimeFingerprint"),
            harness.index("# BEGIN_DURABLE_REPORT_FINALLY"),
        )

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
        already_applied = complete.index(
            "if ($aclState.state -in @('EXACT_PROTECTED', 'SAFE_NO_REPAIR_REQUIRED'))"
        )
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
        self.assertIn(
            "$report.acl_plan = $null",
            complete[already_applied:already_return],
        )
        self.assertIn(
            "$report.machine_runtime_acl_modified = $false",
            complete[already_applied:already_return],
        )
        self.assertGreater(
            complete.index("New-MachineRuntimeAclPlan $pythonBase"),
            already_return,
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
        self.assertIn("ACL_AUDIT_ROOT_INHERITANCE_NOT_PROTECTED", plan_source)
        self.assertIn("ACL_AUDIT_INHERITANCE_PARENT_UNVERIFIED", plan_source)
        self.assertIn("safe_inherited_descendants", plan_source)
        self.assertIn("SAFE_NO_REPAIR_REQUIRED", plan_source)
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
        promote_gate = (
            ROOT / "scripts" / "TradingLabPromoteVenvGate.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("$Record -is [System.Collections.IDictionary]", promote_gate)
        self.assertIn("$Record.Contains($Name)", promote_gate)
        self.assertIn("Get-TradingLabPromotePropertyCount $environment", promote_gate)
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

    def test_gateway_acl_verifier_uses_read_only_per_target_maintenance_policy(self) -> None:
        verifier = (ROOT / "trading_lab" / "windows_acl.py").read_text(encoding="utf-8")
        bootstrap = (ROOT / "scripts" / "TradingLabAclBootstrap.ps1").read_text(
            encoding="utf-8"
        )
        initializer = (ROOT / "scripts" / "Initialize-TradingLabAcl.ps1").read_text(
            encoding="utf-8"
        )
        policy = json.loads(
            (ROOT / "config" / "windows-acl-policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {
                "automaton_state",
                "gateway_logs",
                "lab_root",
                "logs_root",
                "operational",
                "security_logs",
            },
            set(policy["maintenance_targets"]),
        )
        self.assertNotIn("S-1-5-21-568964486-193631783-1609210587-1001", verifier)
        self.assertNotIn("Proyecto IA", verifier)
        self.assertIn("maintenance_identity", verifier)
        self.assertIn("maintenance_sid not in admin_members", verifier)
        self.assertIn("maintenance_policy.maintenance_targets.get(policy_key)", verifier)
        self.assertIn("Read-TradingLabWindowsAclPolicy", bootstrap)
        self.assertIn("config\\windows-acl-policy.json", initializer)
        for forbidden in ("Set-Acl", "icacls", "/grant", "/reset"):
            self.assertNotIn(forbidden, verifier)
        for mt5_boundary in ("MetaTrader5", "order_check", "order_send"):
            self.assertNotIn(mt5_boundary, verifier)

    def test_mt5_read_only_precondition_gates_have_no_runtime_or_trading_actions(self) -> None:
        authorization_acl = (
            ROOT / "scripts" / "Set-MT5ReadOnlyAuthorizationAcl.ps1"
        ).read_text(encoding="utf-8")
        protected_identity = (
            ROOT / "scripts" / "Set-MT5ReadOnlyProtectedIdentity.ps1"
        ).read_text(encoding="utf-8")
        powershell_helper = (
            ROOT / "scripts" / "ProtectedIdentityGateHelpers.ps1"
        ).read_text(encoding="utf-8")
        python_helper = (
            ROOT / "trading_lab" / "protected_identity_config.py"
        ).read_text(encoding="utf-8")
        combined = authorization_acl + protected_identity + powershell_helper + python_helper
        for forbidden in (
            "import MetaTrader5", "from MetaTrader5", "initialize(", "login(",
            "order_check", "order_send", "trading_lab.service", "start_gateway",
            "start_automaton", "runas", "Invoke-Expression",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("FileMode]::CreateNew", authorization_acl)
        self.assertIn("[System.IO.File]::Replace", protected_identity)
        self.assertIn("--mode pre-replace", protected_identity)
        self.assertIn("--mode post-replace", protected_identity)
        self.assertIn("VALIDATE_PRE_REPLACE", protected_identity)
        self.assertIn("VALIDATE_POST_REPLACE", protected_identity)
        self.assertIn(
            "$migrationRequired = @('KNOWN_PLACEHOLDER', "
            "'KNOWN_PREVIOUS_TARGET') -contains $report.initial_state",
            protected_identity,
        )
        self.assertIn(
            "if (-not $Apply -or $migrationRequired)",
            protected_identity,
        )
        self.assertIn("elseif ($migrationRequired)", protected_identity)
        self.assertNotIn("[string] $Account", protected_identity)
        self.assertIn("authorized_account = 10012236003", protected_identity)
        self.assertIn("PREVIOUS_TARGET_ACCOUNT = 107554164", python_helper)
        self.assertIn("TARGET_ACCOUNT = 10012236003", python_helper)
        self.assertIn("$report.real_loader_validated = $false", protected_identity)
        self.assertIn("$report.hash_after = $report.hash_before", protected_identity)
        self.assertIn("_build_mt5_security_config", python_helper)
        self.assertIn("CANONICAL_WORKSPACE", python_helper)
        self.assertIn("load_mt5_security_config(candidate)", python_helper)
        self.assertIn("CANONICAL_CONFIG_PATH", python_helper)
        self.assertIn("ReadToEndAsync()", powershell_helper)
        self.assertIn("...[TRUNCATED]", powershell_helper)
        self.assertIn('with destination.open("xb")', python_helper)
        self.assertIn('destination.name.startswith(".trading.identity-")', python_helper)
        self.assertIn('destination.name.endswith(".tmp")', python_helper)


if __name__ == "__main__":
    unittest.main()
