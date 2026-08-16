$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$installerPath = Join-Path $root 'scripts\Install-TradingLabPythonRuntime.ps1'
$inventoryPath = Join-Path $root 'scripts\TradingLabPythonInventory.ps1'
$buildVenvGatePath = Join-Path $root 'scripts\TradingLabBuildVenvGate.ps1'
$promoteVenvGatePath = Join-Path $root 'scripts\TradingLabPromoteVenvGate.ps1'
$aclPlanPath = Join-Path $root 'scripts\TradingLabPythonAclPlan.ps1'
$rightsPath = Join-Path $root 'scripts\TradingLabFileSystemRights.ps1'
$aclGatePath = Join-Path $root 'scripts\Apply-TradingLabAclGate.ps1'
$setupPath = Join-Path $root 'scripts\setup.ps1'
$gatewayPath = Join-Path $root 'scripts\Test-GatewayRuntimeAcl.ps1'
$collectorPath = Join-Path $root 'scripts\Collect-RuntimeAclResults.ps1'
$gatewayEnvironmentPath = Join-Path $root 'scripts\Initialize-GatewayPythonEnvironment.ps1'
$gatewayStartPath = Join-Path $root 'scripts\start_gateway.ps1'

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

foreach ($path in @(
    $installerPath, $inventoryPath, $buildVenvGatePath, $promoteVenvGatePath, $aclPlanPath, $rightsPath, $aclGatePath,
    $setupPath, $gatewayPath, $collectorPath,
    $gatewayEnvironmentPath, $gatewayStartPath
)) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$tokens, [ref]$errors
    )
    Assert-True ($errors.Count -eq 0) "PowerShell AST failed for ${path}: $($errors -join '; ')"
}

$installer = [System.IO.File]::ReadAllText($installerPath)
$inventorySource = [System.IO.File]::ReadAllText($inventoryPath)
$buildVenvGateSource = [System.IO.File]::ReadAllText($buildVenvGatePath)
$promoteVenvGateSource = [System.IO.File]::ReadAllText($promoteVenvGatePath)
$aclPlanSource = [System.IO.File]::ReadAllText($aclPlanPath)
$rightsSource = [System.IO.File]::ReadAllText($rightsPath)
$aclGateSource = [System.IO.File]::ReadAllText($aclGatePath)
$setup = [System.IO.File]::ReadAllText($setupPath)
$gateway = [System.IO.File]::ReadAllText($gatewayPath)
$collector = [System.IO.File]::ReadAllText($collectorPath)
$gatewayEnvironment = [System.IO.File]::ReadAllText($gatewayEnvironmentPath)
$gatewayStart = [System.IO.File]::ReadAllText($gatewayStartPath)

foreach ($required in @(
    '#Requires -RunAsAdministrator',
    "[ValidateSet('Inventory', 'PrepareWheelhouse', 'UninstallTraditional', 'InstallMachineRuntime', 'ResumeMachineRuntime', 'BuildVenv', 'PromoteVenv')]",
    "[string] `$Phase = 'Inventory'",
    'INVENTORY_APPLY_FORBIDDEN',
    'SAME_VERSION_TRADITIONAL_INSTALL_PRESENT=FAIL',
    'PARTIAL_TARGET_RUNTIME=FAIL',
    "`$stagingVenvPath = Join-Path `$workspace '.venv.new'",
    "`$logsRoot = Join-Path `$maintenanceRoot 'logs'",
    "`$wheelhousePath = Join-Path `$maintenanceRoot 'wheelhouse\cp314-win_amd64'",
    'Resolve-TradingLabWheelhouseManifestState', 'WHEELHOUSE_COMPLETE=FAIL',
    "`$pythonBase = 'C:\Program Files\AutomatonPython\3.14.5'",
    "`$expectedPythonVersion = '3.14.5'",
    "`$expectedInstallerLength = 30361968L",
    "`$expectedInstallerSha256 = 'f9c09f5ed6f796fd1a8bc5ddfa41715a494b453c4781f0e35d5077cf9fa58f6d'",
    "`$expectedRegisteredBundleSha256 = '693522e3a8a747926a2f1f5a013b07315ac9472657d691b8f152fb6438b81723'",
    "`$expectedLockSha256 = '68d14ddc9d943079e8f791bb8f276ae630f46c8ee8997b2bf2afeabed1e30d99'",
    'Get-AuthenticodeSignature', 'O=Python Software Foundation',
    'Get-RegisteredTraditionalBundle', 'Resolve-RegisteredBundleExecutable',
    "Start-LoggedInstaller `$bundleExecutable @('/uninstall', '/quiet') `$uninstallLog",
    'Resolve-TradingLabInstallerExit $process.ExitCode',
    'Start-LoggedInstaller $plan.executable $plan.arguments $installLog', "@('/log', `$LogPath)",
    'InstallAllUsers=1', 'Include_dev=0', 'Include_test=0', 'Include_doc=0', 'Include_tcltk=0',
    "Invoke-BuildVenvProcess `$createStep.executable",
    "'--no-index', '--find-links', `$wheelhousePath",
    'importlib.metadata.version("MetaTrader5")',
    'TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING',
    'REBUILD_AT_FINAL_PATH_TRANSACTIONALLY', 'PromotionFailedRolledBack',
    'CriticalRecoveryRequired', 'current_run_applied_phase',
    "required_previous_phase = `$null", "previous_phase_verified = `$false",
    "previous_phase_report = `$null", 'Get-VerifiedPrepareWheelhouseEvidence',
    'Get-VerifiedUninstallTraditionalEvidence',
    "`$report.gates.PREVIOUS_PHASE_PREPARE_WHEELHOUSE = 'PASS'",
    "`$report.gates.PREVIOUS_PHASE_UNINSTALL_TRADITIONAL = 'PASS'",
    "`$report.gates.WHEELHOUSE_PRESENT = 'PASS'",
    "`$report.gates.WHEELHOUSE_HASH_LOCKED = 'PASS'",
    "`$report.gates.WHEELHOUSE_COMPLETE = 'PASS'",
    "`$report.gates.META_TRADER5_WHEEL_PRESENT = 'PASS'",
    "`$report.gates.NUMPY_WHEEL_PRESENT = 'PASS'",
    "`$report.gates.PYTHON_MANAGER_PRESERVE = 'PASS'",
    "`$report.gates.TRADITIONAL_BUNDLE_TARGET = 'PASS'",
    "`$report.gates.TRADITIONAL_MSI_COMPONENTS_EXPECTED = 9",
    "`$report.gates.NO_MANUAL_REGISTRY_CLEANUP = 'PASS'",
    "`$report.gates.NO_PACKAGE_CACHE_DELETE = 'PASS'",
    "`$report.gates.NO_WINDOWS_INSTALLER_CACHE_DELETE = 'PASS'",
    "`$report.gates.ACTIVE_VENV_UNTOUCHED = 'PASS'",
    "`$report.gates.PARTIAL_TARGET_NOT_DELETED_YET = 'PASS'",
    'PYTHON_MANAGER_PRESERVE_PATH=', 'TRADITIONAL_BUNDLE_UNINSTALLER=',
    'WHEELHOUSE_EXPECTED_REQUIREMENTS=', 'WHEELHOUSE_ARTIFACT_COUNT=',
    'WHEELHOUSE_MISSING_REQUIREMENTS=', 'WHEELHOUSE_SOURCE_DISTRIBUTIONS=',
    'WHEELHOUSE_UNEXPECTED_ARTIFACTS=', 'WHEELHOUSE_CORRUPT_ARTIFACTS=',
    'installer_plan.operation=', 'installer_plan.executable=', 'installer_plan.arguments=',
    'installer_plan.target_dir=', 'installer_plan.log_path_template=',
    'Assert-ExpectedTraditionalMsiComponents', 'Assert-PythonManagerPreserved',
    'Assert-UninstallPlanHasNoDirectCleanup',
    'Assert-InstallMachinePreconditions', 'New-MachineRuntimeInstallerPlan',
    'Assert-MachineInstallerPlan', 'INSTALL_CPYTHON_MACHINE_WIDE_MINIMAL',
    "`$report.gates.INSTALL_ALL_USERS = 'PASS'",
    "`$report.gates.TARGET_MACHINE_WIDE = 'PASS'",
    "`$report.gates.TARGET_OUTSIDE_USER_PROFILE = 'PASS'",
    "`$report.gates.PREPEND_PATH_DISABLED = 'PASS'",
    "`$report.gates.LAUNCHER_DISABLED = 'PASS'",
    "`$report.gates.FILE_ASSOCIATIONS_DISABLED = 'PASS'",
    "`$report.gates.DEVELOPMENT_LIBRARIES_DISABLED = 'PASS'",
    "`$report.gates.TEST_SUITE_DISABLED = 'PASS'",
    "`$report.gates.DOCUMENTATION_DISABLED = 'PASS'",
    "`$report.gates.TCL_TK_DISABLED = 'PASS'",
    'PYTHON_EXE_EXISTS', 'PYTHON314_DLL_EXISTS', 'PYTHON_LIB_EXISTS',
    'PYTHON_STDLIB', 'PYTHON_VENV_IMPORT', 'PYTHON_PIP_AVAILABLE',
    'PYTHON_VERSION_EXACT', 'PYTHON_ARCH_X64', 'PYTHON_BASE_PREFIX_TARGET',
    'PYTHON_EXECUTABLE_TARGET', 'PYTHON_RUNTIME_USER_PROFILE_DEPENDENCIES',
    'PYTHON_BASE_MACHINE_WIDE', 'PYTHON_BASE_OUTSIDE_USER_PROFILE',
    'PYTHON_GATEWAY_EXECUTE', 'PYTHON_GATEWAY_MODIFY_DENY', 'PYTHON_AGENT_ACCESS_DENY',
    'MUST_NOT_EXECUTE_INSTALLER', 'INSTALLER_REEXECUTED',
    'INSTALLED_RUNTIME_EVIDENCE', 'INSTALLER_RESULT_EVIDENCE',
    'EXPECTED_MACHINE_MSI_COMPONENTS', 'UNEXPECTED_MACHINE_MSI_COMPONENTS',
    'MachineRuntimeAclRecoveryRequested', 'MachineRuntimeAclRecovered',
    'New-MachineRuntimeAclPlan', 'Set-MachineRuntimeAclPlanGates',
    'ACL_TARGET_ONLY', 'ACL_OWNER_ADMINISTRATORS_PLANNED',
    'ACL_INHERITANCE_PROTECTED_PLANNED', 'SYSTEM_FULLCONTROL_PLANNED',
    'ADMINISTRATORS_FULLCONTROL_PLANNED', 'GATEWAY_READ_EXECUTE_PLANNED',
    'GATEWAY_WRITE_ABSENT_PLANNED', 'GATEWAY_MODIFY_ABSENT_PLANNED',
    'GATEWAY_DELETE_ABSENT_PLANNED', 'GATEWAY_CHANGE_PERMISSIONS_ABSENT_PLANNED',
    'GATEWAY_TAKE_OWNERSHIP_ABSENT_PLANNED', 'AGENT_ACCESS_ABSENT_PLANNED',
    'AUTHENTICATED_USERS_MODIFY_ABSENT_PLANNED', 'USERS_MODIFY_ABSENT_PLANNED',
    'DENY_ACES_PLANNED', 'ACL_OTHER_DOMAINS_MODIFIED',
    'machine_runtime_acl_modified', 'acl_apply_requested', 'acl_applied', 'acl_plan',
    'TARGET_RUNTIME_ACL_ALREADY_APPLIED_VALIDATION_PENDING',
    'TARGET_RUNTIME_ACL_ALREADY_SAFE_NO_REPAIR_REQUIRED',
    'MUST_NOT_CALL_SET_ACL', 'ACL_REAPPLIED', 'SET_ACL_CALL_COUNT',
    'ACL_OWNER_ADMINISTRATORS',
    'ACL_ROOT_INHERITANCE_PROTECTED', 'ACL_DESCENDANT_POLICY_SAFE',
    'ACL_SAFE_INHERITED_DESCENDANTS', 'ACL_UNSAFE_DESCENDANTS',
    'PYTHON_GATEWAY_READ', 'PYTHON_GATEWAY_WRITE_DENY',
    'PYTHON_GATEWAY_DELETE_DENY', 'PYTHON_GATEWAY_CHANGE_PERMISSIONS_DENY',
    'PYTHON_GATEWAY_TAKE_OWNERSHIP_DENY', 'ACL_UNEXPECTED_PRINCIPALS',
    'ACL_RECURSIVE_FINDINGS', 'ACL_REPARSE_POINTS',
    'VENV_BASE_OUTSIDE_USER_PROFILE', 'VENV_LOCK_MATCH',
    'META_TRADER5_PACKAGE_PRESENT',
    'GatewayPythonBaseRunId', 'AgentPythonBaseRunId',
    'Get-VerifiedResumeMachineRuntimeEvidence', 'Get-VerifiedPythonBaseRuntimeEvidence',
    'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME', 'GATEWAY_PYTHON_BASE_RUNTIME_EVIDENCE',
    'AGENT_PYTHON_BASE_RUNTIME_EVIDENCE', 'STAGING_VENV_ABSENT',
    'New-BuildVenvPlan', 'Assert-BuildVenvPlan', 'New-PostBuildValidationPlan',
    'BUILD_STAGING_VENV_OFFLINE_HASH_LOCKED', 'PIP_CONFIG_FILE', 'PIP_NO_INDEX',
    'PIP_DISABLE_PIP_VERSION_CHECK', 'PYTHONNOUSERSITE',
    'STAGING_BUILD_FAILED', 'STAGING_LEFT_FOR_INSPECTION',
    'ACTIVE_VENV_MODIFIED', 'ACTIVE_VENV_EXECUTED', 'MT5_IMPORTED',
    'ORDER_CHECK_CALLED', 'ORDER_SEND_CALLED',
    "trading_mode\s*:\s*OBSERVE_ONLY",
    "mt5_accessed = `$false", "automaton_started = `$false", "gateway_started = `$false"
)) {
    Assert-True ($installer.Contains($required)) "Python recovery gate lacks invariant: $required"
}

foreach ($required in @(
    'Get-TradingLabPythonCoreRegistrations', 'HKCU:\Software\Python\PythonCore\3.14',
    'HKLM:\Software\Python\PythonCore\3.14', 'Get-TradingLabPythonUninstallEntries',
    'Get-TradingLabPythonMsiProducts', 'Installer\UserData',
    'Resolve-TradingLabInstallerExit', 'INSTALLER_MAINTENANCE_COLLISION',
    'Resolve-TradingLabWheelhouseManifestState',
    'Test-TradingLabPrepareWheelhouseReportRecord',
    'Find-TradingLabPrepareWheelhouseReport',
    'Test-TradingLabUninstallTraditionalReportRecord',
    'Find-TradingLabUninstallTraditionalReport',
    'Resolve-TradingLabInstallPreconditionState',
    'Resolve-TradingLabInstallerArtifactState',
    'Test-TradingLabExactMachineTarget',
    'Test-TradingLabInstalledRuntimePendingReportRecord',
    'Find-TradingLabInstalledRuntimePendingReport',
    'Resolve-TradingLabMachineMsiComponentState',
    'Invoke-TradingLabPythonStdinJson', "`$startInfo.Arguments = '-B -I -'",
    'Test-TradingLabManagerExcludedFromUninstallPlan',
    'Resolve-TradingLabMsiComponentSetState',
    'PYTHON_MANAGER_RUNTIME', 'TRADITIONAL_BUNDLE', 'TRADITIONAL_MSI_COMPONENT',
    'partial_target_runtime', 'completed_target_runtime', 'broken_active_venv',
    'mixed_pythoncore_registration', 'same_version_traditional_install_present',
    'traditional_bundle_registration_scope', 'traditional_runtime_payload_scope',
    'machine_runtime_target_present', 'machine_runtime_msi_components',
    'EXPECTED_INSTALLED_TARGET_RUNTIME', 'CONFLICTING_PREEXISTING_RUNTIME',
    'target_probe', 'TARGET_LAYOUT_INCOMPLETE',
    'Invoke-TradingLabPythonRuntimeValidationMetadata',
    'Resolve-TradingLabRuntimeVerificationState',
    'ConvertTo-TradingLabVerifiedPythonInventory',
    'PRESENT_VERIFIED', 'LIVE_READ_ONLY',
    'filesystem_modified', 'acl_modified', 'reports_written'
)) {
    Assert-True ($inventorySource.Contains($required)) "Python inventory lacks invariant: $required"
}

foreach ($required in @(
    'Test-TradingLabResumeMachineRuntimeReportRecord',
    'Find-TradingLabResumeMachineRuntimeReport',
    'Test-TradingLabPythonBaseRuntimeEvidenceRecord',
    'Read-TradingLabPythonBaseRuntimeEvidenceFile',
    'Resolve-TradingLabBuildVenvPlanState',
    'Resolve-TradingLabStagingDistributionState',
    'MachineRuntimeValidationRecovered', 'PYTHON_BASE_ONLY',
    'BUILD_STAGING_VENV_OFFLINE_HASH_LOCKED', '--no-index', '--require-hashes',
    '--only-binary=:all:', 'PIP_CONFIG_FILE', 'PYTHONNOUSERSITE',
    'filesystem_runtime_modified', 'order_check_called', 'order_send_called'
)) {
    Assert-True ($buildVenvGateSource.Contains($required)) "BuildVenv evidence gate lacks invariant: $required"
}
foreach ($forbidden in @(
    'import MetaTrader5', '.initialize(', '.login(', '.account_info(', '.terminal_info(',
    '.symbol_info(', '.order_check(', '.order_send(', 'Set-Acl', 'Start-Service',
    'Invoke-WebRequest', 'https://', 'http://'
)) {
    Assert-True (-not $buildVenvGateSource.Contains($forbidden)) "BuildVenv evidence helper contains forbidden action: $forbidden"
}

foreach ($required in @(
    'Test-TradingLabBuildVenvEvidenceRecord',
    'Test-TradingLabPythonStagingEvidenceRecord',
    'Resolve-TradingLabPromoteArtifactState',
    'Test-TradingLabProcessUsesVenv',
    'Resolve-TradingLabPromoteVenvPlanState',
    'Resolve-TradingLabRollbackExpectation',
    'REBUILD_AT_FINAL_PATH_TRANSACTIONALLY',
    'PRESERVE_READ_ONLY', '--no-index', '--require-hashes', '--only-binary=:all:',
    'PIP_CONFIG_FILE', 'PIP_NO_INDEX', 'PIP_NO_CACHE_DIR', 'PYTHONNOUSERSITE'
)) {
    Assert-True ($promoteVenvGateSource.Contains($required)) "PromoteVenv evidence gate lacks invariant: $required"
}
foreach ($forbidden in @(
    'import MetaTrader5', '.initialize(', '.login(', '.account_info(', '.terminal_info(',
    '.symbol_info(', '.order_check(', '.order_send(', 'Set-Acl', 'Start-Service',
    'Invoke-WebRequest', 'https://', 'http://', 'Remove-Item'
)) {
    Assert-True (-not $promoteVenvGateSource.Contains($forbidden)) "PromoteVenv evidence helper contains forbidden action: $forbidden"
}

foreach ($forbidden in @(
    'Invoke-WebRequest', 'Start-BitsTransfer', 'curl.exe', 'msizap', 'Win32_Product',
    'Remove-Item', 'reg.exe delete', 'Package Cache', 'WriteAllText((Join-Path $Root ''pyvenv.cfg'')',
    'import MetaTrader5', '.initialize(', '.login(', '.symbol_select(', '.order_check(', '.order_send(',
    'Start-Service', 'New-LocalUser', 'Add-LocalGroupMember', 'Invoke-Expression'
)) {
    Assert-True (-not ($installer + $inventorySource + $aclPlanSource + $rightsSource).Contains($forbidden)) "Python recovery gate contains forbidden action: $forbidden"
}
Assert-True (-not $installer.Contains('$modifyMask')) 'Composite Modify mask anti-pattern must be removed from Python recovery.'
Assert-True ($installer.Contains('Test-TradingLabFileSystemRightsMutation')) 'Python recovery must use the centralized atomic mutation classifier.'
Assert-True ($aclGateSource.Contains('Get-TradingLabProhibitedMutationRightsMask')) 'Global ACL gate must share the centralized mutation mask.'
Assert-True ($aclGateSource.Contains('Test-TradingLabFileSystemRightsMutation')) 'Global ACL gate must classify broad-principal mutation semantically.'

$inventoryApply = $installer.IndexOf('INVENTORY_APPLY_FORBIDDEN')
$phaseSwitch = $installer.IndexOf('switch ($Phase)')
Assert-True ($inventoryApply -ge 0 -and $inventoryApply -lt $phaseSwitch) 'Inventory must reject -Apply before phase dispatch.'
$inventoryPhaseStart = $installer.IndexOf("if (`$Phase -eq 'Inventory')")
$inventoryPhaseEnd = $installer.IndexOf('Assert-ExactServiceIdentity', $inventoryPhaseStart)
Assert-True ($inventoryPhaseStart -ge 0 -and $inventoryPhaseEnd -gt $inventoryPhaseStart) 'Inventory read-only phase boundary is absent.'
$inventoryPhaseBlock = $installer.Substring($inventoryPhaseStart, $inventoryPhaseEnd - $inventoryPhaseStart)
foreach ($forbiddenInventoryMutation in @(
    'Set-Acl', 'SetOwner', 'Start-LoggedInstaller', 'Invoke-LoggedProcess',
    'Remove-Item', 'Move-Item', 'New-Item', 'Write-Report', 'Initialize-PhaseStorage'
)) {
    Assert-True (-not $inventoryPhaseBlock.Contains($forbiddenInventoryMutation)) "Inventory phase contains forbidden mutation: $forbiddenInventoryMutation"
}
Assert-True ($installer.Contains("if (`$Phase -in @('Inventory', 'BuildVenv', 'PromoteVenv'))")) 'Inventory, BuildVenv, and PromoteVenv must obtain the same live read-only verification snapshot.'
Assert-True ($installer.IndexOf('Assert-InstallMachinePreconditions $inventory') -lt $installer.IndexOf('Start-LoggedInstaller $plan.executable')) 'Current runtime state must block install execution.'
Assert-True ($installer.IndexOf('$report.previous_phase_verified = $true') -lt $installer.IndexOf("Start-LoggedInstaller `$bundleExecutable")) 'Durable previous-phase verification must precede supported uninstall.'
Assert-True ($installer.IndexOf('Assert-PythonManagerPreserved $inventory $plan') -lt $installer.IndexOf("Start-LoggedInstaller `$bundleExecutable")) 'Manager preservation proof must precede supported uninstall.'
Assert-True ($installer.IndexOf('Assert-UninstallPlanHasNoDirectCleanup $plan') -lt $installer.IndexOf("Start-LoggedInstaller `$bundleExecutable")) 'No-direct-cleanup proof must precede supported uninstall.'
Assert-True (-not $installer.Contains('Move-Item -LiteralPath $stagingVenvPath -Destination $venvPath')) 'PromoteVenv must never relocate staging into the final path.'
Assert-True (-not $installer.Contains('[System.IO.Directory]::Delete($stagingVenvPath')) 'Recovery must retain failed staging for diagnosis.'
Assert-True (-not $installer.Contains('last_applied_phase')) 'Current executions must not expose stale continuity semantics.'
$uninstallStart = $installer.IndexOf("'UninstallTraditional' {")
$uninstallEnd = $installer.IndexOf("'InstallMachineRuntime' {", $uninstallStart)
Assert-True ($uninstallStart -ge 0 -and $uninstallEnd -gt $uninstallStart) 'UninstallTraditional phase boundary is absent.'
$uninstallBlock = $installer.Substring($uninstallStart, $uninstallEnd - $uninstallStart)
foreach ($forbiddenUninstallMutation in @(
    'Remove-Item', 'Remove-ItemProperty', 'Set-ItemProperty', 'reg.exe', 'msiexec',
    '[System.IO.Directory]::Delete', '[System.IO.File]::Delete', 'Move-Item', 'Set-Acl'
)) {
    Assert-True (-not $uninstallBlock.Contains($forbiddenUninstallMutation)) "Uninstall phase contains forbidden direct cleanup: $forbiddenUninstallMutation"
}
Assert-True (($uninstallBlock.Split(@('Start-LoggedInstaller $bundleExecutable'), [System.StringSplitOptions]::None).Count - 1) -eq 1) 'Uninstall phase must contain exactly one supported bundle execution site.'
$installStart = $installer.IndexOf("'InstallMachineRuntime' {")
$installEnd = $installer.IndexOf("'BuildVenv' {", $installStart)
Assert-True ($installStart -ge 0 -and $installEnd -gt $installStart) 'InstallMachineRuntime phase boundary is absent.'
$installBlock = $installer.Substring($installStart, $installEnd - $installStart)
Assert-True ($installBlock.IndexOf("`$report.required_previous_phase = 'UninstallTraditional'") -lt $installBlock.IndexOf('Start-LoggedInstaller $plan.executable')) 'UninstallTraditional continuity must precede installation.'
Assert-True ($installBlock.IndexOf('Get-VerifiedUninstallTraditionalEvidence') -lt $installBlock.IndexOf('Start-LoggedInstaller $plan.executable')) 'Durable UninstallTraditional evidence must precede installation.'
Assert-True ($installBlock.IndexOf('Assert-Wheelhouse $wheelhousePath') -lt $installBlock.IndexOf('Start-LoggedInstaller $plan.executable')) 'Wheelhouse revalidation must precede installation.'
Assert-True ($installBlock.IndexOf('Assert-Installer $InstallerPath') -lt $installBlock.IndexOf('Start-LoggedInstaller $plan.executable')) 'Installer verification must precede installation.'
Assert-True ($installBlock.IndexOf('Test-InstalledMachineRuntimePending $inventory') -lt $installBlock.IndexOf('Start-LoggedInstaller $plan.executable')) 'Installed-validation-pending detection must precede every installer execution site.'
Assert-True ($installBlock.IndexOf('Complete-InstalledMachineRuntime $inventory') -lt $installBlock.IndexOf('Start-LoggedInstaller $plan.executable')) 'Installed runtime recovery must branch before the bootstrapper.'
foreach ($forbiddenInstallMutation in @('.venv.new', 'Move-Item', 'Invoke-LoggedProcess', 'import MetaTrader5')) {
    Assert-True (-not $installBlock.Contains($forbiddenInstallMutation)) "Install phase crosses a forbidden venv/MT5 boundary: $forbiddenInstallMutation"
}
$resumeStart = $installer.IndexOf("'ResumeMachineRuntime' {")
$resumeEnd = $installer.IndexOf("'BuildVenv' {", $resumeStart)
Assert-True ($resumeStart -ge 0 -and $resumeEnd -gt $resumeStart) 'ResumeMachineRuntime phase boundary is absent.'
$resumeBlock = $installer.Substring($resumeStart, $resumeEnd - $resumeStart)
Assert-True ($resumeBlock.Contains('Complete-InstalledMachineRuntime $inventory')) 'Resume phase must use the shared validation/ACL-only recovery path.'
foreach ($forbiddenResumeAction in @('Start-LoggedInstaller', 'Invoke-LoggedProcess', 'Move-Item', '.venv.new')) {
    Assert-True (-not $resumeBlock.Contains($forbiddenResumeAction)) "Resume phase contains forbidden action: $forbiddenResumeAction"
}
$completeStart = $installer.IndexOf('function Complete-InstalledMachineRuntime')
$completeEnd = $installer.IndexOf('function Write-Report', $completeStart)
Assert-True ($completeStart -ge 0 -and $completeEnd -gt $completeStart) 'Shared machine-runtime completion boundary is absent.'
$completeBlock = $installer.Substring($completeStart, $completeEnd - $completeStart)
$dryRunReturn = $completeBlock.IndexOf('if (-not $Apply) { return }')
$aclMutationCall = $completeBlock.IndexOf('Protect-ExactRuntimeTree $pythonBase $aclPlan')
Assert-True ($dryRunReturn -ge 0 -and $aclMutationCall -gt $dryRunReturn) 'Dry-run must return before the only machine runtime ACL mutation call.'
$alreadyAppliedBranch = $completeBlock.IndexOf("if (`$aclState.state -in @('EXACT_PROTECTED', 'SAFE_NO_REPAIR_REQUIRED'))")
$alreadyAppliedReturn = $completeBlock.IndexOf('return', $alreadyAppliedBranch)
Assert-True ($alreadyAppliedBranch -ge 0 -and $alreadyAppliedReturn -gt $alreadyAppliedBranch -and $alreadyAppliedReturn -lt $aclMutationCall) 'Safe ACL recovery must return before Set-Acl.'
$noRepairBlock = $completeBlock.Substring($alreadyAppliedBranch, $alreadyAppliedReturn - $alreadyAppliedBranch)
Assert-True ($noRepairBlock.Contains("`$report.must_not_call_set_acl = `$true")) 'Safe ACL recovery must set MUST_NOT_CALL_SET_ACL.'
Assert-True ($noRepairBlock.Contains("`$report.acl_reapplied = `$false")) 'Safe ACL recovery must report ACL_REAPPLIED=false.'
Assert-True ($noRepairBlock.Contains("`$report.acl_plan = `$null")) 'Safe inherited ACL recovery must not produce a repair plan.'
Assert-True ($noRepairBlock.Contains("`$report.machine_runtime_acl_modified = `$false")) 'Safe inherited ACL recovery must report no runtime ACL mutation.'
Assert-True ($completeBlock.IndexOf('New-MachineRuntimeAclPlan $pythonBase') -gt $alreadyAppliedReturn) 'A recursive ACL plan must only be constructed after the safe no-op branch.'
Assert-True (-not $completeBlock.Substring(0, $dryRunReturn).Contains('Set-Acl')) 'Dry-run path must never call Set-Acl.'
Assert-True (-not $completeBlock.Substring(0, $dryRunReturn).Contains('.SetOwner(')) 'Dry-run path must never modify owner.'
Assert-True ($installer.Contains('Assert-ExactRuntimeTarget $Root')) 'ACL application must validate the exact runtime target.'
Assert-True ($installer.Contains('[System.IO.Directory]::EnumerateFileSystemEntries')) 'ACL tree walk must avoid following reparse points recursively.'
Assert-True ($installer.IndexOf('Assert-InMemoryRuntimeSecurity $directorySecurity $Plan') -lt $installer.IndexOf('Set-Acl -LiteralPath $item.FullName')) 'In-memory directory ACL validation must precede filesystem mutation.'
Assert-True ($installer.IndexOf('Assert-InMemoryRuntimeSecurity $fileSecurity $Plan') -lt $installer.IndexOf('Set-Acl -LiteralPath $item.FullName')) 'In-memory file ACL validation must precede filesystem mutation.'
Assert-True ($inventorySource.Contains("`$startInfo.Arguments = '-B -I -'")) 'Python metadata must execute stdin source with -B -I and python -.'
Assert-True ($inventorySource.Contains('RedirectStandardInput = $true')) 'Python stdin must be redirected explicitly.'
Assert-True ($inventorySource.Contains('$process.StandardInput.Write($Source)')) 'Python source must be written verbatim to stdin.'
Assert-True (-not $inventorySource.Contains("-I -c")) 'Python metadata must not use fragile -c quoting.'
Assert-True ($inventorySource.Contains("separators=(',', ':')")) 'Metadata JSON quoting regression is not covered.'
$buildStart = $installer.IndexOf("'BuildVenv' {")
$buildEnd = $installer.IndexOf("'PromoteVenv' {", $buildStart)
$buildBlock = $installer.Substring($buildStart, $buildEnd - $buildStart)
Assert-True ($buildBlock.IndexOf('Assert-FinalVerifiedMachineRuntimeInventory $inventory') -ge 0) 'BuildVenv must require the final verified Inventory state.'
Assert-True ($buildBlock.IndexOf('Assert-FinalVerifiedMachineRuntimeInventory $inventory') -lt $buildBlock.IndexOf('Invoke-BuildVenvProcess $createStep.executable')) 'BuildVenv verification must precede venv creation.'
Assert-True ($buildBlock.IndexOf("`$report.gates.STAGING_VENV_ABSENT = 'PASS'") -lt $buildBlock.IndexOf('Invoke-BuildVenvProcess $createStep.executable')) 'Staging absence must precede venv creation.'
Assert-True ($buildBlock.Contains("`$report.required_previous_phase = 'ResumeMachineRuntime'")) 'BuildVenv must require ResumeMachineRuntime evidence.'
Assert-True ($buildBlock.Contains('Get-VerifiedPythonBaseRuntimeEvidence')) 'BuildVenv must verify both explicit token reports.'
Assert-True ($buildBlock.Contains('staging_left_for_inspection')) 'BuildVenv failure must retain staging for inspection.'
$buildDryReturn = $buildBlock.IndexOf('if (-not $Apply) { break }')
Assert-True ($buildDryReturn -ge 0 -and $buildDryReturn -lt $buildBlock.IndexOf('Initialize-PhaseStorage')) 'BuildVenv dry-run must stop before storage mutation.'
Assert-True ($buildDryReturn -lt $buildBlock.IndexOf('Invoke-BuildVenvProcess $createStep.executable')) 'BuildVenv dry-run must stop before staging creation.'
foreach ($forbiddenBuildBoundary in @('Set-Acl', 'Move-Item -LiteralPath $venvPath', 'import MetaTrader5', 'Start-Service')) {
    Assert-True (-not $buildBlock.Contains($forbiddenBuildBoundary)) "BuildVenv crosses forbidden boundary: $forbiddenBuildBoundary"
}
$promoteStart = $installer.IndexOf("'PromoteVenv' {")
Assert-True ($promoteStart -ge 0) 'PromoteVenv phase boundary is absent.'
$promoteBlock = $installer.Substring($promoteStart)
foreach ($requiredPromoteBoundary in @(
    "`$report.promotion_strategy = 'REBUILD_AT_FINAL_PATH_TRANSACTIONALLY'",
    'Get-VerifiedBuildVenvEvidence', 'Get-VerifiedPythonStagingRuntimeEvidence',
    'Assert-ExactVenvLiveReadOnly', 'Get-VenvProcessUsers',
    'Assert-PromotionArtifactsAbsent', 'New-PromoteVenvPlan',
    'Assert-PromoteVenvPlan', 'Get-VenvTreeFingerprint',
    'Get-FinalNonRelocationAudit', 'Invoke-PromoteVenvRollback',
    "`$report.staging_promoted = `$false", "`$report.must_not_call_set_acl = `$true"
)) {
    Assert-True ($promoteBlock.Contains($requiredPromoteBoundary)) "PromoteVenv phase lacks boundary: $requiredPromoteBoundary"
}
$promoteDryReturn = $promoteBlock.IndexOf('if (-not $Apply) { break }')
Assert-True ($promoteDryReturn -ge 0 -and $promoteDryReturn -lt $promoteBlock.IndexOf('Initialize-PhaseStorage')) 'PromoteVenv dry-run must stop before runtime storage mutation.'
Assert-True ($promoteDryReturn -lt $promoteBlock.IndexOf('[System.IO.Directory]::Move($venvPath, $report.promote_venv_plan.backup_path)')) 'PromoteVenv dry-run must stop before active backup.'
Assert-True (-not $promoteBlock.Contains('[System.IO.Directory]::Move($stagingVenvPath')) 'PromoteVenv must never move or rename staging.'
Assert-True (-not $promoteBlock.Contains('[System.IO.Directory]::Delete')) 'PromoteVenv must preserve active failure artifacts, backups, and staging.'
foreach ($forbiddenPromoteBoundary in @(
    'Set-Acl', 'import MetaTrader5', '.initialize(', '.login(', '.terminal_info(',
    '.account_info(', '.symbol_info(', '.order_check(', '.order_send(',
    'Start-Service', 'Stop-Service', 'Start-LoggedInstaller'
)) {
    Assert-True (-not $promoteBlock.Contains($forbiddenPromoteBoundary)) "PromoteVenv crosses forbidden boundary: $forbiddenPromoteBoundary"
}

. $inventoryPath
. $buildVenvGatePath
. $promoteVenvGatePath
. $aclPlanPath
. $rightsPath

function Copy-TestFixture([object] $Value) {
    return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
}

$resumeFixture = [pscustomobject]@{
    schema_version = 3; phase = 'ResumeMachineRuntime'; apply_requested = $true
    status = 'PASS'; trading_mode = 'OBSERVE_ONLY'; python_version = '3.14.5'
    python_base = 'C:\Program Files\AutomatonPython\3.14.5'
    current_run_applied_phase = 'MachineRuntimeValidationRecovered'
    required_previous_phase = 'InstallMachineRuntime'; previous_phase_verified = $true
    previous_phase_report = 'C:\protected\install.json'; previous_phase_report_sha256 = ('a' * 64)
    installer_executed = $false; installer_reexecuted = $false
    must_not_call_set_acl = $true; set_acl_call_count = 0; machine_runtime_acl_modified = $false
    venv_rebuilt = $false; venv_promoted = $false; mt5_accessed = $false
    gateway_started = $false; automaton_started = $false; error = $null
    gates = [pscustomobject]@{
        PYTHON_RUNTIME_ACL = 'PASS'; PYTHON_VERSION_EXACT = 'PASS'; PYTHON_ARCH_X64 = 'PASS'
        PYTHON_BASE_PREFIX_TARGET = 'PASS'; PYTHON_EXECUTABLE_TARGET = 'PASS'
        EXPECTED_MACHINE_MSI_COMPONENTS = 4; UNEXPECTED_MACHINE_MSI_COMPONENTS = 0
    }
}
Assert-True (Test-TradingLabResumeMachineRuntimeReportRecord $resumeFixture '3.14.5' $resumeFixture.python_base) 'Valid ResumeMachineRuntime evidence must pass.'
$failedResume = Copy-TestFixture $resumeFixture; $failedResume.status = 'FAIL'
Assert-True (-not (Test-TradingLabResumeMachineRuntimeReportRecord $failedResume '3.14.5' $resumeFixture.python_base)) 'Resume status other than PASS must fail closed.'
$wrongResumeRuntime = Copy-TestFixture $resumeFixture; $wrongResumeRuntime.python_base = 'C:\Program Files\OtherPython'
Assert-True (-not (Test-TradingLabResumeMachineRuntimeReportRecord $wrongResumeRuntime '3.14.5' $resumeFixture.python_base)) 'Resume evidence for a different runtime must fail closed.'
$resumeEvidenceRoot = Join-Path $env:TEMP ('automaton-build-resume-' + [guid]::NewGuid().ToString('D'))
[void][System.IO.Directory]::CreateDirectory($resumeEvidenceRoot)
try {
    $missingResume = $false
    try { [void](Find-TradingLabResumeMachineRuntimeReport $resumeEvidenceRoot '3.14.5' $resumeFixture.python_base) }
    catch { $missingResume = $_.Exception.Message -like 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL*' }
    Assert-True $missingResume 'Missing ResumeMachineRuntime evidence must fail closed.'
    Set-Content -LiteralPath (Join-Path $resumeEvidenceRoot 'python-runtime-corrupt.json') -Value '{bad-json' -Encoding UTF8
    $corruptResume = $false
    try { [void](Find-TradingLabResumeMachineRuntimeReport $resumeEvidenceRoot '3.14.5' $resumeFixture.python_base) }
    catch { $corruptResume = $_.Exception.Message -like 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL*corrupt*' }
    Assert-True $corruptResume 'Corrupt ResumeMachineRuntime evidence must fail closed.'
} finally { [System.IO.Directory]::Delete($resumeEvidenceRoot, $true) }
$ambiguousResumeRoot = Join-Path $env:TEMP ('automaton-build-resume-ambiguous-' + [guid]::NewGuid().ToString('D'))
[void][System.IO.Directory]::CreateDirectory($ambiguousResumeRoot)
try {
    $resumeFixture | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $ambiguousResumeRoot 'python-runtime-one.json') -Encoding UTF8
    $resumeFixture | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $ambiguousResumeRoot 'python-runtime-two.json') -Encoding UTF8
    $ambiguousResume = $false
    try { [void](Find-TradingLabResumeMachineRuntimeReport $ambiguousResumeRoot '3.14.5' $resumeFixture.python_base) }
    catch { $ambiguousResume = $_.Exception.Message -like 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL*ambiguous*' }
    Assert-True $ambiguousResume 'Ambiguous ResumeMachineRuntime PASS evidence must fail closed.'
} finally { [System.IO.Directory]::Delete($ambiguousResumeRoot, $true) }

function New-PythonBaseEvidenceFixture([string] $Role, [string] $RunId, [string] $Sid) {
    $tests = [ordered]@{}
    foreach ($entry in (Get-TradingLabPythonBaseExpectedTests $Role $Sid).GetEnumerator()) {
        $tests[$entry.Key] = [ordered]@{
            expected = $entry.Value[0]; observed = $entry.Value[1]; passed = $true; evidence = 'SYNTHETIC'
        }
    }
    return [pscustomobject]@{
        schema_version = 1; mode = 'PYTHON_BASE_ONLY'; role = $Role; run_id = $RunId
        effective_sid = $Sid; status = 'PASS'; runtime_error = $null; tests = [pscustomobject]$tests
        boundaries = [pscustomobject]@{
            trading_mode = 'OBSERVE_ONLY'; build_venv = $false; mt5_accessed = $false
            order_check_called = $false; order_send_called = $false; gateway_started = $false
            automaton_started = $false; venv_accessed = $false; venv_new_accessed = $false
            acl_modified = $false; filesystem_runtime_modified = $false
        }
    }
}
$gatewayFixtureRunId = '00000000-0000-0000-0000-000000000101'
$agentFixtureRunId = '00000000-0000-0000-0000-000000000102'
$gatewayFixtureSid = 'S-1-5-21-1-2-3-1007'
$agentFixtureSid = 'S-1-5-21-1-2-3-1006'
$gatewayFixture = New-PythonBaseEvidenceFixture 'AutomatonGateway' $gatewayFixtureRunId $gatewayFixtureSid
$agentFixture = New-PythonBaseEvidenceFixture 'AutomatonAgent' $agentFixtureRunId $agentFixtureSid
Assert-True (Test-TradingLabPythonBaseRuntimeEvidenceRecord $gatewayFixture 'AutomatonGateway' $gatewayFixtureRunId $gatewayFixtureSid) 'Valid Gateway token evidence must pass.'
Assert-True (Test-TradingLabPythonBaseRuntimeEvidenceRecord $agentFixture 'AutomatonAgent' $agentFixtureRunId $agentFixtureSid) 'Valid Agent token evidence must pass.'
foreach ($case in @(
    [pscustomobject]@{ Name = 'wrong RunId'; Record = $( $copy = Copy-TestFixture $gatewayFixture; $copy.run_id = '00000000-0000-0000-0000-000000000999'; $copy ) },
    [pscustomobject]@{ Name = 'wrong SID'; Record = $( $copy = Copy-TestFixture $gatewayFixture; $copy.effective_sid = 'S-1-5-21-wrong'; $copy ) },
    [pscustomobject]@{ Name = 'failed status'; Record = $( $copy = Copy-TestFixture $gatewayFixture; $copy.status = 'FAIL'; $copy ) },
    [pscustomobject]@{ Name = 'boundary violation'; Record = $( $copy = Copy-TestFixture $gatewayFixture; $copy.boundaries.mt5_accessed = $true; $copy ) }
)) {
    Assert-True (-not (Test-TradingLabPythonBaseRuntimeEvidenceRecord $case.Record 'AutomatonGateway' $gatewayFixtureRunId $gatewayFixtureSid)) "Gateway $($case.Name) must fail closed."
}
foreach ($case in @(
    [pscustomobject]@{ Name = 'wrong RunId'; Record = $( $copy = Copy-TestFixture $agentFixture; $copy.run_id = '00000000-0000-0000-0000-000000000999'; $copy ) },
    [pscustomobject]@{ Name = 'wrong SID'; Record = $( $copy = Copy-TestFixture $agentFixture; $copy.effective_sid = 'S-1-5-21-wrong'; $copy ) },
    [pscustomobject]@{ Name = 'failed status'; Record = $( $copy = Copy-TestFixture $agentFixture; $copy.status = 'FAIL'; $copy ) },
    [pscustomobject]@{ Name = 'boundary violation'; Record = $( $copy = Copy-TestFixture $agentFixture; $copy.boundaries.venv_accessed = $true; $copy ) }
)) {
    Assert-True (-not (Test-TradingLabPythonBaseRuntimeEvidenceRecord $case.Record 'AutomatonAgent' $agentFixtureRunId $agentFixtureSid)) "Agent $($case.Name) must fail closed."
}
$tokenEvidenceRoot = Join-Path $env:TEMP ('automaton-build-token-' + [guid]::NewGuid().ToString('D'))
[void][System.IO.Directory]::CreateDirectory($tokenEvidenceRoot)
try {
    $missingToken = $false
    try { [void](Read-TradingLabPythonBaseRuntimeEvidenceFile (Join-Path $tokenEvidenceRoot 'missing.json') 'AutomatonGateway' $gatewayFixtureRunId $gatewayFixtureSid) }
    catch { $missingToken = $_.Exception.Message -like 'PYTHON_BASE_RUNTIME_EVIDENCE=FAIL*absent*' }
    Assert-True $missingToken 'Missing explicit PythonBaseOnly report must fail closed.'
    $missingAgentToken = $false
    try { [void](Read-TradingLabPythonBaseRuntimeEvidenceFile (Join-Path $tokenEvidenceRoot 'missing-agent.json') 'AutomatonAgent' $agentFixtureRunId $agentFixtureSid) }
    catch { $missingAgentToken = $_.Exception.Message -like 'PYTHON_BASE_RUNTIME_EVIDENCE=FAIL*absent*' }
    Assert-True $missingAgentToken 'Missing explicit Agent PythonBaseOnly report must fail closed.'
    $corruptTokenPath = Join-Path $tokenEvidenceRoot 'corrupt.json'
    Set-Content -LiteralPath $corruptTokenPath -Value '{bad-json' -Encoding UTF8
    $corruptToken = $false
    try { [void](Read-TradingLabPythonBaseRuntimeEvidenceFile $corruptTokenPath 'AutomatonGateway' $gatewayFixtureRunId $gatewayFixtureSid) }
    catch { $corruptToken = $_.Exception.Message -like 'PYTHON_BASE_RUNTIME_EVIDENCE=FAIL*invalid*' }
    Assert-True $corruptToken 'Corrupt explicit PythonBaseOnly report must fail closed.'
} finally { [System.IO.Directory]::Delete($tokenEvidenceRoot, $true) }

$basePlanPython = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'
$planStaging = 'C:\automaton\.venv.new'
$planLock = 'C:\automaton\requirements-gateway-win-py314.lock'
$planWheelhouse = 'C:\ProgramData\AutomatonMT5Lab\maintenance\wheelhouse\cp314-win_amd64'
$planActive = 'C:\automaton\.venv'
$planEnvironment = [pscustomobject]@{
    PIP_CONFIG_FILE='NUL'; PIP_NO_INDEX='1'; PIP_DISABLE_PIP_VERSION_CHECK='1'; PIP_NO_CACHE_DIR='1'
    PYTHONNOUSERSITE='1'; PYTHONDONTWRITEBYTECODE='1'
    TEMP='C:\ProgramData\AutomatonMT5Lab\maintenance\runtime-tmp\build-venv-test'
    TMP='C:\ProgramData\AutomatonMT5Lab\maintenance\runtime-tmp\build-venv-test'
}
$validBuildPlan = [pscustomobject]@{
    operation='BUILD_STAGING_VENV_OFFLINE_HASH_LOCKED'; base_python=$basePlanPython
    staging_venv=$planStaging; lock_file=$planLock; wheelhouse=$planWheelhouse
    temp_path='C:\ProgramData\AutomatonMT5Lab\maintenance\runtime-tmp\build-venv-test'
    steps=@(
        [pscustomobject]@{ executable=$basePlanPython; arguments=@('-B','-I','-m','venv',$planStaging); use_shell=$false; environment=$planEnvironment },
        [pscustomobject]@{ executable=(Join-Path $planStaging 'Scripts\python.exe'); arguments=@('-B','-I','-m','pip','install','--disable-pip-version-check','--no-input','--no-index','--find-links',$planWheelhouse,'--require-hashes','--only-binary=:all:','-r',$planLock); use_shell=$false; environment=$planEnvironment }
    )
}
Assert-True (Resolve-TradingLabBuildVenvPlanState $validBuildPlan $basePlanPython $planStaging $planLock $planWheelhouse $planActive).valid 'Exact offline BuildVenv plan must pass.'
$userPythonPlan = Copy-TestFixture $validBuildPlan; $userPythonPlan.base_python='C:\Users\Admin\python.exe'; $userPythonPlan.steps[0].executable=$userPythonPlan.base_python
Assert-True (-not (Resolve-TradingLabBuildVenvPlanState $userPythonPlan $basePlanPython $planStaging $planLock $planWheelhouse $planActive).valid) 'User-profile base Python must fail closed.'
$activePythonPlan = Copy-TestFixture $validBuildPlan; $activePythonPlan.steps[1].executable=(Join-Path $planActive 'Scripts\python.exe')
Assert-True (-not (Resolve-TradingLabBuildVenvPlanState $activePythonPlan $basePlanPython $planStaging $planLock $planWheelhouse $planActive).valid) 'Active venv Python must fail closed.'
foreach ($missingArgument in @('--no-index','--require-hashes','--only-binary=:all:')) {
    $badPlan = Copy-TestFixture $validBuildPlan
    $badPlan.steps[1].arguments = @($badPlan.steps[1].arguments | Where-Object { $_ -ne $missingArgument })
    Assert-True (-not (Resolve-TradingLabBuildVenvPlanState $badPlan $basePlanPython $planStaging $planLock $planWheelhouse $planActive).valid) "Pip without $missingArgument must fail closed."
}
$urlPlan = Copy-TestFixture $validBuildPlan; $urlPlan.steps[1].arguments += 'https://example.invalid/wheel.whl'
Assert-True (-not (Resolve-TradingLabBuildVenvPlanState $urlPlan $basePlanPython $planStaging $planLock $planWheelhouse $planActive).valid) 'Pip URL must fail closed.'

$lockedDistributions = @(1..27 | ForEach-Object { [pscustomobject]@{ name="package$_"; version='1.0' } })
$installedDistributions = @($lockedDistributions | ForEach-Object { [pscustomobject]@{ name=$_.name; version=$_.version } }) + @([pscustomobject]@{name='pip';version='26.0'})
$distributionState = Resolve-TradingLabStagingDistributionState $lockedDistributions $installedDistributions @('pip')
Assert-True ($distributionState.valid -and $distributionState.expected_requirements -eq 27) 'Exact 27 locked distributions plus pip must pass.'
$missingDistributionState = Resolve-TradingLabStagingDistributionState $lockedDistributions @($installedDistributions | Where-Object {$_.name -ne 'package1'}) @('pip')
Assert-True (-not $missingDistributionState.valid -and $missingDistributionState.missing_requirements.Count -eq 1) 'Missing staging distribution must fail closed.'
$unexpectedDistributionState = Resolve-TradingLabStagingDistributionState $lockedDistributions @($installedDistributions + [pscustomobject]@{name='unexpected';version='1.0'}) @('pip')
Assert-True (-not $unexpectedDistributionState.valid -and $unexpectedDistributionState.unexpected_distributions.Count -eq 1) 'Unexpected staging distribution must fail closed.'

$promoteRunId = '00000000-0000-0000-0000-000000000201'
$promoteGatewayRunId = '00000000-0000-0000-0000-000000000202'
$promoteAgentRunId = '00000000-0000-0000-0000-000000000203'
$promoteBase = 'C:\Program Files\AutomatonPython\3.14.5'
$promoteBasePython = Join-Path $promoteBase 'python.exe'
$promoteActive = 'C:\automaton\.venv'
$promoteStaging = 'C:\automaton\.venv.new'
$promoteBackup = "C:\automaton\.venv.backup.$promoteRunId"
$promoteFailed = "C:\automaton\.venv.failed.$promoteRunId"
$promoteWheelhouse = 'C:\ProgramData\AutomatonMT5Lab\maintenance\wheelhouse\cp314-win_amd64'
$promoteLock = 'C:\automaton\requirements-gateway-win-py314.lock'
$promoteTemp = "C:\ProgramData\AutomatonMT5Lab\maintenance\runtime-tmp\promote-venv-$promoteRunId"

$buildEvidence = [pscustomobject]@{
    schema_version=3; run_id=$promoteRunId; phase='BuildVenv'; status='PASS'; apply_requested=$true
    current_run_applied_phase='BuildVenv'; trading_mode='OBSERVE_ONLY'; python_base=$promoteBase
    active_venv=$promoteActive; staging_venv=$promoteStaging; wheelhouse=$promoteWheelhouse; lock_file=$promoteLock
    staging_venv_created=$true; staging_build_failed=$false; venv_rebuilt=$true; venv_promoted=$false
    mt5_package_installed=$true; must_not_call_set_acl=$true; must_not_execute_installer=$true
    active_venv_modified=$false; active_venv_deleted=$false; active_venv_renamed=$false; active_venv_executed=$false
    installer_executed=$false; installer_reexecuted=$false; mt5_imported=$false; mt5_accessed=$false
    order_check_called=$false; order_send_called=$false; gateway_started=$false; automaton_started=$false
    acl_modified=$false; set_acl_call_count=0
}
Assert-True (Test-TradingLabBuildVenvEvidenceRecord $buildEvidence $promoteRunId $promoteBase $promoteActive $promoteStaging $promoteWheelhouse $promoteLock) 'Exact BuildVenv evidence must pass.'
Assert-True (-not (Test-TradingLabBuildVenvEvidenceRecord $null $promoteRunId $promoteBase $promoteActive $promoteStaging $promoteWheelhouse $promoteLock)) 'Missing BuildVenv evidence must fail closed.'
foreach ($case in @(
    [pscustomobject]@{ Name='wrong RunId'; Property='run_id'; Value='00000000-0000-0000-0000-000000000999' },
    [pscustomobject]@{ Name='wrong phase'; Property='phase'; Value='Inventory' },
    [pscustomobject]@{ Name='failed status'; Property='status'; Value='FAIL' },
    [pscustomobject]@{ Name='staging absent'; Property='staging_venv_created'; Value=$false },
    [pscustomobject]@{ Name='already promoted'; Property='venv_promoted'; Value=$true },
    [pscustomobject]@{ Name='active modified'; Property='active_venv_modified'; Value=$true },
    [pscustomobject]@{ Name='MT5 imported'; Property='mt5_imported'; Value=$true },
    [pscustomobject]@{ Name='MT5 accessed'; Property='mt5_accessed'; Value=$true }
)) {
    $record = Copy-TestFixture $buildEvidence
    $record.($case.Property) = $case.Value
    Assert-True (-not (Test-TradingLabBuildVenvEvidenceRecord $record $promoteRunId $promoteBase $promoteActive $promoteStaging $promoteWheelhouse $promoteLock)) "BuildVenv evidence $($case.Name) must fail closed."
}

function New-PythonStagingEvidenceFixture([string] $Role, [string] $RunId, [string] $Sid) {
    $tests = [ordered]@{}
    foreach ($name in Get-TradingLabStagingCriticalTests $Role) {
        $expectation = if ($name -eq 'IDENTITY') { $Sid }
            elseif ($name -in @('STAGING_PYTHON_READ','STAGING_SITE_PACKAGES_READ')) { 'ALLOW' }
            elseif ($name -in @(
                'STAGING_CREATE_FILE_DENY','STAGING_CREATE_DIRECTORY_DENY','STAGING_WRITE_DENY',
                'STAGING_APPEND_DENY','STAGING_TRUNCATE_DENY','STAGING_RENAME_DENY',
                'STAGING_DELETE_DENY','STAGING_WRITE_ATTRIBUTES_DENY','STAGING_CHANGE_ACL_DENY',
                'STAGING_TAKE_OWNERSHIP_DENY','STAGING_PYTHON_FUNCTIONAL_EXECUTION_DENY'
            )) { 'DENY' }
            elseif ($name -eq 'STAGING_METATRADER5_IMPORTED') { 'false' }
            else { 'PASS' }
        $evidence = if ($name -eq 'STAGING_ENUMERATE') { 'ITEMS_ENUMERATED_5406' } else { 'SYNTHETIC' }
        $tests[$name] = [pscustomobject]@{ passed=$true; expected=$expectation; observed=$expectation; evidence=$evidence }
    }
    $exitCode = if ($Role -eq 'AutomatonGateway') { 0 } else { 103 }
    return [pscustomobject]@{
        schema_version=1; mode='PYTHON_STAGING_ONLY'; role=$Role; run_id=$RunId
        effective_sid=$Sid; status='PASS'; runtime_error=$null; tests=[pscustomobject]$tests
        execution=[pscustomobject]@{ process_started=$true; exit_code=$exitCode; success_marker_observed=$false }
        boundaries=[pscustomobject]@{
            trading_mode='OBSERVE_ONLY'; build_venv=$false; promote_venv=$false
            active_venv_accessed=$false; active_venv_modified=$false
            mt5_imported=$false; mt5_accessed=$false; order_check_called=$false; order_send_called=$false
            gateway_started=$false; automaton_started=$false; acl_modified=$false; filesystem_staging_modified=$false
        }
    }
}
$promoteGatewaySid = 'S-1-5-21-1-2-3-1007'
$promoteAgentSid = 'S-1-5-21-1-2-3-1006'
$gatewayStagingEvidence = New-PythonStagingEvidenceFixture 'AutomatonGateway' $promoteGatewayRunId $promoteGatewaySid
$agentStagingEvidence = New-PythonStagingEvidenceFixture 'AutomatonAgent' $promoteAgentRunId $promoteAgentSid
Assert-True (Test-TradingLabPythonStagingEvidenceRecord $gatewayStagingEvidence 'AutomatonGateway' $promoteGatewayRunId $promoteGatewaySid) 'Exact Gateway staging evidence must pass.'
Assert-True (Test-TradingLabPythonStagingEvidenceRecord $agentStagingEvidence 'AutomatonAgent' $promoteAgentRunId $promoteAgentSid) 'Exact Agent staging evidence must pass.'
Assert-True ((Get-TradingLabStagingEvidenceTreeCount $gatewayStagingEvidence) -eq 5406) 'Gateway staging evidence tree count must be exact and parseable.'
Assert-True (-not (Test-TradingLabPythonStagingEvidenceRecord $null 'AutomatonGateway' $promoteGatewayRunId $promoteGatewaySid)) 'Missing Gateway staging evidence must fail closed.'
Assert-True (-not (Test-TradingLabPythonStagingEvidenceRecord $null 'AutomatonAgent' $promoteAgentRunId $promoteAgentSid)) 'Missing Agent staging evidence must fail closed.'
foreach ($roleCase in @(
    [pscustomobject]@{ Role='AutomatonGateway'; RunId=$promoteGatewayRunId; Sid=$promoteGatewaySid; Fixture=$gatewayStagingEvidence },
    [pscustomobject]@{ Role='AutomatonAgent'; RunId=$promoteAgentRunId; Sid=$promoteAgentSid; Fixture=$agentStagingEvidence }
)) {
    foreach ($case in @(
        [pscustomobject]@{ Name='wrong UUID'; Property='run_id'; Value='00000000-0000-0000-0000-000000000999' },
        [pscustomobject]@{ Name='wrong SID'; Property='effective_sid'; Value='S-1-5-21-wrong' },
        [pscustomobject]@{ Name='wrong role'; Property='role'; Value='WrongRole' },
        [pscustomobject]@{ Name='wrong mode'; Property='mode'; Value='PYTHON_BASE_ONLY' },
        [pscustomobject]@{ Name='failed status'; Property='status'; Value='FAIL' }
    )) {
        $record = Copy-TestFixture $roleCase.Fixture; $record.($case.Property) = $case.Value
        Assert-True (-not (Test-TradingLabPythonStagingEvidenceRecord $record $roleCase.Role $roleCase.RunId $roleCase.Sid)) "$($roleCase.Role) staging $($case.Name) must fail closed."
    }
    $testFailure = Copy-TestFixture $roleCase.Fixture
    $criticalName = (Get-TradingLabStagingCriticalTests $roleCase.Role)[-1]
    $testFailure.tests.$criticalName.passed = $false
    Assert-True (-not (Test-TradingLabPythonStagingEvidenceRecord $testFailure $roleCase.Role $roleCase.RunId $roleCase.Sid)) "$($roleCase.Role) critical test failure must fail closed."
    $mutationAllow = Copy-TestFixture $roleCase.Fixture
    $mutationAllow.tests.STAGING_WRITE_DENY.passed = $false
    Assert-True (-not (Test-TradingLabPythonStagingEvidenceRecord $mutationAllow $roleCase.Role $roleCase.RunId $roleCase.Sid)) "$($roleCase.Role) unexpected mutation allow must fail closed."
    $boundaryViolation = Copy-TestFixture $roleCase.Fixture
    $boundaryViolation.boundaries.filesystem_staging_modified = $true
    Assert-True (-not (Test-TradingLabPythonStagingEvidenceRecord $boundaryViolation $roleCase.Role $roleCase.RunId $roleCase.Sid)) "$($roleCase.Role) staging boundary violation must fail closed."
    $structuralEvidenceInvalid = Copy-TestFixture $roleCase.Fixture
    $structuralEvidenceInvalid.tests.STAGING_ENUMERATE.evidence = 'ITEMS_ENUMERATED_INVALID'
    Assert-True (-not (Test-TradingLabPythonStagingEvidenceRecord $structuralEvidenceInvalid $roleCase.Role $roleCase.RunId $roleCase.Sid)) "$($roleCase.Role) malformed staging tree evidence must fail closed."
}
$agentUnexpectedExecution = Copy-TestFixture $agentStagingEvidence
$agentUnexpectedExecution.execution.exit_code = 0; $agentUnexpectedExecution.execution.success_marker_observed = $true
Assert-True (-not (Test-TradingLabPythonStagingEvidenceRecord $agentUnexpectedExecution 'AutomatonAgent' $promoteAgentRunId $promoteAgentSid)) 'Agent functional execution unexpectedly allowed must fail closed.'

Assert-True (Test-TradingLabProcessUsesVenv 'C:\automaton\.venv\Scripts\python.exe' '' $promoteActive) 'Process executable under active venv must be detected.'
Assert-True (Test-TradingLabProcessUsesVenv '' 'worker C:\automaton\.venv.new\Scripts\python.exe' $promoteStaging) 'Process command line under staging venv must be detected.'
Assert-True (-not (Test-TradingLabProcessUsesVenv 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' 'safe-worker' $promoteActive)) 'Unrelated process must not be attributed to active venv.'

Assert-True (Resolve-TradingLabPromoteArtifactState $false $false 0 0).valid 'Absent promotion artifacts must pass.'
foreach ($artifactCase in @(
    @( $true, $false, 0, 0 ), @( $false, $true, 0, 0 ),
    @( $false, $false, 1, 0 ), @( $false, $false, 0, 1 )
)) {
    Assert-True (-not (Resolve-TradingLabPromoteArtifactState @artifactCase).valid) 'Any preexisting promotion artifact must fail closed.'
}

$promoteEnvironment = [pscustomobject]@{
    PIP_CONFIG_FILE='NUL'; PIP_NO_INDEX='1'; PIP_DISABLE_PIP_VERSION_CHECK='1'; PIP_NO_CACHE_DIR='1'
    PYTHONNOUSERSITE='1'; PYTHONDONTWRITEBYTECODE='1'; TEMP=$promoteTemp; TMP=$promoteTemp
}
$validPromotePlan = [pscustomobject]@{
    promotion_strategy='REBUILD_AT_FINAL_PATH_TRANSACTIONALLY'; active_venv=$promoteActive
    staging_venv_read_only=$promoteStaging; staging_action='PRESERVE_READ_ONLY'
    backup_path=$promoteBackup; failed_path=$promoteFailed; base_python=$promoteBasePython
    lock_file=$promoteLock; wheelhouse=$promoteWheelhouse
    temp_path=$promoteTemp
    steps=@(
        [pscustomobject]@{ phase='BACKUP'; operation='RENAME_DIRECTORY_SAME_VOLUME'; source=$promoteActive; destination=$promoteBackup; copy=$false; delete=$false; call_set_acl=$false },
        [pscustomobject]@{ phase='CREATE_FINAL'; operation='CREATE_VENV_AT_FINAL_PATH'; executable=$promoteBasePython; arguments=@('-B','-I','-m','venv',$promoteActive); target=$promoteActive; use_shell=$false; environment=$promoteEnvironment },
        [pscustomobject]@{ phase='INSTALL_FINAL'; operation='INSTALL_HASH_LOCKED_WHEELS_OFFLINE'; executable=(Join-Path $promoteActive 'Scripts\python.exe'); arguments=@('-B','-I','-m','pip','install','--disable-pip-version-check','--no-input','--no-index','--find-links',$promoteWheelhouse,'--require-hashes','--only-binary=:all:','-r',$promoteLock); target=$promoteActive; use_shell=$false; environment=$promoteEnvironment },
        [pscustomobject]@{ phase='VALIDATE_FINAL'; operation='VALIDATE_READ_ONLY'; executable=(Join-Path $promoteActive 'Scripts\python.exe'); arguments=@('-B','-I','-'); source_transport='STDIN'; target=$promoteActive; import_allowlist=@('fastapi','pydantic','yaml','uvicorn'); metatrader5_validation='IMPORTLIB_METADATA_ONLY'; use_shell=$false },
        [pscustomobject]@{ phase='NON_RELOCATION'; operation='SCAN_FINAL_ASCII_UTF16LE_READ_ONLY'; target=$promoteActive; forbidden_reference=$promoteStaging; expected_references=0; expected_read_errors=0 },
        [pscustomobject]@{ phase='ACL'; operation='VALIDATE_READ_ONLY'; target=$promoteActive; inherit_from='C:\automaton'; call_set_acl=$false }
    )
}
Assert-True (Resolve-TradingLabPromoteVenvPlanState $validPromotePlan $promoteBasePython $promoteActive $promoteStaging $promoteBackup $promoteFailed $promoteLock $promoteWheelhouse $promoteTemp).valid 'Exact transactional PromoteVenv plan must pass.'
$orderedPlanSeed = Copy-TestFixture $validPromotePlan
$orderedPromoteEnvironment = [ordered]@{}
foreach ($property in $promoteEnvironment.PSObject.Properties) {
    $orderedPromoteEnvironment[$property.Name] = $property.Value
}
$orderedPlanSeed.steps[1].environment = $orderedPromoteEnvironment
$orderedPlanSeed.steps[2].environment = $orderedPromoteEnvironment
$orderedPromotePlan = [ordered]@{}
foreach ($property in $orderedPlanSeed.PSObject.Properties) {
    $orderedPromotePlan[$property.Name] = $property.Value
}
Assert-True ((Get-TradingLabPromoteProperty $orderedPromotePlan 'promotion_strategy') -eq 'REBUILD_AT_FINAL_PATH_TRANSACTIONALLY') 'PromoteVenv property access must support the OrderedDictionary emitted by the live plan builder.'
Assert-True ((Get-TradingLabPromotePropertyCount $orderedPromoteEnvironment) -eq 8) 'PromoteVenv must count live OrderedDictionary environment keys, not adapter properties.'
Assert-True (Resolve-TradingLabPromoteVenvPlanState $orderedPromotePlan $promoteBasePython $promoteActive $promoteStaging $promoteBackup $promoteFailed $promoteLock $promoteWheelhouse $promoteTemp).valid 'The live OrderedDictionary PromoteVenv plan shape must validate.'
foreach ($planCase in @(
    [pscustomobject]@{ Name='relocates staging'; Mutate={ param($p) $p.steps[0].source=$promoteStaging } },
    [pscustomobject]@{ Name='deletes staging'; Mutate={ param($p) $p.steps[4].operation='DELETE'; $p.steps[4].target=$promoteStaging } },
    [pscustomobject]@{ Name='wrong final path'; Mutate={ param($p) $p.steps[1].arguments[-1]='C:\automaton\.venv.other' } },
    [pscustomobject]@{ Name='user-profile Python'; Mutate={ param($p) $p.base_python='C:\Users\Admin\python.exe'; $p.steps[1].executable=$p.base_python } },
    [pscustomobject]@{ Name='PyPI URL'; Mutate={ param($p) $p.steps[2].arguments += 'https://pypi.invalid/package.whl' } },
    [pscustomobject]@{ Name='Set-Acl'; Mutate={ param($p) $p.steps[5].operation='Set-Acl' } },
    [pscustomobject]@{ Name='MetaTrader5 import'; Mutate={ param($p) $p.steps[3].operation='import MetaTrader5' } },
    [pscustomobject]@{ Name='service startup'; Mutate={ param($p) $p.steps[5].operation='Start-Service' } }
)) {
    $bad = Copy-TestFixture $validPromotePlan; & $planCase.Mutate $bad
    Assert-True (-not (Resolve-TradingLabPromoteVenvPlanState $bad $promoteBasePython $promoteActive $promoteStaging $promoteBackup $promoteFailed $promoteLock $promoteWheelhouse $promoteTemp).valid) "Promote plan that $($planCase.Name) must fail closed."
}
foreach ($missingArgument in @('--no-index','--require-hashes','--only-binary=:all:')) {
    $bad = Copy-TestFixture $validPromotePlan
    $bad.steps[2].arguments = @($bad.steps[2].arguments | Where-Object { $_ -ne $missingArgument })
    Assert-True (-not (Resolve-TradingLabPromoteVenvPlanState $bad $promoteBasePython $promoteActive $promoteStaging $promoteBackup $promoteFailed $promoteLock $promoteWheelhouse $promoteTemp).valid) "Promote pip without $missingArgument must fail closed."
}

$beforeBackup = Resolve-TradingLabRollbackExpectation $false $false $false $false
Assert-True ($beforeBackup.action -eq 'ACTIVE_UNTOUCHED' -and $beforeBackup.active_restored) 'Failure before backup must leave active untouched.'
$afterBackup = Resolve-TradingLabRollbackExpectation $true $false $false $true
Assert-True ($afterBackup.action -eq 'PROMOTION_FAILED_ROLLED_BACK' -and $afterBackup.active_restored) 'Failure after backup must restore backup.'
$partialFinal = Resolve-TradingLabRollbackExpectation $true $true $true $true
Assert-True ($partialFinal.move_partial_to_failed -and $partialFinal.active_restored -and -not $partialFinal.delete_failed) 'Partial final must move to failed and restore backup without deletion.'
$rollbackFailure = Resolve-TradingLabRollbackExpectation $true $true $false $false
Assert-True ($rollbackFailure.critical -and $rollbackFailure.action -eq 'FAIL_CLOSED_CRITICAL_RECOVERY_REQUIRED') 'Rollback failure must require critical recovery.'
foreach ($rollback in @($beforeBackup,$afterBackup,$partialFinal,$rollbackFailure)) {
    Assert-True (-not $rollback.delete_failed -and -not $rollback.delete_staging) 'Rollback must never delete failed artifacts or staging.'
}

Assert-True ((Resolve-TradingLabInstallerExit 0) -eq 'SUCCESS') 'Installer exit 0 classification regressed.'
Assert-True ((Resolve-TradingLabInstallerExit 1603) -eq 'INSTALLER_MAINTENANCE_COLLISION') 'Bootstrapper 1603 must be classified as a maintenance collision.'
Assert-True ((Resolve-TradingLabInstallerExit 5) -eq 'INSTALLER_EXIT_NONZERO') 'Unexpected installer exits must fail closed.'

$safeRights = @(
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
    ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize),
    [System.Security.AccessControl.FileSystemRights]::Read,
    [System.Security.AccessControl.FileSystemRights]::ReadData,
    [System.Security.AccessControl.FileSystemRights]::ExecuteFile,
    [System.Security.AccessControl.FileSystemRights]::ReadAttributes,
    [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes,
    [System.Security.AccessControl.FileSystemRights]::ReadPermissions,
    [System.Security.AccessControl.FileSystemRights]::Synchronize
)
foreach ($rights in $safeRights) {
    $classification = Get-TradingLabFileSystemRightsClassification ([int64]$rights)
    Assert-True (-not $classification.modify_equivalent -and -not $classification.write_capable) "Safe rights misclassified: $rights"
    Assert-True ($classification.mutation_intersection -eq 0) "Safe rights intersect prohibited mask: $rights"
}
$unsafeRights = @(
    [System.Security.AccessControl.FileSystemRights]::WriteData,
    [System.Security.AccessControl.FileSystemRights]::AppendData,
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes,
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
    [System.Security.AccessControl.FileSystemRights]::Delete,
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership,
    [System.Security.AccessControl.FileSystemRights]::Write,
    [System.Security.AccessControl.FileSystemRights]::Modify,
    [System.Security.AccessControl.FileSystemRights]::FullControl
)
foreach ($rights in $unsafeRights) {
    $classification = Get-TradingLabFileSystemRightsClassification ([int64]$rights)
    Assert-True ($classification.modify_equivalent -and $classification.write_capable) "Unsafe rights misclassified: $rights"
    Assert-True ($classification.mutation_intersection -ne 0) "Unsafe rights do not intersect prohibited mask: $rights"
}
$rightsMask = Get-TradingLabProhibitedMutationRightsMask
$gatewayRightsFixture = [int64](
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize
)
Assert-True ($rightsMask -eq 852310L -and ('0x' + $rightsMask.ToString('X')) -eq '0xD0156') 'Atomic prohibited mutation mask changed unexpectedly.'
Assert-True ($gatewayRightsFixture -eq 1179817L -and ('0x' + $gatewayRightsFixture.ToString('X')) -eq '0x1200A9') 'Gateway rights mask changed unexpectedly.'
Assert-True (($gatewayRightsFixture -band $rightsMask) -eq 0) 'Gateway RX plus Synchronize must have zero mutation intersection.'
foreach ($rights in @(
    [System.Security.AccessControl.FileSystemRights]::Write,
    [System.Security.AccessControl.FileSystemRights]::Modify,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.FileSystemRights]::Delete,
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
)) {
    Assert-True (([int64]$rights -band $rightsMask) -ne 0) "Required unsafe mask intersection is zero: $rights"
}

$aclSystemSid = 'S-1-5-18'
$aclAdministratorsSid = 'S-1-5-32-544'
$aclGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$aclAgentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$aclAuthenticatedUsersSid = 'S-1-5-11'
$aclUsersSid = 'S-1-5-32-545'
$aclFullControl = [int64][System.Security.AccessControl.FileSystemRights]::FullControl
$aclGatewayRx = [int64](
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize
)
function New-ValidAclPlanFixture {
    [pscustomobject]@{
        target = 'C:\Program Files\AutomatonPython\3.14.5'
        owner = 'BUILTIN\Administrators'
        owner_sid = $aclAdministratorsSid
        protect_inheritance = $true
        remove_inherited_aces = $true
        target_tree_reparse_points = 0
        validated_tree_item_count = 100
        entries = @(
            [pscustomobject]@{ identity = 'NT AUTHORITY\SYSTEM'; sid = $aclSystemSid; rights = 'FullControl'; rights_value = $aclFullControl; type = 'Allow' },
            [pscustomobject]@{ identity = 'BUILTIN\Administrators'; sid = $aclAdministratorsSid; rights = 'FullControl'; rights_value = $aclFullControl; type = 'Allow' },
            [pscustomobject]@{ identity = 'LAB\AutomatonGateway'; sid = $aclGatewaySid; rights = 'ReadAndExecute,Synchronize'; rights_value = $aclGatewayRx; type = 'Allow' }
        )
        automaton_agent_effective_access = 'NONE'
        authenticated_users_modify = $false
        users_modify = $false
        deny_aces_planned = 0
        other_domains_modified = $false
    }
}
function Test-AclPlanFixture([object] $Plan) {
    Test-TradingLabRuntimeAclPlan $Plan 'C:\Program Files\AutomatonPython\3.14.5' `
        $aclSystemSid $aclAdministratorsSid $aclGatewaySid $aclAgentSid `
        $aclAuthenticatedUsersSid $aclUsersSid $aclFullControl $aclGatewayRx
}
function Copy-AclPlanFixture([object] $Plan) {
    return ($Plan | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
}

$validAclPlan = New-ValidAclPlanFixture
Assert-True (Test-AclPlanFixture $validAclPlan).valid 'The exact three-Allow-ACE runtime ACL plan must pass.'
$directoryDescriptor = New-TradingLabRuntimeSecurityDescriptor $true $validAclPlan
$descriptorRules = @($directoryDescriptor.GetAccessRules(
    $true, $false, [System.Security.Principal.SecurityIdentifier]
))
Assert-True ($directoryDescriptor.AreAccessRulesProtected) 'In-memory descriptor inheritance must be protected.'
Assert-True ($directoryDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -eq $aclAdministratorsSid) 'In-memory descriptor owner must be Administrators.'
Assert-True ($descriptorRules.Count -eq 3) 'In-memory descriptor must contain exactly three ACEs.'
Assert-True (@($descriptorRules | Where-Object { $_.AccessControlType -ne 'Allow' }).Count -eq 0) 'In-memory descriptor must contain no Deny ACE.'
Assert-True ([int64](($descriptorRules | Where-Object { $_.IdentityReference.Value -eq $aclGatewaySid }).FileSystemRights) -eq $aclGatewayRx) 'In-memory Gateway descriptor rights must be exact RX plus Synchronize.'
foreach ($wrongTarget in @(
    'C:\Program Files\AutomatonPython\3.14.6', 'C:\automaton',
    'C:\ProgramData\AutomatonMT5Lab', 'C:\Users\AutomatonAgent',
    'C:\Users\AutomatonGateway'
)) {
    $case = Copy-AclPlanFixture $validAclPlan; $case.target = $wrongTarget
    Assert-True (-not (Test-AclPlanFixture $case).valid) "ACL target must fail closed: $wrongTarget"
}
$reparseCase = Copy-AclPlanFixture $validAclPlan; $reparseCase.target_tree_reparse_points = 1
Assert-True (-not (Test-AclPlanFixture $reparseCase).valid) 'A target reparse point must fail closed.'
$gatewayModifyCase = Copy-AclPlanFixture $validAclPlan
($gatewayModifyCase.entries | Where-Object { $_.sid -eq $aclGatewaySid }).rights_value = [int64][System.Security.AccessControl.FileSystemRights]::Modify
Assert-True (-not (Test-AclPlanFixture $gatewayModifyCase).valid) 'Gateway Modify in the plan must fail closed.'
$gatewayFullCase = Copy-AclPlanFixture $validAclPlan
($gatewayFullCase.entries | Where-Object { $_.sid -eq $aclGatewaySid }).rights_value = $aclFullControl
Assert-True (-not (Test-AclPlanFixture $gatewayFullCase).valid) 'Gateway FullControl in the plan must fail closed.'
$agentAllowCase = Copy-AclPlanFixture $validAclPlan
$agentAllowCase.entries = @($agentAllowCase.entries) + @([pscustomobject]@{
    identity = 'LAB\AutomatonAgent'; sid = $aclAgentSid; rights = 'ReadAndExecute'; rights_value = $aclGatewayRx; type = 'Allow'
})
Assert-True (-not (Test-AclPlanFixture $agentAllowCase).valid) 'Any Agent Allow ACE must fail closed.'
$denyCase = Copy-AclPlanFixture $validAclPlan; $denyCase.deny_aces_planned = 1
Assert-True (-not (Test-AclPlanFixture $denyCase).valid) 'Any planned Deny ACE must fail closed.'
$unresolvedIdentityCase = Copy-AclPlanFixture $validAclPlan
($unresolvedIdentityCase.entries | Where-Object { $_.sid -eq $aclGatewaySid }).identity = ''
Assert-True (-not (Test-AclPlanFixture $unresolvedIdentityCase).valid) 'An unresolved plan identity must fail closed.'
$systemWeakCase = Copy-AclPlanFixture $validAclPlan
($systemWeakCase.entries | Where-Object { $_.sid -eq $aclSystemSid }).rights_value = $aclGatewayRx
Assert-True (-not (Test-AclPlanFixture $systemWeakCase).valid) 'SYSTEM without exact FullControl must fail closed.'
$administratorsWeakCase = Copy-AclPlanFixture $validAclPlan
($administratorsWeakCase.entries | Where-Object { $_.sid -eq $aclAdministratorsSid }).rights_value = $aclGatewayRx
Assert-True (-not (Test-AclPlanFixture $administratorsWeakCase).valid) 'Administrators without exact FullControl must fail closed.'
$inheritanceCase = Copy-AclPlanFixture $validAclPlan; $inheritanceCase.protect_inheritance = $false
Assert-True (-not (Test-AclPlanFixture $inheritanceCase).valid) 'Unprotected inheritance must fail closed.'
$authenticatedUsersCase = Copy-AclPlanFixture $validAclPlan
$authenticatedUsersCase.authenticated_users_modify = $true
$authenticatedUsersCase.entries = @($authenticatedUsersCase.entries) + @([pscustomobject]@{
    identity = 'NT AUTHORITY\Authenticated Users'; sid = $aclAuthenticatedUsersSid; rights = 'Modify'; rights_value = [int64][System.Security.AccessControl.FileSystemRights]::Modify; type = 'Allow'
})
Assert-True (-not (Test-AclPlanFixture $authenticatedUsersCase).valid) 'Authenticated Users Modify must fail closed.'
$usersCase = Copy-AclPlanFixture $validAclPlan
$usersCase.users_modify = $true
$usersCase.entries = @($usersCase.entries) + @([pscustomobject]@{
    identity = 'BUILTIN\Users'; sid = $aclUsersSid; rights = 'Modify'; rights_value = [int64][System.Security.AccessControl.FileSystemRights]::Modify; type = 'Allow'
})
Assert-True (-not (Test-AclPlanFixture $usersCase).valid) 'BUILTIN Users Modify must fail closed.'

function New-ValidAclAuditItem(
    [string] $Path,
    [bool] $Protected = $true,
    [bool] $Inherited = $false,
    [bool] $Directory = $true
) {
    [pscustomobject]@{
        path = $Path
        is_directory = $Directory
        is_reparse_point = $false
        owner_sid = $aclAdministratorsSid
        inheritance_protected = $Protected
        rules = @(
            [pscustomobject]@{ sid = $aclSystemSid; rights = $aclFullControl; type = 'Allow'; inherited = $Inherited },
            [pscustomobject]@{ sid = $aclAdministratorsSid; rights = $aclFullControl; type = 'Allow'; inherited = $Inherited },
            [pscustomobject]@{ sid = $aclGatewaySid; rights = $aclGatewayRx; type = 'Allow'; inherited = $Inherited }
        )
    }
}
function Test-AclAuditFixture([object[]] $Items) {
    Test-TradingLabRuntimeAclAudit $Items 'C:\Program Files\AutomatonPython\3.14.5' `
        $aclSystemSid $aclAdministratorsSid $aclGatewaySid $aclAgentSid `
        $aclFullControl $aclGatewayRx
}
function Copy-AclAuditFixture([object] $Value) {
    return ($Value | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
}

$cleanAuditItems = @(
    (New-ValidAclAuditItem 'C:\Program Files\AutomatonPython\3.14.5'),
    (New-ValidAclAuditItem 'C:\Program Files\AutomatonPython\3.14.5\Lib')
)
$cleanAudit = Test-AclAuditFixture $cleanAuditItems
Assert-True ($cleanAudit.valid -and $cleanAudit.recursive_findings -eq 0 -and $cleanAudit.reparse_points -eq 0) 'Exact recursive ACL audit must pass with zero findings.'
Assert-True ($cleanAudit.unexpected_principals -eq 0 -and $cleanAudit.gateway_mutation_intersection -eq 0) 'Exact recursive ACL audit masks/principals regressed.'
Assert-True ($cleanAudit.owner_administrators -and $cleanAudit.root_inheritance_protected) 'Exact audit must expose owner/root-inheritance evidence.'
Assert-True ($cleanAudit.descendant_policy_safe -and $cleanAudit.unsafe_descendants -eq 0) 'Protected descendants must satisfy the effective policy.'
Assert-True ($cleanAudit.system_full_control -and $cleanAudit.administrators_full_control) 'Exact audit must expose administrative FullControl evidence.'
Assert-True ($cleanAudit.gateway_read_execute -and $cleanAudit.agent_allow_aces -eq 0 -and $cleanAudit.deny_aces -eq 0) 'Exact audit must expose Gateway/Agent/Deny evidence.'

$safeInheritedItems = @(
    (New-ValidAclAuditItem 'C:\Program Files\AutomatonPython\3.14.5'),
    (New-ValidAclAuditItem 'C:\Program Files\AutomatonPython\3.14.5\safe.pyc' $false $true $false)
)
$safeInheritedAudit = Test-AclAuditFixture $safeInheritedItems
Assert-True ($safeInheritedAudit.valid -and $safeInheritedAudit.recursive_findings -eq 0) 'A safe inherited descendant must not generate a recursive finding.'
Assert-True ($safeInheritedAudit.safe_inherited_descendants -eq 1 -and $safeInheritedAudit.unsafe_descendants -eq 0) 'Safe inherited descendant classification/count regressed.'
Assert-True ($safeInheritedAudit.descendant_classification_counts.DESCENDANT_ACL_SAFE_INHERITED -eq 1) 'Safe inherited descendant must expose its explicit classification.'
Assert-True ((Resolve-TradingLabRuntimeAclDisposition $safeInheritedAudit) -eq 'SAFE_NO_REPAIR_REQUIRED') 'Safe inherited ACL state must be a no-repair disposition.'

$sixtySafePycItems = [System.Collections.Generic.List[object]]::new()
$sixtySafePycItems.Add((New-ValidAclAuditItem 'C:\Program Files\AutomatonPython\3.14.5'))
foreach ($index in 1..60) {
    $sixtySafePycItems.Add((New-ValidAclAuditItem `
        ("C:\Program Files\AutomatonPython\3.14.5\safe-{0:D2}.pyc" -f $index) `
        $false $true $false))
}
$sixtySafePycAudit = Test-AclAuditFixture @($sixtySafePycItems)
Assert-True ($sixtySafePycAudit.valid -and $sixtySafePycAudit.recursive_findings -eq 0) 'Sixty safe inherited pyc descendants must pass without a repair finding.'
Assert-True ($sixtySafePycAudit.safe_inherited_descendants -eq 60) 'Safe inherited count must be dynamic and preserve all sixty fixture items.'
Assert-True ((Resolve-TradingLabRuntimeAclDisposition $sixtySafePycAudit) -eq 'SAFE_NO_REPAIR_REQUIRED') 'Sixty safe inherited descendants must remain a no-op ACL state.'

$missingParentItems = @(
    (New-ValidAclAuditItem 'C:\Program Files\AutomatonPython\3.14.5'),
    (New-ValidAclAuditItem 'C:\Program Files\AutomatonPython\3.14.5\missing\unsafe.pyc' $false $true $false)
)
$missingParentAudit = Test-AclAuditFixture $missingParentItems
Assert-True (-not $missingParentAudit.valid -and $missingParentAudit.unsafe_descendants -eq 1) 'An inherited child with an unaudited parent chain must fail closed.'
foreach ($unsafeGatewayRight in @(
    [System.Security.AccessControl.FileSystemRights]::Modify,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.FileSystemRights]::Delete,
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
)) {
    $case = Copy-AclAuditFixture $cleanAuditItems
    ($case[0].rules | Where-Object { $_.sid -eq $aclGatewaySid }).rights = [int64]$unsafeGatewayRight
    $unsafeAudit = Test-AclAuditFixture $case
    Assert-True (-not $unsafeAudit.valid -and -not $unsafeAudit.gateway_read_execute -and $unsafeAudit.gateway_mutation_intersection -ne 0) "Unsafe Gateway audit rights must fail closed: $unsafeGatewayRight"
}
$agentAuditCase = Copy-AclAuditFixture $cleanAuditItems
$agentAuditCase[0].rules = @($agentAuditCase[0].rules) + @([pscustomobject]@{ sid = $aclAgentSid; rights = 1L; type = 'Allow'; inherited = $false })
$agentAudit = Test-AclAuditFixture $agentAuditCase
Assert-True (-not $agentAudit.valid -and $agentAudit.agent_allow_aces -eq 1) 'Agent Allow in recursive audit must fail closed.'
$denyAuditCase = Copy-AclAuditFixture $cleanAuditItems
$denyAuditCase[0].rules = @($denyAuditCase[0].rules) + @([pscustomobject]@{ sid = $aclAgentSid; rights = 1L; type = 'Deny'; inherited = $false })
$denyAudit = Test-AclAuditFixture $denyAuditCase
Assert-True (-not $denyAudit.valid -and $denyAudit.deny_aces -eq 1) 'Deny ACE in recursive audit must fail closed.'
$unexpectedAuditCase = Copy-AclAuditFixture $cleanAuditItems
$unexpectedAuditCase[0].rules = @($unexpectedAuditCase[0].rules) + @([pscustomobject]@{ sid = 'S-1-5-11'; rights = 2L; type = 'Allow'; inherited = $false })
$unexpectedAudit = Test-AclAuditFixture $unexpectedAuditCase
Assert-True (-not $unexpectedAudit.valid -and $unexpectedAudit.unexpected_principals -eq 1) 'Additional write-capable principal must fail closed.'
$inheritanceAuditCase = Copy-AclAuditFixture $cleanAuditItems; $inheritanceAuditCase[0].inheritance_protected = $false
Assert-True (-not (Test-AclAuditFixture $inheritanceAuditCase).valid) 'Unprotected runtime inheritance must fail closed.'
$ownerAuditCase = Copy-AclAuditFixture $cleanAuditItems; $ownerAuditCase[0].owner_sid = $aclSystemSid
Assert-True (-not (Test-AclAuditFixture $ownerAuditCase).valid) 'Incorrect runtime owner must fail closed.'
$reparseAuditCase = Copy-AclAuditFixture $cleanAuditItems; $reparseAuditCase[0].is_reparse_point = $true
$reparseAudit = Test-AclAuditFixture $reparseAuditCase
Assert-True (-not $reparseAudit.valid -and $reparseAudit.reparse_points -eq 1) 'Runtime reparse point must fail closed.'

foreach ($unsafeInheritedGatewayRight in @(
    [System.Security.AccessControl.FileSystemRights]::Write,
    [System.Security.AccessControl.FileSystemRights]::Modify,
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership,
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions
)) {
    $case = Copy-AclAuditFixture $safeInheritedItems
    ($case[1].rules | Where-Object { $_.sid -eq $aclGatewaySid }).rights = [int64]$unsafeInheritedGatewayRight
    $audit = Test-AclAuditFixture $case
    Assert-True (-not $audit.valid -and $audit.unsafe_descendants -eq 1 -and $audit.gateway_mutation_intersection -ne 0) "Inherited Gateway mutation must fail closed: $unsafeInheritedGatewayRight"
}
$inheritedAgentCase = Copy-AclAuditFixture $safeInheritedItems
$inheritedAgentCase[1].rules = @($inheritedAgentCase[1].rules) + @([pscustomobject]@{
    sid = $aclAgentSid; rights = 1L; type = 'Allow'; inherited = $true
})
$inheritedAgentAudit = Test-AclAuditFixture $inheritedAgentCase
Assert-True (-not $inheritedAgentAudit.valid -and $inheritedAgentAudit.agent_allow_aces -eq 1 -and $inheritedAgentAudit.unsafe_descendants -eq 1) 'Inherited Agent Read must fail closed.'
$explicitUnsafeChildCase = Copy-AclAuditFixture $safeInheritedItems
($explicitUnsafeChildCase[1].rules | Where-Object { $_.sid -eq $aclGatewaySid }).inherited = $false
($explicitUnsafeChildCase[1].rules | Where-Object { $_.sid -eq $aclGatewaySid }).rights = [int64][System.Security.AccessControl.FileSystemRights]::Write
$explicitUnsafeChildAudit = Test-AclAuditFixture $explicitUnsafeChildCase
Assert-True (-not $explicitUnsafeChildAudit.valid -and $explicitUnsafeChildAudit.unsafe_descendants -eq 1) 'An unprotected child with an explicit unsafe ACE must fail closed.'
$unexpectedInheritedCase = Copy-AclAuditFixture $safeInheritedItems
$unexpectedInheritedCase[1].rules = @($unexpectedInheritedCase[1].rules) + @([pscustomobject]@{
    sid = 'S-1-5-11'; rights = 1L; type = 'Allow'; inherited = $true
})
$unexpectedInheritedAudit = Test-AclAuditFixture $unexpectedInheritedCase
Assert-True (-not $unexpectedInheritedAudit.valid -and $unexpectedInheritedAudit.unexpected_principals -eq 1) 'An inherited unexpected principal must fail closed.'
$inheritedReparseCase = Copy-AclAuditFixture $safeInheritedItems
$inheritedReparseCase[1].is_reparse_point = $true
$inheritedReparseAudit = Test-AclAuditFixture $inheritedReparseCase
Assert-True (-not $inheritedReparseAudit.valid -and $inheritedReparseAudit.reparse_points -eq 1) 'An inherited reparse-point child must fail closed.'

$lockedWheelFixture = @(
    [pscustomobject]@{ name = 'MetaTrader5'; version = '5.0.6090'; sha256 = ('a' * 64) },
    [pscustomobject]@{ name = 'numpy'; version = '2.5.2'; sha256 = ('b' * 64) }
)
$validWheelFixture = @(
    [pscustomobject]@{ name = 'metatrader5-5.0.6090-cp314-cp314-win_amd64.whl'; sha256 = ('a' * 64); is_directory = $false },
    [pscustomobject]@{ name = 'numpy-2.5.2-cp314-cp314-win_amd64.whl'; sha256 = ('b' * 64); is_directory = $false }
)
$wheelState = Resolve-TradingLabWheelhouseManifestState $lockedWheelFixture $validWheelFixture
Assert-True $wheelState.complete 'Exact wheelhouse fixture must be complete.'
Assert-True ($wheelState.expected_requirements -eq 2 -and $wheelState.artifact_count -eq 2) 'Wheelhouse exact cardinality regressed.'
Assert-True ($wheelState.metatrader5_present -and $wheelState.numpy_present) 'MT5/numpy wheel evidence regressed.'
$missingWheelState = Resolve-TradingLabWheelhouseManifestState $lockedWheelFixture @($validWheelFixture[0])
Assert-True (-not $missingWheelState.complete -and $missingWheelState.missing_requirements.Count -eq 1) 'Missing wheelhouse requirement must fail closed.'
$corruptWheelFixture = @($validWheelFixture[0], [pscustomobject]@{
    name = $validWheelFixture[1].name; sha256 = ('c' * 64); is_directory = $false
})
$corruptWheelState = Resolve-TradingLabWheelhouseManifestState $lockedWheelFixture $corruptWheelFixture
Assert-True (-not $corruptWheelState.complete -and $corruptWheelState.corrupt_artifacts.Count -eq 1) 'Corrupt wheel must fail closed.'
$sourceWheelState = Resolve-TradingLabWheelhouseManifestState $lockedWheelFixture @(
    $validWheelFixture + [pscustomobject]@{ name = 'numpy-2.5.2.tar.gz'; sha256 = ('b' * 64); is_directory = $false }
)
Assert-True (-not $sourceWheelState.complete -and $sourceWheelState.source_distributions.Count -eq 1) 'Source distributions must fail closed.'
$unexpectedWheelState = Resolve-TradingLabWheelhouseManifestState $lockedWheelFixture @(
    $validWheelFixture + [pscustomobject]@{ name = 'unexpected-1.0-py3-none-any.whl'; sha256 = ('d' * 64); is_directory = $false }
)
Assert-True (-not $unexpectedWheelState.complete -and $unexpectedWheelState.unexpected_artifacts.Count -eq 1) 'Unexpected wheel must fail closed.'

$validReport = [pscustomobject]@{
    schema_version = 2
    run_id = '00000000-0000-0000-0000-000000000001'
    phase = 'PrepareWheelhouse'
    apply_requested = $true
    status = 'PASS'
    trading_mode = 'OBSERVE_ONLY'
    python_version = '3.14.5'
    wheelhouse = 'C:\ProgramData\AutomatonMT5Lab\maintenance\wheelhouse\cp314-win_amd64'
    lock_file = 'C:\automaton\requirements-gateway-win-py314.lock'
    last_applied_phase = 'PrepareWheelhouse'
    installer_executed = $false
    uninstaller_executed = $false
    mt5_accessed = $false
    automaton_started = $false
    gateway_started = $false
    error = $null
    gates = [pscustomobject]@{
        DECLARATIVE_HASH_LOCK = 'PASS'
        WHEELHOUSE_HASH_LOCKED = 'PASS'
        META_TRADER5_WHEEL_PRESENT = 'PASS'
        NUMPY_WHEEL_PRESENT = 'PASS'
    }
}
Assert-True (Test-TradingLabPrepareWheelhouseReportRecord $validReport $validReport.wheelhouse $validReport.lock_file '3.14.5') 'Valid legacy PrepareWheelhouse evidence must remain readable.'
$staleReport = $validReport.PSObject.Copy()
$staleReport.status = 'FAIL'
Assert-True (-not (Test-TradingLabPrepareWheelhouseReportRecord $staleReport $validReport.wheelhouse $validReport.lock_file '3.14.5')) 'Stale last_applied_phase must not authorize anything.'
$missingReportRoot = Join-Path $env:TEMP ("automaton-missing-report-" + [guid]::NewGuid().ToString('D'))
[void][System.IO.Directory]::CreateDirectory($missingReportRoot)
try {
    $missingReportFailed = $false
    try {
        [void](Find-TradingLabPrepareWheelhouseReport $missingReportRoot $validReport.wheelhouse $validReport.lock_file '3.14.5')
    } catch { $missingReportFailed = $_.Exception.Message -like 'PREVIOUS_PHASE_PREPARE_WHEELHOUSE=FAIL*' }
    Assert-True $missingReportFailed 'Missing PrepareWheelhouse report must fail closed.'
} finally {
    [System.IO.Directory]::Delete($missingReportRoot, $false)
}

$validUninstallReport = [pscustomobject]@{
    schema_version = 3
    run_id = '00000000-0000-0000-0000-000000000002'
    phase = 'UninstallTraditional'
    apply_requested = $true
    status = 'PASS'
    trading_mode = 'OBSERVE_ONLY'
    python_version = '3.14.5'
    python_base = 'C:\Program Files\AutomatonPython\3.14.5'
    active_venv = 'C:\automaton\.venv'
    wheelhouse = $validReport.wheelhouse
    lock_file = $validReport.lock_file
    current_run_applied_phase = 'UninstallTraditional'
    required_previous_phase = 'PrepareWheelhouse'
    previous_phase_verified = $true
    previous_phase_report = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-runtime-results\python-runtime-00000000-0000-0000-0000-000000000001.json'
    previous_phase_report_sha256 = ('a' * 64)
    installer_executed = $false
    uninstaller_executed = $true
    venv_rebuilt = $false
    venv_promoted = $false
    mt5_accessed = $false
    automaton_started = $false
    gateway_started = $false
    acl_existing_domains_modified = $false
    error = $null
    gates = [pscustomobject]@{
        DECLARATIVE_HASH_LOCK = 'PASS'; PYTHON_MANAGER_RUNTIME = 'PASS'
        PREVIOUS_PHASE_PREPARE_WHEELHOUSE = 'PASS'; WHEELHOUSE_PRESENT = 'PASS'
        WHEELHOUSE_HASH_LOCKED = 'PASS'; WHEELHOUSE_COMPLETE = 'PASS'
        META_TRADER5_WHEEL_PRESENT = 'PASS'; NUMPY_WHEEL_PRESENT = 'PASS'
        PYTHON_MANAGER_PRESERVE = 'PASS'; SAME_VERSION_TRADITIONAL_INSTALL_PRESENT = 'PASS'
        PARTIAL_TARGET_POST_STATE = 'ABSENT'; MIXED_PYTHONCORE_POST_STATE = 'ABSENT'
    }
    inventory_after = [pscustomobject]@{
        python_manager_runtime = 'FUNCTIONAL'; traditional_user_runtime = 'ABSENT'
        traditional_machine_runtime = 'ABSENT'; traditional_msi_components = 0
        partial_target_runtime = 'ABSENT'; mixed_pythoncore_registration = 'ABSENT'
        same_version_traditional_install_present = 'PASS'
    }
    wheelhouse_validation = [pscustomobject]@{
        expected_requirements = 27; artifact_count = 27
        missing_requirements = @(); source_distributions = @(); unexpected_artifacts = @()
        corrupt_artifacts = @(); duplicate_requirements = @()
        matched_artifacts = @(1..27); hash_locked = $true; complete = $true
        metatrader5_present = $true; numpy_present = $true
    }
}
$uninstallArgs = @(
    $validUninstallReport, $validUninstallReport.wheelhouse, $validUninstallReport.lock_file,
    '3.14.5', $validUninstallReport.python_base, $validUninstallReport.active_venv
)
$uninstallRecordArgs = @(
    $validUninstallReport.wheelhouse, $validUninstallReport.lock_file,
    '3.14.5', $validUninstallReport.python_base, $validUninstallReport.active_venv
)
Assert-True (Test-TradingLabUninstallTraditionalReportRecord @uninstallArgs) 'Valid applied UninstallTraditional report must pass.'
$wrongPhaseReport = $validUninstallReport.PSObject.Copy()
$wrongPhaseReport.phase = 'PrepareWheelhouse'
Assert-True (-not (Test-TradingLabUninstallTraditionalReportRecord $wrongPhaseReport @uninstallRecordArgs)) 'Previous phase other than UninstallTraditional must fail closed.'
$failedUninstallReport = $validUninstallReport.PSObject.Copy()
$failedUninstallReport.status = 'FAIL'
Assert-True (-not (Test-TradingLabUninstallTraditionalReportRecord $failedUninstallReport @uninstallRecordArgs)) 'Non-PASS UninstallTraditional report must fail closed.'
$legacyUninstallReport = $validUninstallReport.PSObject.Copy()
$legacyUninstallReport.schema_version = 2
Assert-True (-not (Test-TradingLabUninstallTraditionalReportRecord $legacyUninstallReport @uninstallRecordArgs)) 'Incompatible UninstallTraditional schema must fail closed.'
$corruptUninstallRoot = Join-Path $env:TEMP ("automaton-corrupt-uninstall-report-" + [guid]::NewGuid().ToString('D'))
[void][System.IO.Directory]::CreateDirectory($corruptUninstallRoot)
try {
    $missingUninstallFailed = $false
    try {
        [void](Find-TradingLabUninstallTraditionalReport $corruptUninstallRoot @uninstallRecordArgs)
    } catch { $missingUninstallFailed = $_.Exception.Message -like 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL*' }
    Assert-True $missingUninstallFailed 'Missing UninstallTraditional evidence must fail closed.'
    Set-Content -LiteralPath (Join-Path $corruptUninstallRoot 'python-runtime-corrupt.json') -Value '{not-json' -Encoding UTF8
    $corruptReportFailed = $false
    try {
        [void](Find-TradingLabUninstallTraditionalReport $corruptUninstallRoot @uninstallRecordArgs)
    } catch { $corruptReportFailed = $_.Exception.Message -like 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL*' }
    Assert-True $corruptReportFailed 'Corrupt UninstallTraditional evidence must fail closed.'
} finally {
    [System.IO.Directory]::Delete($corruptUninstallRoot, $true)
}

$pendingInstallReport = [pscustomobject]@{
    schema_version = 3; phase = 'InstallMachineRuntime'; apply_requested = $true
    status = 'FAIL'; trading_mode = 'OBSERVE_ONLY'; python_version = '3.14.5'
    python_base = 'C:\Program Files\AutomatonPython\3.14.5'
    installer = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-3.14.5-amd64.exe'
    current_run_applied_phase = 'InstallMachineRuntime'
    required_previous_phase = 'UninstallTraditional'; previous_phase_verified = $true
    previous_phase_report = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-runtime-results\python-runtime-prior.json'
    previous_phase_report_sha256 = ('a' * 64)
    installer_executed = $true; uninstaller_executed = $false
    venv_rebuilt = $false; venv_promoted = $false
    mt5_accessed = $false; automaton_started = $false; gateway_started = $false
    acl_existing_domains_modified = $false
    error = 'Python metadata command failed after successful installation.'
    gates = [pscustomobject]@{
        TRADING_MODE_OBSERVE_ONLY = 'PASS'; PREVIOUS_PHASE_UNINSTALL_TRADITIONAL = 'PASS'
        PYTHON_INSTALLER_VERIFIED = 'PASS'; INSTALL_ALL_USERS = 'PASS'; TARGET_MACHINE_WIDE = 'PASS'
    }
    installer_plan = [pscustomobject]@{
        operation = 'INSTALL_CPYTHON_MACHINE_WIDE_MINIMAL'
        executable = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-3.14.5-amd64.exe'
        target_dir = 'C:\Program Files\AutomatonPython\3.14.5'
    }
}
$pendingArgs = @(
    '3.14.5', 'C:\Program Files\AutomatonPython\3.14.5',
    'C:\ProgramData\AutomatonMT5Lab\maintenance\python-3.14.5-amd64.exe'
)
Assert-True (Test-TradingLabInstalledRuntimePendingReportRecord $pendingInstallReport @pendingArgs) 'Installed-but-validation-pending evidence must pass exact validation.'
$pendingWithoutInstaller = $pendingInstallReport.PSObject.Copy(); $pendingWithoutInstaller.installer_executed = $false
Assert-True (-not (Test-TradingLabInstalledRuntimePendingReportRecord $pendingWithoutInstaller @pendingArgs)) 'Recovery evidence must prove the installer completed before validation failed.'
$pendingWrongPhase = $pendingInstallReport.PSObject.Copy(); $pendingWrongPhase.current_run_applied_phase = 'InstallMachineRuntimeRequested'
Assert-True (-not (Test-TradingLabInstalledRuntimePendingReportRecord $pendingWrongPhase @pendingArgs)) 'A failure before installer completion must not authorize ACL recovery.'

$validInstallState = [pscustomobject]@{
    python_manager_runtime = 'FUNCTIONAL'; traditional_user_runtime = 'ABSENT'
    traditional_machine_runtime = 'ABSENT'; traditional_msi_components = 0
    partial_target_runtime = 'ABSENT'; mixed_pythoncore_registration = 'ABSENT'
    same_version_traditional_install_present = 'ABSENT'
}
Assert-True (Resolve-TradingLabInstallPreconditionState $validInstallState).valid 'Clean post-uninstall state must authorize install prevalidation.'
$msiReappeared = $validInstallState.PSObject.Copy(); $msiReappeared.traditional_msi_components = 1
Assert-True (-not (Resolve-TradingLabInstallPreconditionState $msiReappeared).valid) 'A reappearing traditional MSI must fail closed.'
$partialReappeared = $validInstallState.PSObject.Copy(); $partialReappeared.partial_target_runtime = 'PRESENT'
Assert-True (-not (Resolve-TradingLabInstallPreconditionState $partialReappeared).valid) 'A reappearing partial target must fail closed.'
$mixedReappeared = $validInstallState.PSObject.Copy(); $mixedReappeared.mixed_pythoncore_registration = 'PRESENT'
Assert-True (-not (Resolve-TradingLabInstallPreconditionState $mixedReappeared).valid) 'A reappearing mixed PythonCore registration must fail closed.'

$validInstallerState = Resolve-TradingLabInstallerArtifactState `
    'python-3.14.5-amd64.exe' 30361968 ('a' * 64) 'Valid' `
    'CN=Python Software Foundation, O=Python Software Foundation, C=US' `
    'python-3.14.5-amd64.exe' 30361968 ('a' * 64)
Assert-True $validInstallerState.verified 'Exact installer evidence must pass.'
$badHashInstallerState = Resolve-TradingLabInstallerArtifactState `
    'python-3.14.5-amd64.exe' 30361968 ('b' * 64) 'Valid' `
    'CN=Python Software Foundation, O=Python Software Foundation, C=US' `
    'python-3.14.5-amd64.exe' 30361968 ('a' * 64)
Assert-True (-not $badHashInstallerState.verified -and -not $badHashInstallerState.hash_valid) 'Installer hash mismatch must fail closed.'
Assert-True (Test-TradingLabExactMachineTarget `
    'C:\Program Files\AutomatonPython\3.14.5' 'C:\Program Files\AutomatonPython\3.14.5' 'C:\Users') `
    'Exact machine-wide target must pass.'
Assert-True (-not (Test-TradingLabExactMachineTarget `
    'C:\Users\Admin\AutomatonPython' 'C:\Program Files\AutomatonPython\3.14.5' 'C:\Users')) `
    'A user-profile Python target must fail closed.'

$maliciousManagerPlan = [pscustomobject]@{
    executable = 'C:\Users\Admin\AppData\Local\Python\pythoncore-3.14-64\pymanager.exe'
    arguments = @('uninstall')
    destructive_registry_ids = @('pymanager-pythoncore-3.14-64')
    direct_filesystem_deletes = @('C:\Users\Admin\AppData\Local\Python\pythoncore-3.14-64')
}
Assert-True (-not (Test-TradingLabManagerExcludedFromUninstallPlan `
    $maliciousManagerPlan 'pymanager-pythoncore-3.14-64' 'C:\Users\Admin\AppData\Local\Python\pythoncore-3.14-64')) `
    'Python Manager in uninstall plan must be CRITICAL_FAIL.'

$expectedMsiFixture = @(1..9 | ForEach-Object {
    [pscustomobject]@{ product_code = ('{00000000-0000-0000-0000-' + $_.ToString('000000000000') + '}'); display_name = "Component $_" }
})
$validMsiState = Resolve-TradingLabMsiComponentSetState $expectedMsiFixture @($expectedMsiFixture)
Assert-True ($validMsiState.valid -and $validMsiState.expected_count -eq 9) 'Expected nine traditional MSI components must pass.'
$unexpectedMsiFixture = @($expectedMsiFixture[0..7]) + @(
    [pscustomobject]@{ product_code = '{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}'; display_name = 'Unexpected' }
)
$unexpectedMsiState = Resolve-TradingLabMsiComponentSetState $expectedMsiFixture $unexpectedMsiFixture
Assert-True (-not $unexpectedMsiState.valid -and $unexpectedMsiState.unexpected_product_codes.Count -eq 1) 'Unexpected MSI ProductCode must fail closed.'

function New-Probe([bool] $Functional) {
    [pscustomobject]@{
        functional = $Functional
        metadata = [pscustomobject]@{
            version = '3.14.5'; architecture = '64bit';
            base_prefix = 'C:\Users\Admin\AppData\Local\Python\pythoncore-3.14-64'
        }
    }
}
function New-Layout([bool] $Exists, [bool] $Complete) {
    [pscustomobject]@{ exists = $Exists; complete_layout = $Complete }
}
function New-VenvState([bool] $Broken) { [pscustomobject]@{ broken = $Broken } }
function Resolve-Synthetic(
    [object[]] $Entries, [object[]] $Msi, [object[]] $Core,
    [bool] $ManagerFunctional, [bool] $TargetExists, [bool] $TargetComplete, [bool] $VenvBroken
) {
    Resolve-TradingLabPythonInventoryState $Entries $Msi $Core (New-Probe $ManagerFunctional) `
        (New-Layout $TargetExists $TargetComplete) (New-VenvState $VenvBroken)
}

$manager = [pscustomobject]@{ kind = 'PYTHON_MANAGER_RUNTIME'; scope = 'HKCU' }
$traditionalUser = [pscustomobject]@{ kind = 'TRADITIONAL_BUNDLE'; scope = 'HKCU' }
$partial = Resolve-Synthetic @($manager, $traditionalUser) @([pscustomobject]@{}) @() $true $true $false $true
Assert-True ($partial.python_manager_runtime -eq 'FUNCTIONAL') 'Python Manager runtime must remain distinct and functional.'
Assert-True ($partial.traditional_user_runtime -eq 'PRESENT') 'Same-version traditional user runtime was not detected.'
Assert-True ($partial.same_version_traditional_install_present -eq 'CONFLICTING_PREEXISTING_RUNTIME') 'Conflicting traditional install must fail prevalidation.'
Assert-True ($partial.partial_target_runtime -eq 'PRESENT') 'Partial target was not classified.'
Assert-True ($partial.broken_active_venv -eq 'PRESENT') 'Broken redirector venv was not classified.'
Assert-True ($partial.prevalidation -eq 'FAIL') 'Mixed maintenance state must fail closed.'

$clean = Resolve-Synthetic @($manager) @() @() $true $false $false $true
Assert-True ($clean.same_version_traditional_install_present -eq 'ABSENT') 'Clean traditional registration state must be absent.'
Assert-True ($clean.python_manager_runtime -eq 'FUNCTIONAL') 'Manager must survive traditional cleanup.'

$mixedCore = [pscustomobject]@{
    managed_by_python_manager = $true
    executable_path = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'
}
$mixedOnly = Resolve-Synthetic @($manager) @() @($mixedCore) $true $false $false $true
Assert-True ($mixedOnly.mixed_pythoncore_registration -eq 'PRESENT') 'Mixed PythonCore registration was not detected.'
Assert-True ($mixedOnly.prevalidation -eq 'FAIL') 'Mixed PythonCore registration must fail prevalidation alone.'

$machineBundleHkcu = [pscustomobject]@{ kind = 'TRADITIONAL_BUNDLE'; scope = 'HKCU' }
$machineCoreExact = [pscustomobject]@{
    scope = 'HKLM'; managed_by_python_manager = $false
    executable_path = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'
}
$machineMsiExact = @($script:TradingLabExpectedMachineMsiComponents | ForEach-Object {
    [pscustomobject]@{
        product_code = $_.product_code; display_name = $_.display_name
        user_data_sid = 'S-1-5-18'
    }
})
$complete = Resolve-Synthetic @($manager, $machineBundleHkcu) $machineMsiExact @($machineCoreExact) $true $true $true $false
Assert-True ($complete.traditional_machine_runtime -eq 'PRESENT') 'Machine traditional runtime was not distinguished.'
Assert-True ($complete.traditional_user_runtime -eq 'ABSENT') 'HKCU bundle registration must not imply a second user payload.'
Assert-True ($complete.traditional_bundle_registration_scope -eq 'HKCU') 'Bundle registration scope must remain independently visible.'
Assert-True ($complete.traditional_runtime_payload_scope -eq 'MACHINE') 'Payload scope must follow PythonCore/MSI/target evidence.'
Assert-True ($complete.machine_runtime_msi_components -eq 4 -and $complete.unexpected_machine_msi_components -eq 0) 'Exact four-component minimal runtime was not recognized.'
Assert-True ($complete.same_version_traditional_install_present -eq 'EXPECTED_INSTALLED_TARGET_RUNTIME') 'Expected installed target must not be classified as a conflict.'
Assert-True ($complete.prevalidation -eq 'TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING') 'Installed runtime must enter validation-pending recovery.'
Assert-True ($complete.completed_target_runtime -eq 'PRESENT_UNVERIFIED') 'Complete layout must still require execution validation.'

function New-RuntimeVerificationInventory([object] $State) {
    [ordered]@{
        target_layout = [pscustomobject]@{
            root = 'C:\Program Files\AutomatonPython\3.14.5'
            complete_layout = $true
        }
        target_probe = [pscustomobject]@{
            functional = $true
            metadata = [pscustomobject]@{
                version = '3.14.5'; architecture = '64bit'
                executable = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'
                base_prefix = 'C:\Program Files\AutomatonPython\3.14.5'
                prefix = 'C:\Program Files\AutomatonPython\3.14.5'
                sys_import = $true; stdlib_import = $true
                stdlib_path = 'C:\Program Files\AutomatonPython\3.14.5\Lib\os.py'
                venv_import = $true; pip_import = $true
                pip_path = 'C:\Program Files\AutomatonPython\3.14.5\Lib\site-packages\pip\__init__.py'
                sys_path = @('C:\Program Files\AutomatonPython\3.14.5\Lib')
            }
        }
        state = $State
        runtime_verification = $null
    }
}

function New-ExactRuntimeAclAudit {
    [pscustomobject]@{
        valid = $true; scanned_items = 20; recursive_findings = 0
        unexpected_principals = 0; reparse_points = 0
        owner_administrators = $true; inheritance_protected = $true
        root_inheritance_protected = $true; descendant_policy_safe = $true
        protected_descendants = 19; safe_inherited_descendants = 0; unsafe_descendants = 0
        system_full_control = $true; administrators_full_control = $true
        gateway_read_execute = $true; gateway_mutation_intersection = 0
        agent_allow_aces = 0; deny_aces = 0
    }
}

$pendingInventory = New-RuntimeVerificationInventory $complete.PSObject.Copy()
$pendingVerification = Resolve-TradingLabRuntimeVerificationState `
    $pendingInventory $null 'C:\Program Files\AutomatonPython\3.14.5' '3.14.5' 'C:\Users'
Assert-True (-not $pendingVerification.verified) 'Installed runtime without ACL evidence must remain unverified.'
Assert-True ($pendingVerification.completed_target_runtime -eq 'PRESENT_UNVERIFIED') 'ACL-pending runtime must remain PRESENT_UNVERIFIED.'
Assert-True ($pendingVerification.prevalidation -eq 'TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING') 'ACL-pending runtime must remain validation-pending.'

$verifiedInventory = New-RuntimeVerificationInventory $complete.PSObject.Copy()
$verifiedInventory = ConvertTo-TradingLabVerifiedPythonInventory `
    $verifiedInventory (New-ExactRuntimeAclAudit) 'C:\Program Files\AutomatonPython\3.14.5' '3.14.5' 'C:\Users'
Assert-True $verifiedInventory.runtime_verification.verified 'Complete live runtime and exact ACL must verify.'
Assert-True ($verifiedInventory.state.completed_target_runtime -eq 'PRESENT_VERIFIED') 'Verified runtime must be PRESENT_VERIFIED.'
Assert-True ($verifiedInventory.state.prevalidation -eq 'PASS') 'Verified runtime prevalidation must be PASS.'

$safeInheritedVerificationAcl = New-ExactRuntimeAclAudit
$safeInheritedVerificationAcl.protected_descendants = 19
$safeInheritedVerificationAcl.safe_inherited_descendants = 60
$safeInheritedInventory = ConvertTo-TradingLabVerifiedPythonInventory `
    (New-RuntimeVerificationInventory $complete.PSObject.Copy()) $safeInheritedVerificationAcl `
    'C:\Program Files\AutomatonPython\3.14.5' '3.14.5' 'C:\Users'
Assert-True ($safeInheritedInventory.runtime_verification.verified -and
    $safeInheritedInventory.state.completed_target_runtime -eq 'PRESENT_VERIFIED' -and
    $safeInheritedInventory.state.prevalidation -eq 'PASS') 'Safe inherited descendants must permit read-only final runtime verification.'

$modifyAcl = New-ExactRuntimeAclAudit
$modifyAcl.valid = $false; $modifyAcl.gateway_read_execute = $false; $modifyAcl.gateway_mutation_intersection = 65814
$modifyResult = Resolve-TradingLabRuntimeVerificationState `
    (New-RuntimeVerificationInventory $complete.PSObject.Copy()) $modifyAcl `
    'C:\Program Files\AutomatonPython\3.14.5' '3.14.5' 'C:\Users'
Assert-True (-not $modifyResult.verified -and 'ACL_GATEWAY_MUTATION_RIGHTS_ZERO' -in $modifyResult.failures) 'Gateway Modify must never produce PRESENT_VERIFIED.'

$agentAcl = New-ExactRuntimeAclAudit
$agentAcl.valid = $false; $agentAcl.agent_allow_aces = 1
$agentResult = Resolve-TradingLabRuntimeVerificationState `
    (New-RuntimeVerificationInventory $complete.PSObject.Copy()) $agentAcl `
    'C:\Program Files\AutomatonPython\3.14.5' '3.14.5' 'C:\Users'
Assert-True (-not $agentResult.verified -and 'ACL_AGENT_ACCESS_ABSENT' -in $agentResult.failures) 'Agent Allow must never produce PRESENT_VERIFIED.'

$unexpectedMsiStateForVerification = $complete.PSObject.Copy()
$unexpectedMsiStateForVerification.unexpected_machine_msi_components = 1
$unexpectedMsiStateForVerification.machine_runtime_msi_valid = $false
$unexpectedMsiStateForVerification.prevalidation = 'FAIL'
$unexpectedMsiResult = Resolve-TradingLabRuntimeVerificationState `
    (New-RuntimeVerificationInventory $unexpectedMsiStateForVerification) (New-ExactRuntimeAclAudit) `
    'C:\Program Files\AutomatonPython\3.14.5' '3.14.5' 'C:\Users'
Assert-True (-not $unexpectedMsiResult.verified -and $unexpectedMsiResult.prevalidation -eq 'FAIL') 'Unexpected MSI must fail closed instead of becoming verified.'

$reparseAcl = New-ExactRuntimeAclAudit
$reparseAcl.valid = $false; $reparseAcl.reparse_points = 1
$reparseResult = Resolve-TradingLabRuntimeVerificationState `
    (New-RuntimeVerificationInventory $complete.PSObject.Copy()) $reparseAcl `
    'C:\Program Files\AutomatonPython\3.14.5' '3.14.5' 'C:\Users'
Assert-True (-not $reparseResult.verified -and 'ACL_REPARSE_POINTS_ZERO' -in $reparseResult.failures) 'A runtime reparse point must never produce PRESENT_VERIFIED.'

$unexpectedMachineMsi = @($machineMsiExact) + @([pscustomobject]@{
    product_code = '{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}'
    display_name = 'Python 3.14.5 Unexpected (64-bit)'
    user_data_sid = 'S-1-5-18'
})
$unexpectedMachineState = Resolve-TradingLabMachineMsiComponentState $unexpectedMachineMsi
Assert-True (-not $unexpectedMachineState.valid -and $unexpectedMachineState.unexpected_product_codes.Count -eq 1) 'Unexpected fifth machine MSI must fail closed.'

foreach ($required in @(
    "`$machinePython = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'",
    "`$env:TEMP = `$canonicalTemp", "`$env:TMP = `$canonicalTemp",
    "`$env:PYTHONDONTWRITEBYTECODE = '1'"
)) {
    Assert-True (($setup + $gatewayEnvironment).Contains($required)) "Runtime boundary lacks: $required"
}
Assert-True (-not $setup.Contains('& python -c')) 'Setup must not resolve Python from PATH.'
Assert-True (-not $gatewayEnvironment.Contains('Windows\TEMP')) 'Gateway environment must not use Windows TEMP.'
Assert-True ($gatewayStart.IndexOf('Initialize-GatewayPythonEnvironment') -lt $gatewayStart.IndexOf('& $python')) 'Private TEMP must precede Python.'
foreach ($gate in @(
    'PYTHON_BASE_MACHINE_WIDE', 'PYTHON_BASE_OUTSIDE_USER_PROFILE',
    'PYTHON_GATEWAY_EXECUTE', 'PYTHON_GATEWAY_MODIFY_DENY', 'VENV_BASE_OUTSIDE_USER_PROFILE'
)) {
    Assert-True ($gateway.Contains($gate)) "Gateway runtime report lacks gate: $gate"
    Assert-True ($collector.Contains($gate)) "Collector lacks gate: $gate"
}

[pscustomobject]@{
    POWERSHELL_AST = 'PASS'
    PYTHON_INVENTORY_CLASSIFICATION = 'PASS'
    INVENTORY_INSTALLED_ACL_PENDING = 'PASS'
    INVENTORY_RUNTIME_VERIFIED = 'PASS'
    INVENTORY_GATEWAY_MODIFY_NOT_VERIFIED = 'PASS'
    INVENTORY_AGENT_ALLOW_NOT_VERIFIED = 'PASS'
    INVENTORY_UNEXPECTED_MSI_NOT_VERIFIED = 'PASS'
    INVENTORY_REPARSE_NOT_VERIFIED = 'PASS'
    INVENTORY_READ_ONLY = 'PASS'
    BUILD_VENV_REQUIRES_VERIFIED_RUNTIME = 'PASS'
    SAME_VERSION_TRADITIONAL_FAIL_CLOSED = 'PASS'
    PYTHON_MANAGER_RUNTIME_DISTINCT = 'PASS'
    PARTIAL_TARGET_RUNTIME_DETECTED = 'PASS'
    BOOTSTRAPPER_1603_CLASSIFIED = 'PASS'
    BROKEN_VENV_DETECTED = 'PASS'
    EXPLICIT_PHASE_BOUNDARY = 'PASS'
    IDEMPOTENT_RESUME_DESIGN = 'PASS'
    DURABLE_INSTALLER_LOGS = 'PASS'
    PREVIOUS_PHASE_PREPARE_WHEELHOUSE = 'PASS'
    PREVIOUS_PHASE_UNINSTALL_TRADITIONAL = 'PASS'
    MISSING_UNINSTALL_REPORT_FAIL_CLOSED = 'PASS'
    CORRUPT_UNINSTALL_REPORT_FAIL_CLOSED = 'PASS'
    WRONG_UNINSTALL_PHASE_FAIL_CLOSED = 'PASS'
    FAILED_UNINSTALL_STATUS_FAIL_CLOSED = 'PASS'
    INCOMPATIBLE_UNINSTALL_SCHEMA_FAIL_CLOSED = 'PASS'
    MISSING_WHEELHOUSE_FAIL_CLOSED = 'PASS'
    CORRUPT_WHEEL_FAIL_CLOSED = 'PASS'
    WHEELHOUSE_COMPLETE_EXACT = 'PASS'
    MISSING_PREPARE_REPORT_FAIL_CLOSED = 'PASS'
    STALE_PHASE_STATE_NOT_AUTHORIZATION = 'PASS'
    PYTHON_MANAGER_UNINSTALL_PLAN_CRITICAL_FAIL = 'PASS'
    TRADITIONAL_MSI_COMPONENTS_EXPECTED_9 = 'PASS'
    UNEXPECTED_MSI_PRODUCT_CODE_FAIL_CLOSED = 'PASS'
    TRADITIONAL_MSI_REAPPEAR_FAIL_CLOSED = 'PASS'
    PARTIAL_TARGET_REAPPEAR_FAIL_CLOSED = 'PASS'
    MIXED_PYTHONCORE_REAPPEAR_FAIL_CLOSED = 'PASS'
    INSTALLER_HASH_MISMATCH_FAIL_CLOSED = 'PASS'
    USER_PROFILE_TARGET_FAIL_CLOSED = 'PASS'
    MINIMAL_INSTALLER_COMPONENTS = 'PASS'
    POST_INSTALL_METADATA_STDIN = 'PASS'
    INSTALLED_VALIDATION_PENDING_RECOVERY = 'PASS'
    RECOVERY_NEVER_RERUNS_INSTALLER = 'PASS'
    BUNDLE_HKCU_MACHINE_PAYLOAD_CLASSIFICATION = 'PASS'
    EXPECTED_MACHINE_MSI_COMPONENTS_4 = 'PASS'
    UNEXPECTED_MACHINE_MSI_FAIL_CLOSED = 'PASS'
    INCOMPLETE_ACL_STATE_DETECTED = 'PASS'
    ACL_ONLY_RESUME_BOUNDARY = 'PASS'
    ACL_PLAN_EXACT = 'PASS'
    ACL_TARGET_OUTSIDE_RUNTIME_FAIL_CLOSED = 'PASS'
    ACL_REPARSE_TARGET_FAIL_CLOSED = 'PASS'
    ACL_GATEWAY_PRIVILEGE_ESCALATION_FAIL_CLOSED = 'PASS'
    ACL_AGENT_ALLOW_FAIL_CLOSED = 'PASS'
    ACL_DENY_ACE_FAIL_CLOSED = 'PASS'
    ACL_UNRESOLVED_IDENTITY_FAIL_CLOSED = 'PASS'
    ACL_SYSTEM_ADMIN_FULLCONTROL_REQUIRED = 'PASS'
    ACL_INHERITANCE_PROTECTED_REQUIRED = 'PASS'
    ACL_BROAD_GROUP_MODIFY_FAIL_CLOSED = 'PASS'
    ACL_DRY_RUN_NO_MUTATION = 'PASS'
    FILESYSTEM_RIGHTS_SAFE_CASES = 'PASS'
    FILESYSTEM_RIGHTS_UNSAFE_CASES = 'PASS'
    ATOMIC_MUTATION_MASK = 'PASS'
    GATEWAY_MUTATION_INTERSECTION_ZERO = 'PASS'
    ACL_ALREADY_APPLIED_NO_REAPPLY = 'PASS'
    ACL_RECURSIVE_AUDIT_EXACT = 'PASS'
    ACL_ROOT_PROTECTED_DESCENDANTS_PROTECTED = 'PASS'
    ACL_DESCENDANT_SAFE_INHERITED = 'PASS'
    ACL_SAFE_INHERITED_60_NO_REPAIR = 'PASS'
    ACL_SAFE_INHERITED_NO_RECURSIVE_FINDING = 'PASS'
    ACL_SAFE_INHERITED_COUNT_DYNAMIC = 'PASS'
    ACL_INHERITANCE_CHAIN_CONFINED = 'PASS'
    ACL_SAFE_STATE_NO_OP = 'PASS'
    ACL_SAFE_STATE_SET_ACL_NEVER_CALLED = 'PASS'
    ACL_RECURSIVE_GATEWAY_UNSAFE_FAIL_CLOSED = 'PASS'
    ACL_RECURSIVE_AGENT_DENY_UNEXPECTED_FAIL_CLOSED = 'PASS'
    ACL_RECURSIVE_OWNER_INHERITANCE_REPARSE_FAIL_CLOSED = 'PASS'
    COMPOSITE_RIGHTS_ANTIPATTERN_REMOVED = 'PASS'
    FAILURE_PRESERVES_INSTALLED_RUNTIME = 'PASS'
    VENV_STAGING_AND_ROLLBACK = 'PASS'
    VENV_HASH_LOCK_ONLY = 'PASS'
    META_TRADER5_METADATA_ONLY = 'PASS'
    MT5_NOT_ACCESSED = 'PASS'
    BUILD_VENV_RESUME_EVIDENCE = 'PASS'
    BUILD_VENV_RESUME_MISSING_CORRUPT_FAIL_CLOSED = 'PASS'
    BUILD_VENV_EXPLICIT_GATEWAY_EVIDENCE = 'PASS'
    BUILD_VENV_EXPLICIT_AGENT_EVIDENCE = 'PASS'
    BUILD_VENV_TOKEN_BOUNDARIES_FAIL_CLOSED = 'PASS'
    BUILD_VENV_OFFLINE_PLAN_EXACT = 'PASS'
    BUILD_VENV_ACTIVE_VENV_ISOLATED = 'PASS'
    BUILD_VENV_STAGING_DISTRIBUTIONS_EXACT = 'PASS'
    BUILD_VENV_FAILED_STAGING_PRESERVED = 'PASS'
    PROMOTE_VENV_EVIDENCE_CHAIN = 'PASS'
    PROMOTE_VENV_STAGING_EVIDENCE_FAIL_CLOSED = 'PASS'
    PROMOTE_VENV_PROCESS_USERS_FAIL_CLOSED = 'PASS'
    PROMOTE_VENV_ARTIFACTS_FAIL_CLOSED = 'PASS'
    PROMOTE_VENV_TRANSACTIONAL_PLAN = 'PASS'
    PROMOTE_VENV_ORDERED_PLAN_LIVE_SHAPE = 'PASS'
    PROMOTE_VENV_STAGING_NON_RELOCATABLE = 'PASS'
    PROMOTE_VENV_OFFLINE_FINAL_BUILD = 'PASS'
    PROMOTE_VENV_ROLLBACK = 'PASS'
    PROMOTE_VENV_DRY_RUN_NO_MUTATION = 'PASS'
} | ConvertTo-Json
