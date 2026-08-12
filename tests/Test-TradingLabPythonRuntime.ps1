$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$installerPath = Join-Path $root 'scripts\Install-TradingLabPythonRuntime.ps1'
$inventoryPath = Join-Path $root 'scripts\TradingLabPythonInventory.ps1'
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
    $installerPath, $inventoryPath, $aclPlanPath, $rightsPath, $aclGatePath,
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
    "Invoke-LoggedProcess `$basePython @('-I', '-m', 'venv', `$stagingVenvPath)",
    "'--no-index', '--find-links', `$wheelhousePath",
    'importlib.metadata.version("MetaTrader5")',
    'TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING', 'BuildVenvAlreadyComplete',
    'PromoteVenvAlreadyComplete', 'PromotionRolledBack', 'current_run_applied_phase',
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
    'MUST_NOT_CALL_SET_ACL', 'ACL_REAPPLIED', 'SET_ACL_CALL_COUNT',
    'ACL_OWNER_ADMINISTRATORS', 'ACL_INHERITANCE_PROTECTED',
    'PYTHON_GATEWAY_READ', 'PYTHON_GATEWAY_WRITE_DENY',
    'PYTHON_GATEWAY_DELETE_DENY', 'PYTHON_GATEWAY_CHANGE_PERMISSIONS_DENY',
    'PYTHON_GATEWAY_TAKE_OWNERSHIP_DENY', 'ACL_UNEXPECTED_PRINCIPALS',
    'ACL_RECURSIVE_FINDINGS', 'ACL_REPARSE_POINTS',
    'VENV_BASE_OUTSIDE_USER_PROFILE', 'VENV_LOCK_MATCH',
    'META_TRADER5_PACKAGE_PRESENT',
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
    'Invoke-TradingLabPythonStdinJson',
    'Test-TradingLabManagerExcludedFromUninstallPlan',
    'Resolve-TradingLabMsiComponentSetState',
    'PYTHON_MANAGER_RUNTIME', 'TRADITIONAL_BUNDLE', 'TRADITIONAL_MSI_COMPONENT',
    'partial_target_runtime', 'completed_target_runtime', 'broken_active_venv',
    'mixed_pythoncore_registration', 'same_version_traditional_install_present',
    'traditional_bundle_registration_scope', 'traditional_runtime_payload_scope',
    'machine_runtime_target_present', 'machine_runtime_msi_components',
    'EXPECTED_INSTALLED_TARGET_RUNTIME', 'CONFLICTING_PREEXISTING_RUNTIME',
    'target_probe', 'TARGET_LAYOUT_INCOMPLETE'
)) {
    Assert-True ($inventorySource.Contains($required)) "Python inventory lacks invariant: $required"
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
Assert-True ($installer.IndexOf('Assert-InstallMachinePreconditions $inventory') -lt $installer.IndexOf('Start-LoggedInstaller $plan.executable')) 'Current runtime state must block install execution.'
Assert-True ($installer.IndexOf('$report.previous_phase_verified = $true') -lt $installer.IndexOf("Start-LoggedInstaller `$bundleExecutable")) 'Durable previous-phase verification must precede supported uninstall.'
Assert-True ($installer.IndexOf('Assert-PythonManagerPreserved $inventory $plan') -lt $installer.IndexOf("Start-LoggedInstaller `$bundleExecutable")) 'Manager preservation proof must precede supported uninstall.'
Assert-True ($installer.IndexOf('Assert-UninstallPlanHasNoDirectCleanup $plan') -lt $installer.IndexOf("Start-LoggedInstaller `$bundleExecutable")) 'No-direct-cleanup proof must precede supported uninstall.'
Assert-True ($installer.IndexOf('Assert-Venv $stagingVenvPath') -lt $installer.LastIndexOf('Move-Item -LiteralPath $stagingVenvPath -Destination $venvPath')) 'Staging validation must precede promotion.'
Assert-True (-not $installer.Contains('[System.IO.Directory]::Delete')) 'Recovery must retain failed staging for diagnosis.'
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
$alreadyAppliedBranch = $completeBlock.IndexOf("if (`$aclState.state -eq 'EXACT')")
$alreadyAppliedReturn = $completeBlock.IndexOf('return', $alreadyAppliedBranch)
Assert-True ($alreadyAppliedBranch -ge 0 -and $alreadyAppliedReturn -gt $alreadyAppliedBranch -and $alreadyAppliedReturn -lt $aclMutationCall) 'Already-applied ACL recovery must return before Set-Acl.'
Assert-True ($completeBlock.Substring($alreadyAppliedBranch, $alreadyAppliedReturn - $alreadyAppliedBranch).Contains("`$report.must_not_call_set_acl = `$true")) 'Already-applied ACL recovery must set MUST_NOT_CALL_SET_ACL.'
Assert-True ($completeBlock.Substring($alreadyAppliedBranch, $alreadyAppliedReturn - $alreadyAppliedBranch).Contains("`$report.acl_reapplied = `$false")) 'Already-applied ACL recovery must report ACL_REAPPLIED=false.'
Assert-True (-not $completeBlock.Substring(0, $dryRunReturn).Contains('Set-Acl')) 'Dry-run path must never call Set-Acl.'
Assert-True (-not $completeBlock.Substring(0, $dryRunReturn).Contains('.SetOwner(')) 'Dry-run path must never modify owner.'
Assert-True ($installer.Contains('Assert-ExactRuntimeTarget $Root')) 'ACL application must validate the exact runtime target.'
Assert-True ($installer.Contains('[System.IO.Directory]::EnumerateFileSystemEntries')) 'ACL tree walk must avoid following reparse points recursively.'
Assert-True ($installer.IndexOf('Assert-InMemoryRuntimeSecurity $directorySecurity $Plan') -lt $installer.IndexOf('Set-Acl -LiteralPath $item.FullName')) 'In-memory directory ACL validation must precede filesystem mutation.'
Assert-True ($installer.IndexOf('Assert-InMemoryRuntimeSecurity $fileSecurity $Plan') -lt $installer.IndexOf('Set-Acl -LiteralPath $item.FullName')) 'In-memory file ACL validation must precede filesystem mutation.'
Assert-True ($inventorySource.Contains("`$startInfo.Arguments = '-I -'")) 'Python metadata must execute stdin source with python -.'
Assert-True ($inventorySource.Contains('RedirectStandardInput = $true')) 'Python stdin must be redirected explicitly.'
Assert-True ($inventorySource.Contains('$process.StandardInput.Write($Source)')) 'Python source must be written verbatim to stdin.'
Assert-True (-not $inventorySource.Contains("-I -c")) 'Python metadata must not use fragile -c quoting.'
Assert-True ($inventorySource.Contains("separators=(',', ':')")) 'Metadata JSON quoting regression is not covered.'

. $inventoryPath
. $aclPlanPath
. $rightsPath
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

function New-ValidAclAuditItem([string] $Path) {
    [pscustomobject]@{
        path = $Path
        is_directory = $true
        is_reparse_point = $false
        owner_sid = $aclAdministratorsSid
        inheritance_protected = $true
        rules = @(
            [pscustomobject]@{ sid = $aclSystemSid; rights = $aclFullControl; type = 'Allow'; inherited = $false },
            [pscustomobject]@{ sid = $aclAdministratorsSid; rights = $aclFullControl; type = 'Allow'; inherited = $false },
            [pscustomobject]@{ sid = $aclGatewaySid; rights = $aclGatewayRx; type = 'Allow'; inherited = $false }
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
foreach ($unsafeGatewayRight in @(
    [System.Security.AccessControl.FileSystemRights]::Modify,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.FileSystemRights]::Delete,
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
)) {
    $case = Copy-AclAuditFixture $cleanAuditItems
    ($case[0].rules | Where-Object { $_.sid -eq $aclGatewaySid }).rights = [int64]$unsafeGatewayRight
    Assert-True (-not (Test-AclAuditFixture $case).valid) "Unsafe Gateway audit rights must fail closed: $unsafeGatewayRight"
}
$agentAuditCase = Copy-AclAuditFixture $cleanAuditItems
$agentAuditCase[0].rules = @($agentAuditCase[0].rules) + @([pscustomobject]@{ sid = $aclAgentSid; rights = 1L; type = 'Allow'; inherited = $false })
Assert-True (-not (Test-AclAuditFixture $agentAuditCase).valid) 'Agent Allow in recursive audit must fail closed.'
$denyAuditCase = Copy-AclAuditFixture $cleanAuditItems
$denyAuditCase[0].rules = @($denyAuditCase[0].rules) + @([pscustomobject]@{ sid = $aclAgentSid; rights = 1L; type = 'Deny'; inherited = $false })
Assert-True (-not (Test-AclAuditFixture $denyAuditCase).valid) 'Deny ACE in recursive audit must fail closed.'
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
    ACL_RECURSIVE_GATEWAY_UNSAFE_FAIL_CLOSED = 'PASS'
    ACL_RECURSIVE_AGENT_DENY_UNEXPECTED_FAIL_CLOSED = 'PASS'
    ACL_RECURSIVE_OWNER_INHERITANCE_REPARSE_FAIL_CLOSED = 'PASS'
    COMPOSITE_RIGHTS_ANTIPATTERN_REMOVED = 'PASS'
    FAILURE_PRESERVES_INSTALLED_RUNTIME = 'PASS'
    VENV_STAGING_AND_ROLLBACK = 'PASS'
    VENV_HASH_LOCK_ONLY = 'PASS'
    META_TRADER5_METADATA_ONLY = 'PASS'
    MT5_NOT_ACCESSED = 'PASS'
} | ConvertTo-Json
