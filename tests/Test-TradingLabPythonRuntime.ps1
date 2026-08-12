$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$installerPath = Join-Path $root 'scripts\Install-TradingLabPythonRuntime.ps1'
$inventoryPath = Join-Path $root 'scripts\TradingLabPythonInventory.ps1'
$setupPath = Join-Path $root 'scripts\setup.ps1'
$gatewayPath = Join-Path $root 'scripts\Test-GatewayRuntimeAcl.ps1'
$collectorPath = Join-Path $root 'scripts\Collect-RuntimeAclResults.ps1'
$gatewayEnvironmentPath = Join-Path $root 'scripts\Initialize-GatewayPythonEnvironment.ps1'
$gatewayStartPath = Join-Path $root 'scripts\start_gateway.ps1'

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

foreach ($path in @(
    $installerPath, $inventoryPath, $setupPath, $gatewayPath, $collectorPath,
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
$setup = [System.IO.File]::ReadAllText($setupPath)
$gateway = [System.IO.File]::ReadAllText($gatewayPath)
$collector = [System.IO.File]::ReadAllText($collectorPath)
$gatewayEnvironment = [System.IO.File]::ReadAllText($gatewayEnvironmentPath)
$gatewayStart = [System.IO.File]::ReadAllText($gatewayStartPath)

foreach ($required in @(
    '#Requires -RunAsAdministrator',
    "[ValidateSet('Inventory', 'PrepareWheelhouse', 'UninstallTraditional', 'InstallMachineRuntime', 'BuildVenv', 'PromoteVenv')]",
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
    'Start-LoggedInstaller $InstallerPath', "@('/log', `$LogPath)",
    'InstallAllUsers=1', 'Include_dev=0', 'Include_test=0', 'Include_doc=0', 'Include_tcltk=0',
    "Invoke-LoggedProcess `$basePython @('-I', '-m', 'venv', `$stagingVenvPath)",
    "'--no-index', '--find-links', `$wheelhousePath",
    'importlib.metadata.version("MetaTrader5")',
    'InstallMachineRuntimeAlreadyComplete', 'BuildVenvAlreadyComplete',
    'PromoteVenvAlreadyComplete', 'PromotionRolledBack', 'current_run_applied_phase',
    "required_previous_phase = `$null", "previous_phase_verified = `$false",
    "previous_phase_report = `$null", 'Get-VerifiedPrepareWheelhouseEvidence',
    "`$report.gates.PREVIOUS_PHASE_PREPARE_WHEELHOUSE = 'PASS'",
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
    'Assert-ExpectedTraditionalMsiComponents', 'Assert-PythonManagerPreserved',
    'Assert-UninstallPlanHasNoDirectCleanup',
    'PYTHON_BASE_MACHINE_WIDE', 'PYTHON_BASE_OUTSIDE_USER_PROFILE',
    'PYTHON_GATEWAY_EXECUTE', 'PYTHON_GATEWAY_MODIFY_DENY',
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
    'Test-TradingLabManagerExcludedFromUninstallPlan',
    'Resolve-TradingLabMsiComponentSetState',
    'PYTHON_MANAGER_RUNTIME', 'TRADITIONAL_BUNDLE', 'TRADITIONAL_MSI_COMPONENT',
    'partial_target_runtime', 'completed_target_runtime', 'broken_active_venv',
    'mixed_pythoncore_registration', 'same_version_traditional_install_present',
    'target_probe', 'TARGET_LAYOUT_INCOMPLETE'
)) {
    Assert-True ($inventorySource.Contains($required)) "Python inventory lacks invariant: $required"
}

foreach ($forbidden in @(
    'Invoke-WebRequest', 'Start-BitsTransfer', 'curl.exe', 'msizap', 'Win32_Product',
    'Remove-Item', 'reg.exe delete', 'Package Cache', 'WriteAllText((Join-Path $Root ''pyvenv.cfg'')',
    'import MetaTrader5', '.initialize(', '.login(', '.symbol_select(', '.order_check(', '.order_send(',
    'Start-Service', 'New-LocalUser', 'Add-LocalGroupMember'
)) {
    Assert-True (-not ($installer + $inventorySource).Contains($forbidden)) "Python recovery gate contains forbidden action: $forbidden"
}

$inventoryApply = $installer.IndexOf('INVENTORY_APPLY_FORBIDDEN')
$phaseSwitch = $installer.IndexOf('switch ($Phase)')
Assert-True ($inventoryApply -ge 0 -and $inventoryApply -lt $phaseSwitch) 'Inventory must reject -Apply before phase dispatch.'
Assert-True ($installer.IndexOf('Assert-NoTraditionalRuntime $inventory') -lt $installer.IndexOf('Start-LoggedInstaller $InstallerPath')) 'Traditional registration must block install execution.'
Assert-True ($installer.IndexOf('Assert-NoPartialTarget $inventory') -lt $installer.IndexOf('Start-LoggedInstaller $InstallerPath')) 'Partial target must block install execution.'
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

. $inventoryPath
Assert-True ((Resolve-TradingLabInstallerExit 0) -eq 'SUCCESS') 'Installer exit 0 classification regressed.'
Assert-True ((Resolve-TradingLabInstallerExit 1603) -eq 'INSTALLER_MAINTENANCE_COLLISION') 'Bootstrapper 1603 must be classified as a maintenance collision.'
Assert-True ((Resolve-TradingLabInstallerExit 5) -eq 'INSTALLER_EXIT_NONZERO') 'Unexpected installer exits must fail closed.'

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
Assert-True ($partial.same_version_traditional_install_present -eq 'FAIL') 'Same-version traditional install must fail prevalidation.'
Assert-True ($partial.partial_target_runtime -eq 'PRESENT') 'Partial target was not classified.'
Assert-True ($partial.broken_active_venv -eq 'PRESENT') 'Broken redirector venv was not classified.'
Assert-True ($partial.prevalidation -eq 'FAIL') 'Mixed maintenance state must fail closed.'

$clean = Resolve-Synthetic @($manager) @() @() $true $false $false $true
Assert-True ($clean.same_version_traditional_install_present -eq 'PASS') 'Clean traditional registration state must pass.'
Assert-True ($clean.python_manager_runtime -eq 'FUNCTIONAL') 'Manager must survive traditional cleanup.'

$mixedCore = [pscustomobject]@{
    managed_by_python_manager = $true
    executable_path = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'
}
$mixedOnly = Resolve-Synthetic @($manager) @() @($mixedCore) $true $false $false $true
Assert-True ($mixedOnly.mixed_pythoncore_registration -eq 'PRESENT') 'Mixed PythonCore registration was not detected.'
Assert-True ($mixedOnly.prevalidation -eq 'FAIL') 'Mixed PythonCore registration must fail prevalidation alone.'

$machine = [pscustomobject]@{ kind = 'TRADITIONAL_BUNDLE'; scope = 'HKLM' }
$complete = Resolve-Synthetic @($manager, $machine) @([pscustomobject]@{}) @() $true $true $true $false
Assert-True ($complete.traditional_machine_runtime -eq 'PRESENT') 'Machine traditional runtime was not distinguished.'
Assert-True ($complete.completed_target_runtime -eq 'PRESENT_UNVERIFIED') 'Complete layout must still require execution validation.'

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
    MISSING_WHEELHOUSE_FAIL_CLOSED = 'PASS'
    CORRUPT_WHEEL_FAIL_CLOSED = 'PASS'
    WHEELHOUSE_COMPLETE_EXACT = 'PASS'
    MISSING_PREPARE_REPORT_FAIL_CLOSED = 'PASS'
    STALE_PHASE_STATE_NOT_AUTHORIZATION = 'PASS'
    PYTHON_MANAGER_UNINSTALL_PLAN_CRITICAL_FAIL = 'PASS'
    TRADITIONAL_MSI_COMPONENTS_EXPECTED_9 = 'PASS'
    UNEXPECTED_MSI_PRODUCT_CODE_FAIL_CLOSED = 'PASS'
    VENV_STAGING_AND_ROLLBACK = 'PASS'
    VENV_HASH_LOCK_ONLY = 'PASS'
    META_TRADER5_METADATA_ONLY = 'PASS'
    MT5_NOT_ACCESSED = 'PASS'
} | ConvertTo-Json
