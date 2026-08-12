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
    'WHEELHOUSE_LOCK_COVERAGE=FAIL', 'foreach ($locked in Get-LockedRequirements)',
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
    'PromoteVenvAlreadyComplete', 'UninstallTraditionalAlreadyComplete',
    'PromotionRolledBack', 'last_applied_phase',
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
Assert-True ($installer.IndexOf('Assert-Venv $stagingVenvPath') -lt $installer.LastIndexOf('Move-Item -LiteralPath $stagingVenvPath -Destination $venvPath')) 'Staging validation must precede promotion.'
Assert-True (-not $installer.Contains('[System.IO.Directory]::Delete')) 'Recovery must retain failed staging for diagnosis.'

. $inventoryPath
Assert-True ((Resolve-TradingLabInstallerExit 0) -eq 'SUCCESS') 'Installer exit 0 classification regressed.'
Assert-True ((Resolve-TradingLabInstallerExit 1603) -eq 'INSTALLER_MAINTENANCE_COLLISION') 'Bootstrapper 1603 must be classified as a maintenance collision.'
Assert-True ((Resolve-TradingLabInstallerExit 5) -eq 'INSTALLER_EXIT_NONZERO') 'Unexpected installer exits must fail closed.'
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
    VENV_STAGING_AND_ROLLBACK = 'PASS'
    VENV_HASH_LOCK_ONLY = 'PASS'
    META_TRADER5_METADATA_ONLY = 'PASS'
    MT5_NOT_ACCESSED = 'PASS'
} | ConvertTo-Json
