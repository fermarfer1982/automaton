Set-StrictMode -Version 2.0

. (Join-Path $PSScriptRoot 'Test-PythonStagingOnlyRuntimeAcl.ps1')

$script:PythonStagingOnlyIsFinal = $true
$script:PythonStagingOnlyMode = 'PYTHON_FINAL_ONLY'
$script:PythonStagingOnlyRoot = 'C:\automaton\.venv'
$script:PythonStagingOnlyExecutable = 'C:\automaton\.venv\Scripts\python.exe'
$script:PythonStagingOnlySitePackages = 'C:\automaton\.venv\Lib\site-packages'
$script:PythonStagingOnlyFastApiFile = 'C:\automaton\.venv\Lib\site-packages\fastapi\__init__.py'
$script:PythonStagingOnlyConfig = 'C:\automaton\.venv\pyvenv.cfg'

function Test-PythonFinalOnlyExactPath([string] $Path, [string] $ExpectedPath) {
    return Test-PythonStagingOnlyExactPath $Path $ExpectedPath
}

function Test-PythonFinalOnlyTargetPresent([string] $Path) {
    return Test-PythonStagingOnlyTargetPresent $Path
}

function Test-PythonFinalOnlyIdentity([string] $EffectiveSid, [string] $ExpectedSid) {
    return Test-PythonStagingOnlyIdentity $EffectiveSid $ExpectedSid
}

function Test-PythonFinalOnlyReparseAttributes([System.IO.FileAttributes] $Attributes) {
    return Test-PythonStagingOnlyReparseAttributes $Attributes
}

function Test-PythonFinalOnlyPathConfined([string] $Path) {
    return Test-PythonStagingOnlyPathConfined $Path $script:PythonStagingOnlyRoot
}

function Test-PythonFinalOnlyConfigRecord([string[]] $Lines) {
    return Test-PythonStagingOnlyConfigRecord $Lines
}

function Test-PythonFinalOnlyExecutionMetadata([object] $Execution, [object] $Metadata) {
    return Test-PythonStagingOnlyExecutionMetadata $Execution $Metadata
}

function Test-PythonFinalOnlyImportGate([object] $Metadata, [string] $Property) {
    return Test-PythonStagingOnlyImportGate $Metadata $Property
}

function Resolve-PythonFinalOnlyAccessExpectation(
    [bool] $Allowed,
    [int] $ErrorCode,
    [bool] $ExpectedAllow
) {
    return Resolve-PythonStagingOnlyAccessExpectation $Allowed $ErrorCode $ExpectedAllow
}

function Get-PythonFinalOnlyReportFileName([string] $Role, [string] $RunId) {
    return Get-PythonStagingOnlyReportFileName $Role $RunId
}

function Get-PythonFinalOnlyReportPath([string] $Role, [string] $RunId) {
    return Get-PythonStagingOnlyReportPath $Role $RunId
}

function Test-PythonFinalOnlyMt5Metadata([object] $Metadata) {
    return Test-PythonStagingOnlyMt5Metadata $Metadata
}

function Test-PythonFinalOnlyMt5NotImported([object] $Metadata) {
    return Test-PythonStagingOnlyMt5NotImported $Metadata
}

function Resolve-AgentPythonFinalExecutionExpectation(
    [bool] $ProcessStarted,
    [Nullable[int]] $ExitCode,
    [bool] $SuccessMarkerObserved,
    [int] $StartErrorCode
) {
    return Resolve-AgentPythonStagingExecutionExpectation `
        $ProcessStarted $ExitCode $SuccessMarkerObserved $StartErrorCode
}

function Test-PythonFinalOnlyBoundaryRecord([object] $Boundaries) {
    try {
        return $Boundaries.trading_mode -eq 'OBSERVE_ONLY' -and
            -not [bool]$Boundaries.build_venv -and
            -not [bool]$Boundaries.promote_venv -and
            -not [bool]$Boundaries.cleanup -and
            -not [bool]$Boundaries.staging_venv_accessed -and
            -not [bool]$Boundaries.staging_venv_modified -and
            -not [bool]$Boundaries.backup_venv_accessed -and
            -not [bool]$Boundaries.backup_venv_modified -and
            -not [bool]$Boundaries.mt5_imported -and
            -not [bool]$Boundaries.mt5_accessed -and
            -not [bool]$Boundaries.order_check_called -and
            -not [bool]$Boundaries.order_send_called -and
            -not [bool]$Boundaries.gateway_started -and
            -not [bool]$Boundaries.automaton_started -and
            -not [bool]$Boundaries.acl_modified -and
            -not [bool]$Boundaries.filesystem_final_modified
    } catch { return $false }
}

function Invoke-TradingLabPythonFinalOnlyRuntimeAcl(
    [ValidateSet('AutomatonGateway', 'AutomatonAgent')]
    [string] $Role,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [string] $EffectiveSid,
    [bool] $AdministrativeToken
) {
    return Invoke-TradingLabPythonStagingOnlyRuntimeAcl `
        -Role $Role -RunId $RunId -EffectiveSid $EffectiveSid `
        -AdministrativeToken $AdministrativeToken
}
