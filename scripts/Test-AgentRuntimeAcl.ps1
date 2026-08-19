[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [switch] $PythonBaseOnly,
    [switch] $PythonStagingOnly,
    [switch] $PythonFinalOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$expectedSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$effectiveIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$effectiveSid = $effectiveIdentity.User.Value
if ($effectiveSid -ne $expectedSid) {
    throw "Wrong runtime identity. Expected SID $expectedSid; received $effectiveSid. No tests were run."
}
$principal = [System.Security.Principal.WindowsPrincipal]::new($effectiveIdentity)
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'AutomatonAgent runtime ACL tests refuse an administrative token.'
}

$normalizedRunId = $RunId.ToLowerInvariant()
$isolatedModeCount = @(@($PythonBaseOnly, $PythonStagingOnly, $PythonFinalOnly) | Where-Object { [bool]$_ }).Count
if ($isolatedModeCount -gt 1) {
    throw 'Select only one isolated runtime ACL mode.'
}
if ($PythonBaseOnly) {
    . (Join-Path $PSScriptRoot 'Test-PythonBaseOnlyRuntimeAcl.ps1')
    $baseOnlyResult = Invoke-TradingLabPythonBaseOnlyRuntimeAcl `
        -Role 'AutomatonAgent' -RunId $normalizedRunId `
        -EffectiveSid $effectiveSid -AdministrativeToken $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    if ($baseOnlyResult.exit_code -ne 0) { exit $baseOnlyResult.exit_code }
    return
}
if ($PythonStagingOnly) {
    . (Join-Path $PSScriptRoot 'Test-PythonStagingOnlyRuntimeAcl.ps1')
    $stagingOnlyResult = Invoke-TradingLabPythonStagingOnlyRuntimeAcl `
        -Role 'AutomatonAgent' -RunId $normalizedRunId `
        -EffectiveSid $effectiveSid -AdministrativeToken $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    if ($stagingOnlyResult.exit_code -ne 0) { exit $stagingOnlyResult.exit_code }
    return
}
if ($PythonFinalOnly) {
    . (Join-Path $PSScriptRoot 'Test-PythonFinalOnlyRuntimeAcl.ps1')
    $finalOnlyResult = Invoke-TradingLabPythonFinalOnlyRuntimeAcl `
        -Role 'AutomatonAgent' -RunId $normalizedRunId `
        -EffectiveSid $effectiveSid -AdministrativeToken $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    if ($finalOnlyResult.exit_code -ne 0) { exit $finalOnlyResult.exit_code }
    return
}
$agentStatePath = 'C:\Users\AutomatonAgent\.automaton'
$runtimeTempBase = Join-Path $agentStatePath 'runtime-tmp'
$runtimeTempPath = Join-Path $runtimeTempBase $normalizedRunId
$runtimeTempCleanupAttempted = $false
$runtimeTempCleanupSucceeded = $false
$scriptExitCode = 0

function Get-CanonicalDirectoryPath([string] $Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Assert-PathConfined([string] $Path, [string] $AuthorizedRoot) {
    $candidate = Get-CanonicalDirectoryPath $Path
    $root = Get-CanonicalDirectoryPath $AuthorizedRoot
    if (-not $candidate.StartsWith(
        $root + '\', [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Runtime TEMP escapes its authorized root: $candidate"
    }
}

function Assert-DirectoryNotReparsePoint([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        throw "Runtime TEMP component is not a directory: $Path"
    }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Runtime TEMP component is a reparse point: $Path"
    }
}

function Initialize-PrivateRuntimeTemp(
    [string] $AuthorizedRoot,
    [string] $TempBase,
    [string] $TempPath
) {
    $createdRunTemp = $false
    try {
        Assert-PathConfined $TempBase $AuthorizedRoot
        Assert-PathConfined $TempPath $AuthorizedRoot
        Assert-DirectoryNotReparsePoint $AuthorizedRoot
        if ([System.IO.Directory]::Exists($TempBase)) {
            Assert-DirectoryNotReparsePoint $TempBase
        } else {
            [System.IO.Directory]::CreateDirectory($TempBase) | Out-Null
            Assert-DirectoryNotReparsePoint $TempBase
        }
        if ([System.IO.Directory]::Exists($TempPath) -or [System.IO.File]::Exists($TempPath)) {
            throw 'Runtime TEMP already exists for this RunId. Inspect it and use a new RunId.'
        }
        [System.IO.Directory]::CreateDirectory($TempPath) | Out-Null
        $createdRunTemp = $true
        Assert-DirectoryNotReparsePoint $TempPath
        $env:TEMP = Get-CanonicalDirectoryPath $TempPath
        $env:TMP = $env:TEMP
        if ((Get-CanonicalDirectoryPath ([System.IO.Path]::GetTempPath())) -ne $env:TEMP) {
            throw 'The process did not adopt the confined runtime TEMP.'
        }
        $canaryPath = Join-Path $TempPath '.runtime-temp-write.canary'
        $stream = [System.IO.File]::Open(
            $canaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try { $stream.WriteByte(1); $stream.Flush() } finally { $stream.Dispose() }
        [System.IO.File]::Delete($canaryPath)
        if ([System.IO.File]::Exists($canaryPath)) {
            throw 'Runtime TEMP write canary cleanup failed.'
        }
    } catch {
        if ($createdRunTemp) {
            $cleanupSucceeded = Clear-PrivateRuntimeTemp $AuthorizedRoot $TempPath
            if (-not $cleanupSucceeded) {
                Write-Warning 'Runtime TEMP cleanup failed during initialization.'
            }
        }
        throw
    }
}

function Clear-PrivateRuntimeTemp([string] $AuthorizedRoot, [string] $TempPath) {
    try {
        Assert-PathConfined $TempPath $AuthorizedRoot
        if (-not [System.IO.Directory]::Exists($TempPath)) { return $true }
        Assert-DirectoryNotReparsePoint $AuthorizedRoot
        Assert-DirectoryNotReparsePoint (Split-Path $TempPath -Parent)
        Assert-DirectoryNotReparsePoint $TempPath
        foreach ($item in Get-ChildItem -LiteralPath $TempPath -Force -Recurse -ErrorAction Stop) {
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Refusing to clean a runtime TEMP containing a reparse point: $($item.FullName)"
            }
        }
        [System.IO.Directory]::Delete($TempPath, $true)
        return -not [System.IO.Directory]::Exists($TempPath)
    } catch {
        return $false
    }
}

Initialize-PrivateRuntimeTemp $agentStatePath $runtimeTempBase $runtimeTempPath

try {
# Add-Type is retained to request exact NTFS rights without performing a
# destructive mutation; standard File APIs cannot request WRITE_DAC or DELETE_CHILD.
if (-not ('Automaton.RuntimeAcl.AgentNativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Automaton.RuntimeAcl {
    public static class AgentNativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
        );
    }
}
'@
}

$FILE_LIST_DIRECTORY = [uint32]1
$FILE_WRITE_DATA = [uint32]2
$FILE_ADD_FILE = [uint32]2
$FILE_DELETE_CHILD = [uint32]64
$DELETE = [uint32]65536
$WRITE_DAC = [uint32]262144
$OPEN_EXISTING = [uint32]3
$FILE_ATTRIBUTE_NORMAL = [uint32]128
$FILE_FLAG_BACKUP_SEMANTICS = [uint32]33554432
$SHARE_ALL = [uint32]7

$workspace = 'C:\automaton'
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$configPath = Join-Path $labRoot 'control\trading.yaml'
$controlPath = Join-Path $labRoot 'control'
$demoAuthorizationPath = Join-Path $controlPath 'demo-authorization'
$demoAuthorizationFile = Join-Path $demoAuthorizationPath 'authorization.json'
$killSwitchPath = Join-Path $controlPath 'STOP_TRADING'
$automatonKeyPath = Join-Path $labRoot 'ipc\automaton.key'
$observationKeyPath = Join-Path $labRoot 'ipc\observation.key'
$researchKeyPath = Join-Path $labRoot 'ipc\research.key'
$operationalPath = Join-Path $labRoot 'operational'
$researchPath = Join-Path $labRoot 'research'
$auditSqlitePath = Join-Path $labRoot 'audit\sqlite'
$auditJournalPath = Join-Path $labRoot 'audit\journal\audit.jsonl'
$securityLogPath = Join-Path $labRoot 'logs\security\security.log'
$reportPath = Join-Path $agentStatePath "acl-runtime-results\agent-$normalizedRunId.json"
$tests = [ordered]@{}
$unexpectedProtectedAccess = $false
$criticalUnexpectedAllow = $false

function Add-TestResult(
    [string] $Name,
    [string] $Expected,
    [string] $Observed,
    [string] $Evidence
) {
    $script:tests[$Name] = [ordered]@{
        expected = $Expected
        observed = $Observed
        passed = ($Expected -eq $Observed)
        evidence = $Evidence
    }
    if ($Expected -ne $Observed -and $Observed -eq 'ALLOW') {
        $script:unexpectedProtectedAccess = $true
    }
}

Add-TestResult 'RUNTIME_TEMP_PRIVATE' 'ALLOW' 'ALLOW' 'TEMP_AND_TMP_CONFINED_WRITABLE_NON_REPARSE'

function Invoke-NativeAccessProbe(
    [string] $Path,
    [uint32] $DesiredAccess,
    [bool] $Directory
) {
    $flags = if ($Directory) { $FILE_FLAG_BACKUP_SEMANTICS } else { $FILE_ATTRIBUTE_NORMAL }
    $handle = [Automaton.RuntimeAcl.AgentNativeMethods]::CreateFile(
        $Path, $DesiredAccess, $SHARE_ALL, [IntPtr]::Zero,
        $OPEN_EXISTING, $flags, [IntPtr]::Zero
    )
    if ($handle.IsInvalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $handle.Dispose()
        return [pscustomobject]@{ Allowed = $false; ErrorCode = $errorCode }
    }
    $handle.Dispose()
    return [pscustomobject]@{ Allowed = $true; ErrorCode = 0 }
}

function Add-DeniedRightTest(
    [string] $Name,
    [string] $Path,
    [uint32] $Right,
    [bool] $Directory,
    [bool] $Critical = $false
) {
    $probe = Invoke-NativeAccessProbe $Path $Right $Directory
    if ($probe.Allowed) {
        Add-TestResult $Name 'DENY' 'ALLOW' 'PROTECTED_RIGHT_GRANTED_NO_MUTATION_PERFORMED'
        if ($Critical) { $script:criticalUnexpectedAllow = $true }
    } elseif ($probe.ErrorCode -eq 5) {
        Add-TestResult $Name 'DENY' 'DENY' 'WIN32_ACCESS_DENIED'
    } else {
        Add-TestResult $Name 'DENY' 'ERROR' "WIN32_ERROR_$($probe.ErrorCode)"
    }
}

function Add-AllowedFileReadTest(
    [string] $Name,
    [string] $Path,
    [bool] $RequireNonEmpty
) {
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        )
        $valid = (-not $RequireNonEmpty) -or ($stream.Length -gt 0)
        if ($valid) {
            Add-TestResult $Name 'ALLOW' 'ALLOW' 'READ_SUCCEEDED_CONTENT_NOT_REPORTED'
        } else {
            Add-TestResult $Name 'ALLOW' 'ERROR' 'READ_SUCCEEDED_BUT_FILE_EMPTY'
        }
    } catch [System.UnauthorizedAccessException] {
        Add-TestResult $Name 'ALLOW' 'DENY' 'WIN32_ACCESS_DENIED'
    } catch {
        Add-TestResult $Name 'ALLOW' 'ERROR' $_.Exception.GetType().Name
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Add-DeniedCanaryCreateTest([string] $Name, [string] $Path) {
    $stream = $null
    $created = $false
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $created = $true
        Add-TestResult $Name 'DENY' 'ALLOW' 'TEST_CANARY_CREATION_UNEXPECTEDLY_ALLOWED'
    } catch [System.UnauthorizedAccessException] {
        Add-TestResult $Name 'DENY' 'DENY' 'WIN32_ACCESS_DENIED'
    } catch {
        Add-TestResult $Name 'DENY' 'ERROR' $_.Exception.GetType().Name
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($created) {
            try { [System.IO.File]::Delete($Path) } catch { $script:unexpectedProtectedAccess = $true }
        }
    }
}

function Add-AgentStateCanaryTest([string] $Path) {
    $canaryPath = Join-Path $Path "acl-runtime-$normalizedRunId.canary"
    $expected = "AUTOMATON_AGENT_RUNTIME_ACL_CANARY:$normalizedRunId"
    try {
        [System.IO.Directory]::CreateDirectory($Path) | Out-Null
        [System.IO.File]::WriteAllText(
            $canaryPath, $expected, [System.Text.UTF8Encoding]::new($false)
        )
        $actual = [System.IO.File]::ReadAllText($canaryPath, [System.Text.Encoding]::UTF8)
        if ($actual -ne $expected) { throw 'CANARY_ROUNDTRIP_MISMATCH' }
        [System.IO.File]::Delete($canaryPath)
        if ([System.IO.File]::Exists($canaryPath)) { throw 'CANARY_DELETE_FAILED' }
        Add-TestResult 'STATE_CREATE_WRITE_READ_DELETE' 'ALLOW' 'ALLOW' 'CANARY_ROUNDTRIP_AND_CLEANUP_SUCCEEDED'
    } catch [System.UnauthorizedAccessException] {
        Add-TestResult 'STATE_CREATE_WRITE_READ_DELETE' 'ALLOW' 'DENY' 'WIN32_ACCESS_DENIED'
    } catch {
        Add-TestResult 'STATE_CREATE_WRITE_READ_DELETE' 'ALLOW' 'ERROR' $_.Exception.GetType().Name
        try { if ([System.IO.File]::Exists($canaryPath)) { [System.IO.File]::Delete($canaryPath) } } catch {}
    }
}

function Write-ExclusiveJsonReport([string] $Path, [object] $Value) {
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    $json = $Value | ConvertTo-Json -Depth 8
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($json); $writer.Flush() } finally { $writer.Dispose() }
    } finally {
        $stream.Dispose()
    }
}

Add-TestResult 'IDENTITY' $expectedSid $effectiveSid 'EFFECTIVE_WINDOWS_TOKEN_SID'
Add-AllowedFileReadTest 'WORKSPACE_READ' (Join-Path $workspace 'package.json') $true
Add-DeniedCanaryCreateTest 'WORKSPACE_CREATE' (Join-Path $workspace ".acl-runtime-$normalizedRunId.canary")
Add-DeniedRightTest 'WORKSPACE_MODIFY_CODE' (Join-Path $workspace 'package.json') $FILE_WRITE_DATA $false
Add-DeniedRightTest 'WORKSPACE_DELETE_CODE' (Join-Path $workspace 'package.json') $DELETE $false

Add-DeniedRightTest 'CONFIG_READ' $configPath $FILE_LIST_DIRECTORY $false
Add-DeniedRightTest 'AUTOMATON_KEY_READ' $automatonKeyPath $FILE_LIST_DIRECTORY $false $true
Add-DeniedRightTest 'AUTOMATON_KEY_WRITE' $automatonKeyPath $FILE_WRITE_DATA $false
Add-DeniedRightTest 'AUTOMATON_KEY_TRUNCATE' $automatonKeyPath $FILE_WRITE_DATA $false
Add-DeniedRightTest 'AUTOMATON_KEY_DELETE' $automatonKeyPath $DELETE $false
Add-DeniedRightTest 'AUTOMATON_KEY_CHANGE_ACL' $automatonKeyPath $WRITE_DAC $false

Add-AllowedFileReadTest 'OBSERVATION_KEY_READ' $observationKeyPath $true
Add-DeniedRightTest 'OBSERVATION_KEY_WRITE' $observationKeyPath $FILE_WRITE_DATA $false
Add-DeniedRightTest 'OBSERVATION_KEY_TRUNCATE' $observationKeyPath $FILE_WRITE_DATA $false
Add-DeniedRightTest 'OBSERVATION_KEY_DELETE' $observationKeyPath $DELETE $false
Add-DeniedRightTest 'OBSERVATION_KEY_CHANGE_ACL' $observationKeyPath $WRITE_DAC $false
Add-AllowedFileReadTest 'RESEARCH_KEY_READ' $researchKeyPath $true
Add-DeniedRightTest 'RESEARCH_KEY_WRITE' $researchKeyPath $FILE_WRITE_DATA $false
Add-DeniedRightTest 'RESEARCH_KEY_TRUNCATE' $researchKeyPath $FILE_WRITE_DATA $false
Add-DeniedRightTest 'RESEARCH_KEY_DELETE' $researchKeyPath $DELETE $false
Add-DeniedRightTest 'RESEARCH_KEY_CHANGE_ACL' $researchKeyPath $WRITE_DAC $false

Add-DeniedRightTest 'OPERATIONAL_ACCESS' $operationalPath $FILE_LIST_DIRECTORY $true
Add-DeniedRightTest 'RESEARCH_ACCESS' $researchPath $FILE_LIST_DIRECTORY $true
Add-DeniedRightTest 'AUDIT_SQLITE_ACCESS' $auditSqlitePath $FILE_LIST_DIRECTORY $true
Add-DeniedRightTest 'AUDIT_JOURNAL_ACCESS' $auditJournalPath $FILE_LIST_DIRECTORY $false
Add-DeniedRightTest 'SECURITY_LOG_ACCESS' $securityLogPath $FILE_LIST_DIRECTORY $false
Add-AgentStateCanaryTest $agentStatePath

Add-DeniedRightTest 'DEMO_AUTH_CREATE' $demoAuthorizationPath $FILE_ADD_FILE $true
if ([System.IO.File]::Exists($demoAuthorizationFile)) {
    Add-DeniedRightTest 'DEMO_AUTH_MODIFY' $demoAuthorizationFile $FILE_WRITE_DATA $false
    Add-DeniedRightTest 'DEMO_AUTH_DELETE' $demoAuthorizationFile $DELETE $false
} else {
    Add-DeniedRightTest 'DEMO_AUTH_MODIFY' $demoAuthorizationPath $FILE_ADD_FILE $true
    Add-DeniedRightTest 'DEMO_AUTH_DELETE' $demoAuthorizationPath $FILE_DELETE_CHILD $true
}

Add-DeniedRightTest 'KILL_SWITCH_CREATE' $controlPath $FILE_ADD_FILE $true
if ([System.IO.File]::Exists($killSwitchPath)) {
    Add-DeniedRightTest 'KILL_SWITCH_MODIFY' $killSwitchPath $FILE_WRITE_DATA $false
    Add-DeniedRightTest 'KILL_SWITCH_DELETE' $killSwitchPath $DELETE $false
} else {
    Add-DeniedRightTest 'KILL_SWITCH_MODIFY' $controlPath $FILE_ADD_FILE $true
    Add-DeniedRightTest 'KILL_SWITCH_DELETE' $controlPath $FILE_DELETE_CHILD $true
}

$runtimeTempCleanupAttempted = $true
$runtimeTempCleanupSucceeded = Clear-PrivateRuntimeTemp $agentStatePath $runtimeTempPath
Add-TestResult `
    'RUNTIME_TEMP_CLEANUP' 'ALLOW' `
    $(if ($runtimeTempCleanupSucceeded) { 'ALLOW' } else { 'ERROR' }) `
    $(if ($runtimeTempCleanupSucceeded) { 'RUN_SCOPED_TEMP_REMOVED' } else { 'RUN_SCOPED_TEMP_CLEANUP_FAILED' })

$allPassed = -not $unexpectedProtectedAccess
foreach ($test in $tests.Values) {
    if (-not $test.passed) { $allPassed = $false }
}
$report = [ordered]@{
    schema_version = 1
    role = 'AutomatonAgent'
    run_id = $normalizedRunId
    effective_sid = $effectiveSid
    status = if ($criticalUnexpectedAllow) {
        'CRITICAL_UNEXPECTED_ALLOW'
    } elseif ($allPassed) { 'PASS' } else { 'FAIL' }
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    tests = $tests
    boundaries = [ordered]@{
        mt5_accessed = $false
        automaton_started = $false
        gateway_started = $false
        order_check_executed = $false
        order_send_executed = $false
        demo_execution_enabled = $false
        trading_mode_changed = $false
    }
}
Write-ExclusiveJsonReport $reportPath $report
Write-Output "AGENT_RUNTIME_ACL_STATUS=$($report.status)"
Write-Output "AGENT_RUNTIME_ACL_REPORT=$reportPath"
if (-not $allPassed) { $scriptExitCode = 1 }
} finally {
    if (-not $runtimeTempCleanupAttempted) {
        $runtimeTempCleanupSucceeded = Clear-PrivateRuntimeTemp $agentStatePath $runtimeTempPath
        if (-not $runtimeTempCleanupSucceeded) {
            Write-Warning 'Runtime TEMP cleanup failed after an early harness error.'
        }
    }
}
if ($scriptExitCode -ne 0) { exit $scriptExitCode }
