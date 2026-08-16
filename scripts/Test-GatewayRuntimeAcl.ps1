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

$expectedSid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$effectiveIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$effectiveSid = $effectiveIdentity.User.Value
if ($effectiveSid -ne $expectedSid) {
    throw "Wrong runtime identity. Expected SID $expectedSid; received $effectiveSid. No tests were run."
}
$principal = [System.Security.Principal.WindowsPrincipal]::new($effectiveIdentity)
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'AutomatonGateway runtime ACL tests refuse an administrative token.'
}

$normalizedRunId = $RunId.ToLowerInvariant()
$isolatedModeCount = @(@($PythonBaseOnly, $PythonStagingOnly, $PythonFinalOnly) | Where-Object { [bool]$_ }).Count
if ($isolatedModeCount -gt 1) {
    throw 'Select only one isolated runtime ACL mode.'
}
if ($PythonBaseOnly) {
    . (Join-Path $PSScriptRoot 'Test-PythonBaseOnlyRuntimeAcl.ps1')
    $baseOnlyResult = Invoke-TradingLabPythonBaseOnlyRuntimeAcl `
        -Role 'AutomatonGateway' -RunId $normalizedRunId `
        -EffectiveSid $effectiveSid -AdministrativeToken $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    if ($baseOnlyResult.exit_code -ne 0) { exit $baseOnlyResult.exit_code }
    return
}
if ($PythonStagingOnly) {
    . (Join-Path $PSScriptRoot 'Test-PythonStagingOnlyRuntimeAcl.ps1')
    $stagingOnlyResult = Invoke-TradingLabPythonStagingOnlyRuntimeAcl `
        -Role 'AutomatonGateway' -RunId $normalizedRunId `
        -EffectiveSid $effectiveSid -AdministrativeToken $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    if ($stagingOnlyResult.exit_code -ne 0) { exit $stagingOnlyResult.exit_code }
    return
}
if ($PythonFinalOnly) {
    . (Join-Path $PSScriptRoot 'Test-PythonFinalOnlyRuntimeAcl.ps1')
    $finalOnlyResult = Invoke-TradingLabPythonFinalOnlyRuntimeAcl `
        -Role 'AutomatonGateway' -RunId $normalizedRunId `
        -EffectiveSid $effectiveSid -AdministrativeToken $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    if ($finalOnlyResult.exit_code -ne 0) { exit $finalOnlyResult.exit_code }
    return
}
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$operationalPath = Join-Path $labRoot 'operational'
$runtimeTempBase = Join-Path $operationalPath 'runtime-tmp'
$runtimeTempPath = Join-Path $runtimeTempBase $normalizedRunId
$runtimeTempCleanupAttempted = $false
$runtimeTempCleanupSucceeded = $false
$scriptExitCode = 0
$nativeProbeLoadError = $null

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

Initialize-PrivateRuntimeTemp $operationalPath $runtimeTempBase $runtimeTempPath

try {
# Add-Type is retained to request exact NTFS rights without performing a
# destructive mutation; standard File APIs cannot request WRITE_DAC or DELETE_CHILD.
if (-not ('Automaton.RuntimeAcl.GatewayNativeMethods' -as [type])) {
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Automaton.RuntimeAcl {
    public static class GatewayNativeMethods {
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
} catch {
    $nativeProbeLoadError = $_
}
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
$pythonExe = Join-Path $workspace '.venv\Scripts\python.exe'
$machinePythonBase = 'C:\Program Files\AutomatonPython\3.14.5'
$machinePythonExe = Join-Path $machinePythonBase 'python.exe'
$machinePythonDll = Join-Path $machinePythonBase 'python314.dll'
$machinePythonStdlibFile = Join-Path $machinePythonBase 'Lib\os.py'
$venvScriptsPath = Join-Path $workspace '.venv\Scripts'
$venvPythonExe = Join-Path $venvScriptsPath 'python.exe'
$venvSitePackagesPath = Join-Path $workspace '.venv\Lib\site-packages'
$controlPath = Join-Path $labRoot 'control'
$configPath = Join-Path $controlPath 'trading.yaml'
$demoAuthorizationPath = Join-Path $controlPath 'demo-authorization'
$demoAuthorizationFile = Join-Path $demoAuthorizationPath 'authorization.json'
$killSwitchPath = Join-Path $controlPath 'STOP_TRADING'
$ipcPath = Join-Path $labRoot 'ipc'
$ipcKeyPath = Join-Path $ipcPath 'automaton.key'
$researchPath = Join-Path $labRoot 'research'
$auditSqlitePath = Join-Path $labRoot 'audit\sqlite'
$auditJournalPath = Join-Path $labRoot 'audit\journal\audit.jsonl'
$securityLogPath = Join-Path $labRoot 'logs\security\security.log'
$agentStatePath = 'C:\Users\AutomatonAgent\.automaton'
$reportPath = Join-Path $operationalPath "acl-runtime-results\gateway-$normalizedRunId.json"
$tests = [ordered]@{}
$journalEvidence = $null
$securityLogEvidence = $null
$criticalFail = $false
$runtimeError = $null
$failureClassification = $null
$diagnostic = $null
$currentStage = 'HARNESS_SETUP'
$currentTestName = 'RUNTIME_TEMP_PRIVATE'
$lastCompletedTest = $null
$infrastructureFailure = $false

function ConvertTo-SafeDiagnosticText([object] $Value, [int] $MaximumLength = 2048) {
    if ($null -eq $Value) { return $null }
    $safe = [string]$Value
    $safe = [regex]::Replace(
        $safe,
        '(?i)(password|passwd|credential|api[_-]?key|private[_-]?key|secret|token)\s*[:=]\s*[^\s,;]+',
        '$1=[REDACTED]'
    )
    $safe = [regex]::Replace($safe, '(?i)C:\\Users\\[^\\\r\n]+', 'C:\Users\[REDACTED_PROFILE]')
    $safe = [regex]::Replace($safe, '(?<![0-9A-Fa-f-])[A-Za-z0-9_-]{48,}(?![0-9A-Fa-f-])', '[REDACTED_TOKEN]')
    if ($safe.Length -gt $MaximumLength) {
        $safe = $safe.Substring(0, $MaximumLength) + '...[TRUNCATED]'
    }
    return $safe
}

function Set-TestContext([string] $Stage, [string] $TestName) {
    $script:currentStage = $Stage
    $script:currentTestName = $TestName
}

function New-FailureDiagnostic([System.Management.Automation.ErrorRecord] $ErrorRecord) {
    $invocationInfo = $ErrorRecord.InvocationInfo
    $scriptLine = if ($null -ne $invocationInfo) { [int]$invocationInfo.ScriptLineNumber } else { 0 }
    $invocation = if ($null -ne $invocationInfo -and $invocationInfo.Line) {
        $invocationInfo.Line.Trim()
    } elseif ($null -ne $invocationInfo -and $invocationInfo.InvocationName) {
        $invocationInfo.InvocationName
    } else {
        $null
    }
    return [ordered]@{
        stage = $script:currentStage
        test_name = $script:currentTestName
        exception_type = $ErrorRecord.Exception.GetType().FullName
        exception_message = ConvertTo-SafeDiagnosticText $ErrorRecord.Exception.Message
        FullyQualifiedErrorId = ConvertTo-SafeDiagnosticText $ErrorRecord.FullyQualifiedErrorId
        script_line = $scriptLine
        invocation = ConvertTo-SafeDiagnosticText $invocation
        stack_trace = ConvertTo-SafeDiagnosticText $ErrorRecord.ScriptStackTrace 4096
        last_completed_test = $script:lastCompletedTest
    }
}

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
    $script:lastCompletedTest = $Name
    if ($Observed -eq 'ERROR') {
        $script:infrastructureFailure = $true
    }
}

Add-TestResult 'RUNTIME_TEMP_PRIVATE' 'ALLOW' 'ALLOW' 'TEMP_AND_TMP_CONFINED_WRITABLE_NON_REPARSE'

function Invoke-NativeAccessProbe(
    [string] $Path,
    [uint32] $DesiredAccess,
    [bool] $Directory
) {
    $flags = if ($Directory) { $FILE_FLAG_BACKUP_SEMANTICS } else { $FILE_ATTRIBUTE_NORMAL }
    $handle = [Automaton.RuntimeAcl.GatewayNativeMethods]::CreateFile(
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
    [bool] $Critical
) {
    Set-TestContext 'NTFS_ACCESS_PROBE' $Name
    $probe = Invoke-NativeAccessProbe $Path $Right $Directory
    if ($probe.Allowed) {
        Add-TestResult $Name 'DENY' 'ALLOW' 'PROTECTED_RIGHT_GRANTED_NO_MUTATION_PERFORMED'
        if ($Critical) {
            $script:criticalFail = $true
            throw "CRITICAL_FAIL:$Name"
        }
    } elseif ($probe.ErrorCode -eq 5) {
        Add-TestResult $Name 'DENY' 'DENY' 'WIN32_ACCESS_DENIED'
    } else {
        Add-TestResult $Name 'DENY' 'ERROR' "WIN32_ERROR_$($probe.ErrorCode)"
        throw "UNEXPECTED_WIN32_ACCESS_PROBE_ERROR:${Name}:$($probe.ErrorCode)"
    }
}

function Add-AllowedFileReadTest(
    [string] $Name,
    [string] $Path,
    [bool] $RequireNonEmpty
) {
    Set-TestContext 'FILE_READ_PROBE' $Name
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
        throw
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Add-DeniedCanaryCreateTest([string] $Name, [string] $Path) {
    Set-TestContext 'CANARY_CREATE_PROBE' $Name
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
        throw
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($created) {
            try { [System.IO.File]::Delete($Path) } catch {}
        }
    }
}

function Add-MutableDirectoryCanaryTest([string] $Name, [string] $Directory) {
    Set-TestContext 'MUTABLE_DIRECTORY_CANARY' $Name
    $first = Join-Path $Directory "acl-runtime-$normalizedRunId.canary"
    $renamed = Join-Path $Directory "acl-runtime-$normalizedRunId.renamed.canary"
    $expected = "AUTOMATON_GATEWAY_RUNTIME_ACL_CANARY:$normalizedRunId"
    try {
        [System.IO.File]::WriteAllText($first, $expected, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::AppendAllText($first, ':APPEND', [System.Text.UTF8Encoding]::new($false))
        $actual = [System.IO.File]::ReadAllText($first, [System.Text.Encoding]::UTF8)
        if ($actual -ne ($expected + ':APPEND')) { throw 'CANARY_ROUNDTRIP_MISMATCH' }
        [System.IO.File]::Move($first, $renamed)
        [System.IO.File]::Delete($renamed)
        if ([System.IO.File]::Exists($renamed)) { throw 'CANARY_DELETE_FAILED' }
        Add-TestResult $Name 'ALLOW' 'ALLOW' 'CREATE_WRITE_READ_RENAME_DELETE_SUCCEEDED'
    } catch [System.UnauthorizedAccessException] {
        Add-TestResult $Name 'ALLOW' 'DENY' 'WIN32_ACCESS_DENIED'
    } catch {
        Add-TestResult $Name 'ALLOW' 'ERROR' $_.Exception.GetType().Name
        throw
    } finally {
        foreach ($candidate in @($first, $renamed)) {
            try { if ([System.IO.File]::Exists($candidate)) { [System.IO.File]::Delete($candidate) } } catch {}
        }
    }
}

function Invoke-LocalPythonJson(
    [string] $Source,
    [hashtable] $Environment,
    [string] $ProbeName
) {
    $safeProbeName = $ProbeName -replace '[^A-Za-z0-9_-]', '_'
    $sourcePath = Join-Path $runtimeTempPath "$safeProbeName-$([guid]::NewGuid().ToString('N')).py"
    $process = $null
    try {
        $sourceStream = [System.IO.File]::Open(
            $sourcePath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read
        )
        try {
            $writer = [System.IO.StreamWriter]::new(
                $sourceStream, [System.Text.UTF8Encoding]::new($false)
            )
            try { $writer.Write($Source); $writer.Flush() } finally { $writer.Dispose() }
        } finally {
            $sourceStream.Dispose()
        }

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $pythonExe
        $startInfo.Arguments = '-I "' + $sourcePath + '"'
        $startInfo.WorkingDirectory = $runtimeTempPath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.EnvironmentVariables['TEMP'] = $runtimeTempPath
        $startInfo.EnvironmentVariables['TMP'] = $runtimeTempPath
        $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
        foreach ($key in $Environment.Keys) {
            $startInfo.EnvironmentVariables[[string]$key] = [string]$Environment[$key]
        }
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'PYTHON_PROCESS_START_RETURNED_FALSE'
        }
        $standardOutput = $process.StandardOutput.ReadToEnd()
        $standardError = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $safeStandardError = ConvertTo-SafeDiagnosticText $standardError
        if ($exitCode -ne 0) {
            return [pscustomobject]@{
                Success = $false
                Evidence = "PYTHON_EXIT_$exitCode"
                ExitCode = $exitCode
                StandardError = $safeStandardError
                Value = $null
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($standardError)) {
            return [pscustomobject]@{
                Success = $false
                Evidence = 'PYTHON_UNEXPECTED_STDERR'
                ExitCode = 0
                StandardError = $safeStandardError
                Value = $null
            }
        }
        try {
            $value = $standardOutput.Trim() | ConvertFrom-Json
            return [pscustomobject]@{
                Success = $true
                Evidence = 'LOCAL_PYTHON_COMPLETED'
                ExitCode = 0
                StandardError = $safeStandardError
                Value = $value
            }
        } catch {
            return [pscustomobject]@{
                Success = $false
                Evidence = 'PYTHON_OUTPUT_INVALID'
                ExitCode = 0
                StandardError = $safeStandardError
                Value = $null
            }
        }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
        try { if ([System.IO.File]::Exists($sourcePath)) { [System.IO.File]::Delete($sourcePath) } } catch {}
    }
}

function Assert-PythonInvocation(
    [string] $TestName,
    [object] $Invocation,
    [string] $SuccessEvidence
) {
    Set-TestContext $script:currentStage $TestName
    if ($Invocation.Success) {
        Add-TestResult $TestName 'ALLOW' 'ALLOW' $SuccessEvidence
        return $Invocation.Value
    }
    $failureEvidence = $Invocation.Evidence
    if ($Invocation.StandardError) {
        $failureEvidence += ':' + $Invocation.StandardError
    }
    Add-TestResult $TestName 'ALLOW' 'ERROR' (ConvertTo-SafeDiagnosticText $failureEvidence)
    throw "${TestName}_FAILED:$failureEvidence"
}

function Add-PythonRuntimePreflightTests {
    Set-TestContext 'PYTHON_PREFLIGHT' 'PYTHON_EXECUTABLE_PATH'
    $expectedPythonPath = 'C:\automaton\.venv\Scripts\python.exe'
    $actualPythonPath = [System.IO.Path]::GetFullPath($pythonExe)
    if ($actualPythonPath -ne $expectedPythonPath -or -not [System.IO.File]::Exists($actualPythonPath)) {
        Add-TestResult 'PYTHON_EXECUTABLE_PATH' 'ALLOW' 'ERROR' 'PINNED_LOCAL_PYTHON_NOT_FOUND_OR_CHANGED'
        throw 'PYTHON_EXECUTABLE_PATH_INVALID'
    }
    $pythonItem = Get-Item -LiteralPath $actualPythonPath -Force
    if ($pythonItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Add-TestResult 'PYTHON_EXECUTABLE_PATH' 'ALLOW' 'ERROR' 'PYTHON_EXECUTABLE_IS_REPARSE_POINT'
        throw 'PYTHON_EXECUTABLE_REPARSE_POINT'
    }
    Add-TestResult 'PYTHON_EXECUTABLE_PATH' 'ALLOW' 'ALLOW' $expectedPythonPath

    Set-TestContext 'PYTHON_PREFLIGHT' 'PYTHON_EXECUTE'
    $executeSource = @'
import json
import sys
print(json.dumps({"base_prefix": sys.base_prefix, "executable": sys.executable, "ok": True}, sort_keys=True, separators=(",", ":")))
'@
    $execute = Invoke-LocalPythonJson $executeSource @{} 'python-execute'
    $executeValue = Assert-PythonInvocation 'PYTHON_EXECUTE' $execute 'PINNED_INTERPRETER_EXECUTED'
    Set-TestContext 'PYTHON_PREFLIGHT' 'PYTHON_EXECUTABLE_IDENTITY'
    if (-not $executeValue.ok -or $executeValue.executable -ne $expectedPythonPath) {
        Add-TestResult 'PYTHON_EXECUTABLE_IDENTITY' $expectedPythonPath 'MISMATCH' 'PYTHON_REPORTED_UNEXPECTED_EXECUTABLE'
        $script:failureClassification = 'TEST_FAILED_EXPECTATION'
        throw 'PYTHON_EXECUTABLE_IDENTITY_MISMATCH'
    }
    Add-TestResult 'PYTHON_EXECUTABLE_IDENTITY' $expectedPythonPath $expectedPythonPath 'PYTHON_REPORTED_PINNED_EXECUTABLE'
    Add-TestResult 'PYTHON_GATEWAY_EXECUTE' 'PASS' 'PASS' 'PROCESS_EXECUTED_UNDER_GATEWAY_TOKEN'

    Set-TestContext 'PYTHON_PREFLIGHT' 'PYTHON_BASE_MACHINE_WIDE'
    $reportedBase = [System.IO.Path]::GetFullPath([string]$executeValue.base_prefix).TrimEnd('\')
    $profilesRoot = [System.IO.Path]::GetFullPath((Join-Path $env:SystemDrive 'Users')).TrimEnd('\')
    if ($reportedBase -ne $machinePythonBase) {
        Add-TestResult 'PYTHON_BASE_MACHINE_WIDE' 'PASS' 'MISMATCH' 'BASE_PREFIX_NOT_MANAGED_MACHINE_WIDE'
        $script:failureClassification = 'TEST_FAILED_EXPECTATION'
        throw 'PYTHON_BASE_MACHINE_WIDE_MISMATCH'
    }
    Add-TestResult 'PYTHON_BASE_MACHINE_WIDE' 'PASS' 'PASS' 'EXACT_MANAGED_PROGRAM_FILES_BASE'
    Set-TestContext 'PYTHON_PREFLIGHT' 'PYTHON_BASE_OUTSIDE_USER_PROFILE'
    if (
        $reportedBase.Equals($profilesRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $reportedBase.StartsWith($profilesRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        Add-TestResult 'PYTHON_BASE_OUTSIDE_USER_PROFILE' 'PASS' 'MISMATCH' 'BASE_PREFIX_UNDER_USER_PROFILE'
        $script:failureClassification = 'TEST_FAILED_EXPECTATION'
        throw 'PYTHON_BASE_UNDER_USER_PROFILE'
    }
    Add-TestResult 'PYTHON_BASE_OUTSIDE_USER_PROFILE' 'PASS' 'PASS' 'BASE_PREFIX_OUTSIDE_USER_PROFILES'
    Add-TestResult 'VENV_BASE_OUTSIDE_USER_PROFILE' 'PASS' 'PASS' 'VENV_REDIRECTS_OUTSIDE_USER_PROFILES'

    foreach ($requiredPath in @(
        [pscustomobject]@{ Name = 'PYTHON_BASE_EXE_PRESENT'; Path = $machinePythonExe },
        [pscustomobject]@{ Name = 'PYTHON_BASE_DLL_PRESENT'; Path = $machinePythonDll },
        [pscustomobject]@{ Name = 'PYTHON_BASE_STDLIB_PRESENT'; Path = $machinePythonStdlibFile },
        [pscustomobject]@{ Name = 'PYTHON_VENV_EXE_PRESENT'; Path = $venvPythonExe },
        [pscustomobject]@{ Name = 'PYTHON_VENV_SCRIPTS_PRESENT'; Path = $venvScriptsPath },
        [pscustomobject]@{ Name = 'PYTHON_VENV_SITE_PACKAGES_PRESENT'; Path = $venvSitePackagesPath }
    )) {
        Set-TestContext 'PYTHON_RUNTIME_BOUNDARY' $requiredPath.Name
        if (-not (Test-Path -LiteralPath $requiredPath.Path)) {
            throw "PYTHON_RUNTIME_PROTECTED_PATH_MISSING:$($requiredPath.Path)"
        }
    }
    Add-DeniedRightTest 'PYTHON_BASE_ROOT_MODIFY' $machinePythonBase $FILE_ADD_FILE $true $true
    Add-DeniedRightTest 'PYTHON_BASE_EXE_MODIFY' $machinePythonExe $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'PYTHON_BASE_DLL_MODIFY' $machinePythonDll $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'PYTHON_BASE_STDLIB_MODIFY' $machinePythonStdlibFile $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'PYTHON_BASE_EXE_DELETE' $machinePythonExe $DELETE $false $true
    Add-DeniedRightTest 'PYTHON_VENV_EXE_MODIFY' $venvPythonExe $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'PYTHON_VENV_SCRIPTS_MODIFY' $venvScriptsPath $FILE_ADD_FILE $true $true
    Add-DeniedRightTest 'PYTHON_VENV_SITE_PACKAGES_MODIFY' $venvSitePackagesPath $FILE_ADD_FILE $true $true
    Add-DeniedRightTest 'PYTHON_VENV_EXE_DELETE' $venvPythonExe $DELETE $false $true
    Add-TestResult 'PYTHON_GATEWAY_MODIFY_DENY' 'DENY' 'DENY' 'BASE_VENV_CODE_WRITE_AND_DELETE_DENIED'

    Set-TestContext 'PYTHON_PREFLIGHT' 'PYTHON_SQLITE_IMPORT'
    $importSource = @'
import json
import sqlite3
print(json.dumps({"imported": True, "sqlite_version": sqlite3.sqlite_version}, sort_keys=True, separators=(",", ":")))
'@
    $import = Invoke-LocalPythonJson $importSource @{} 'python-sqlite-import'
    $importValue = Assert-PythonInvocation 'PYTHON_SQLITE_IMPORT' $import 'SQLITE3_IMPORT_SUCCEEDED'
    if (-not $importValue.imported) { throw 'PYTHON_SQLITE_IMPORT_RESULT_INVALID' }

    Set-TestContext 'PYTHON_PREFLIGHT' 'PYTHON_RUNTIME_TEMP'
    $tempSource = @'
import json
import os
import pathlib
import tempfile

expected = pathlib.Path(os.environ["AUTOMATON_RUNTIME_TEST_TEMP"]).resolve()
observed = pathlib.Path(tempfile.gettempdir()).resolve()
canary = expected / "python-temp-write.canary"
if canary.exists():
    raise RuntimeError("TEMP_CANARY_ALREADY_EXISTS")
try:
    with canary.open("x", encoding="utf-8") as handle:
        handle.write("runtime-temp")
    read_back = canary.read_text(encoding="utf-8") == "runtime-temp"
finally:
    if canary.exists():
        canary.unlink()
print(json.dumps({"confined": observed == expected, "read_back": read_back, "cleanup": not canary.exists()}, sort_keys=True, separators=(",", ":")))
'@
    $temp = Invoke-LocalPythonJson $tempSource @{
        AUTOMATON_RUNTIME_TEST_TEMP = $runtimeTempPath
    } 'python-runtime-temp'
    $tempValue = Assert-PythonInvocation 'PYTHON_RUNTIME_TEMP' $temp 'PYTHON_PRIVATE_TEMP_PROBE_COMPLETED'
    Set-TestContext 'PYTHON_PREFLIGHT' 'PYTHON_RUNTIME_TEMP_CONFINED'
    if ($tempValue.confined -and $tempValue.read_back -and $tempValue.cleanup) {
        Add-TestResult 'PYTHON_RUNTIME_TEMP_CONFINED' 'ALLOW' 'ALLOW' 'TEMP_CREATE_READ_DELETE_SUCCEEDED'
    } else {
        Add-TestResult 'PYTHON_RUNTIME_TEMP_CONFINED' 'ALLOW' 'ERROR' 'PYTHON_TEMP_NOT_CONFINED_OR_CLEAN'
        throw 'PYTHON_RUNTIME_TEMP_NOT_CONFINED_OR_CLEAN'
    }
}

function Add-SqliteWalCanaryTest {
    Set-TestContext 'SQLITE_WAL_CANARY' 'SQLITE_DB_CREATE'
    $databasePath = Join-Path $auditSqlitePath "runtime-acl-$normalizedRunId.db"
    $source = @'
import json
import os
import pathlib
import sqlite3

path = pathlib.Path(os.environ["AUTOMATON_RUNTIME_TEST_DB"])
artifacts = [path, pathlib.Path(str(path) + "-wal"), pathlib.Path(str(path) + "-shm")]
result = {
    "db_create": False,
    "wal_mode": False,
    "wal_create": False,
    "shm_create": False,
    "commit": False,
    "read_back": False,
    "checkpoint": False,
    "close": False,
    "cleanup": False,
    "failure_stage": None,
    "error_type": None,
    "error_message": None,
    "errno": None,
    "winerror": None,
}
connection = None
try:
    if any(item.exists() for item in artifacts):
        raise RuntimeError("CANARY_ALREADY_EXISTS")
    result["failure_stage"] = "DB_CREATE"
    connection = sqlite3.connect(path)
    result["db_create"] = path.is_file()
    result["failure_stage"] = "WAL_MODE"
    mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    result["wal_mode"] = mode.lower() == "wal"
    connection.execute("CREATE TABLE canary (value TEXT NOT NULL)")
    connection.execute("INSERT INTO canary(value) VALUES (?)", ("runtime-acl",))
    result["failure_stage"] = "COMMIT"
    connection.commit()
    result["commit"] = True
    result["wal_create"] = pathlib.Path(str(path) + "-wal").is_file()
    result["shm_create"] = pathlib.Path(str(path) + "-shm").is_file()
    result["failure_stage"] = "READ_BACK"
    result["read_back"] = connection.execute("SELECT value FROM canary").fetchone()[0] == "runtime-acl"
    result["failure_stage"] = "CHECKPOINT"
    checkpoint = connection.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
    result["checkpoint"] = checkpoint is not None and len(checkpoint) == 3
    result["failure_stage"] = None
except Exception as exc:
    result["error_type"] = type(exc).__name__
    result["error_message"] = str(exc)[:512]
    result["errno"] = getattr(exc, "errno", None)
    result["winerror"] = getattr(exc, "winerror", None)
finally:
    if connection is not None:
        try:
            connection.close()
            result["close"] = True
        except Exception as exc:
            if result["error_type"] is None:
                result["failure_stage"] = "CLOSE"
                result["error_type"] = type(exc).__name__
                result["error_message"] = str(exc)[:512]
                result["errno"] = getattr(exc, "errno", None)
                result["winerror"] = getattr(exc, "winerror", None)
    cleanup = True
    for item in artifacts:
        try:
            if item.exists():
                item.unlink()
        except OSError as exc:
            cleanup = False
            if result["error_type"] is None:
                result["failure_stage"] = "CLEANUP"
                result["error_type"] = type(exc).__name__
                result["error_message"] = str(exc)[:512]
                result["errno"] = getattr(exc, "errno", None)
                result["winerror"] = getattr(exc, "winerror", None)
    result["cleanup"] = cleanup and not any(item.exists() for item in artifacts)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'@
    $invocation = Invoke-LocalPythonJson $source @{
        AUTOMATON_RUNTIME_TEST_DB = $databasePath
    } 'sqlite-wal-canary'
    $value = Assert-PythonInvocation 'SQLITE_PROCESS' $invocation 'SQLITE_CANARY_PROCESS_COMPLETED'
    $checks = [ordered]@{
        SQLITE_DB_CREATE = [bool]$value.db_create
        SQLITE_WAL_MODE = [bool]$value.wal_mode
        SQLITE_WAL_CREATE = [bool]$value.wal_create
        SQLITE_SHM_CREATE = [bool]$value.shm_create
        SQLITE_COMMIT = [bool]$value.commit
        SQLITE_READ_BACK = [bool]$value.read_back
        SQLITE_CHECKPOINT = [bool]$value.checkpoint
        SQLITE_CLOSE = [bool]$value.close
        SQLITE_CLEANUP = [bool]$value.cleanup
    }
    foreach ($entry in $checks.GetEnumerator()) {
        Set-TestContext 'SQLITE_WAL_CANARY' $entry.Key
        Add-TestResult `
            $entry.Key 'ALLOW' `
            $(if ($entry.Value) { 'ALLOW' } else { 'MISSING' }) `
            $(if ($entry.Value) { 'SQLITE_STAGE_SUCCEEDED' } else { 'SQLITE_STAGE_INCOMPLETE' })
    }
    if ($value.error_type) {
        $failureTestName = switch ([string]$value.failure_stage) {
            'DB_CREATE' { 'SQLITE_DB_CREATE' }
            'WAL_MODE' { 'SQLITE_WAL_MODE' }
            'COMMIT' { 'SQLITE_COMMIT' }
            'READ_BACK' { 'SQLITE_READ_BACK' }
            'CHECKPOINT' { 'SQLITE_CHECKPOINT' }
            'CLOSE' { 'SQLITE_CLOSE' }
            'CLEANUP' { 'SQLITE_CLEANUP' }
            default { 'SQLITE_WAL' }
        }
        Set-TestContext 'SQLITE_WAL_CANARY' $failureTestName
        $sqliteError = "stage=$($value.failure_stage);type=$($value.error_type);message=$($value.error_message);errno=$($value.errno);winerror=$($value.winerror)"
        Add-TestResult 'SQLITE_WAL' 'ALLOW' 'ERROR' (ConvertTo-SafeDiagnosticText $sqliteError)
        throw "SQLITE_CANARY_INFRASTRUCTURE_ERROR:$sqliteError"
    }
    $sqlitePassed = -not @($checks.Values | Where-Object { -not $_ }).Count
    Add-TestResult `
        'SQLITE_WAL' 'ALLOW' `
        $(if ($sqlitePassed) { 'ALLOW' } else { 'MISSING' }) `
        $(if ($sqlitePassed) { 'DB_WAL_SHM_COMMIT_CHECKPOINT_CLOSE_CLEANUP_SUCCEEDED' } else { 'SQLITE_EXPECTATION_INCOMPLETE' })
}

function Add-AuditJournalAppendTest {
    Set-TestContext 'AUDIT_JOURNAL' 'JOURNAL_APPEND'
    $source = @'
import datetime
import hashlib
import json
import os
import pathlib

path = pathlib.Path(os.environ["AUTOMATON_RUNTIME_TEST_JOURNAL"])
run_id = os.environ["AUTOMATON_RUNTIME_TEST_RUN_ID"]
before = path.read_bytes()
previous_hash = "0" * 64
records = 0
for line_number, raw_line in enumerate(before.splitlines(), start=1):
    if not raw_line.strip():
        continue
    record = json.loads(raw_line.decode("utf-8"))
    claimed_hash = record.pop("record_hash")
    if record.get("previous_hash") != previous_hash:
        raise RuntimeError("PREEXISTING_CHAIN_LINK_INVALID")
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    calculated = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if calculated != claimed_hash:
        raise RuntimeError("PREEXISTING_CHAIN_HASH_INVALID")
    previous_hash = claimed_hash
    records += 1
unsigned = {
    "schema_version": 1,
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "event": "runtime_acl_canary",
    "payload": {"purpose": "runtime_acl_append_probe", "run_id": run_id},
    "previous_hash": previous_hash,
}
canonical_unsigned = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
record = dict(unsigned)
record["record_hash"] = hashlib.sha256(canonical_unsigned.encode("utf-8")).hexdigest()
line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
with path.open("a", encoding="utf-8", newline="\n") as handle:
    handle.write(line)
    handle.flush()
    os.fsync(handle.fileno())
after = path.read_bytes()
encoded_line = line.encode("utf-8")
if after[:len(before)] != before or after[len(before):] != encoded_line:
    raise RuntimeError("IMMEDIATE_PREFIX_OR_SUFFIX_MISMATCH")
result = {
    "before_size": len(before),
    "before_sha256": hashlib.sha256(before).hexdigest(),
    "append_size": len(encoded_line),
    "append_sha256": hashlib.sha256(encoded_line).hexdigest(),
    "records_before": records,
    "record_hash": record["record_hash"],
}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'@
    $invocation = Invoke-LocalPythonJson $source @{
        AUTOMATON_RUNTIME_TEST_JOURNAL = $auditJournalPath
        AUTOMATON_RUNTIME_TEST_RUN_ID = $normalizedRunId
    } 'audit-journal-append'
    $script:journalEvidence = Assert-PythonInvocation `
        'JOURNAL_APPEND' $invocation 'CPYTHON_APPEND_FLUSH_FSYNC_SUCCEEDED'
}

function Add-SecurityLogAppendTest {
    Set-TestContext 'SECURITY_LOG' 'SECURITY_APPEND'
    $source = @'
import hashlib
import json
import logging
import os
import pathlib
import sys

path = pathlib.Path(os.environ["AUTOMATON_RUNTIME_TEST_SECURITY_LOG"])
run_id = os.environ["AUTOMATON_RUNTIME_TEST_RUN_ID"]
workspace = pathlib.Path(os.environ["AUTOMATON_RUNTIME_TEST_WORKSPACE"])
if str(workspace) != r"C:\automaton" or workspace.is_symlink():
    raise RuntimeError("WORKSPACE_IMPORT_ROOT_INVALID")
sys.path.insert(0, str(workspace))
from trading_lab.windows_append_log import WindowsAppendOnlyFileHandler

before = path.read_bytes()
logger = logging.getLogger("automaton.runtime_acl_canary." + run_id)
logger.setLevel(logging.WARNING)
logger.propagate = False
handler = WindowsAppendOnlyFileHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
try:
    logger.addHandler(handler)
    logger.warning("SECURITY_APPEND_PROBE %s", run_id)
finally:
    logger.removeHandler(handler)
    handler.close()
after = path.read_bytes()
expected = ("SECURITY_APPEND_PROBE " + run_id + "\n").encode("utf-8")
if after[:len(before)] != before or after[len(before):] != expected:
    raise RuntimeError("IMMEDIATE_PREFIX_OR_SUFFIX_MISMATCH")
appended = after[len(before):]
result = {
    "before_size": len(before),
    "before_sha256": hashlib.sha256(before).hexdigest(),
    "append_size": len(appended),
    "append_sha256": hashlib.sha256(appended).hexdigest(),
}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'@
    $invocation = Invoke-LocalPythonJson $source @{
        AUTOMATON_RUNTIME_TEST_SECURITY_LOG = $securityLogPath
        AUTOMATON_RUNTIME_TEST_RUN_ID = $normalizedRunId
        AUTOMATON_RUNTIME_TEST_WORKSPACE = $workspace
    } 'security-log-append'
    $script:securityLogEvidence = Assert-PythonInvocation `
        'SECURITY_APPEND' $invocation 'WIN32_APPEND_ONLY_HANDLER_SUCCEEDED'
}

function Write-ExclusiveJsonReport([string] $Path, [object] $Value) {
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    $json = $Value | ConvertTo-Json -Depth 10
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

if ($null -ne $nativeProbeLoadError) {
    Set-TestContext 'NATIVE_ACCESS_PROBE_COMPILER' 'ADD_TYPE_NATIVE_METHODS'
    $diagnostic = New-FailureDiagnostic $nativeProbeLoadError
    $runtimeError = $diagnostic.exception_type
    $failureClassification = 'TEST_INFRASTRUCTURE_ERROR'
    $infrastructureFailure = $true
} else {
try {
    Set-TestContext 'IDENTITY' 'IDENTITY'
    Add-TestResult 'IDENTITY' $expectedSid $effectiveSid 'EFFECTIVE_WINDOWS_TOKEN_SID'
    Add-AllowedFileReadTest 'WORKSPACE_READ' (Join-Path $workspace 'package.json') $true
    Add-DeniedCanaryCreateTest 'WORKSPACE_CREATE' (Join-Path $workspace ".acl-runtime-$normalizedRunId.canary")
    Add-DeniedRightTest 'WORKSPACE_MODIFY_CODE' (Join-Path $workspace 'package.json') $FILE_WRITE_DATA $false $false
    Add-DeniedRightTest 'WORKSPACE_DELETE_CODE' (Join-Path $workspace 'package.json') $DELETE $false $false

    Add-AllowedFileReadTest 'CONFIG_READ' $configPath $true
    Set-TestContext 'CONFIG_VALIDATION' 'CONFIG_OBSERVE_ONLY'
    $configText = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
    if ($configText -notmatch '(?m)^\s*trading_mode\s*:\s*OBSERVE_ONLY\s*$') {
        Add-TestResult 'CONFIG_OBSERVE_ONLY' 'OBSERVE_ONLY' 'MISMATCH' 'CONFIG_MODE_NOT_OBSERVE_ONLY'
    } else {
        Add-TestResult 'CONFIG_OBSERVE_ONLY' 'OBSERVE_ONLY' 'OBSERVE_ONLY' 'MODE_READ_WITHOUT_REPORTING_CONFIG'
    }
    Add-DeniedRightTest 'CONFIG_WRITE' $configPath $FILE_WRITE_DATA $false $false
    Add-DeniedRightTest 'CONFIG_TRUNCATE' $configPath $FILE_WRITE_DATA $false $false
    Add-DeniedRightTest 'CONFIG_DELETE' $configPath $DELETE $false $false
    Add-DeniedRightTest 'CONFIG_REPLACE' $controlPath $FILE_ADD_FILE $true $false

    Add-AllowedFileReadTest 'IPC_READ' $ipcKeyPath $true
    Add-DeniedRightTest 'IPC_WRITE' $ipcKeyPath $FILE_WRITE_DATA $false $false
    Add-DeniedRightTest 'IPC_TRUNCATE' $ipcKeyPath $FILE_WRITE_DATA $false $false
    Add-DeniedRightTest 'IPC_DELETE' $ipcKeyPath $DELETE $false $false
    Add-DeniedRightTest 'IPC_REPLACE' $ipcPath $FILE_ADD_FILE $true $false
    Add-DeniedRightTest 'IPC_CHANGE_ACL' $ipcKeyPath $WRITE_DAC $false $false

    Add-MutableDirectoryCanaryTest 'OPERATIONAL_MODIFY' $operationalPath
    Add-MutableDirectoryCanaryTest 'RESEARCH_MODIFY' $researchPath
    Add-PythonRuntimePreflightTests
    Add-SqliteWalCanaryTest

    Add-AuditJournalAppendTest
    Add-AllowedFileReadTest 'JOURNAL_READ' $auditJournalPath $true
    Add-DeniedRightTest 'JOURNAL_OVERWRITE' $auditJournalPath $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'JOURNAL_TRUNCATE' $auditJournalPath $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'JOURNAL_CREATE_OVERWRITE' $auditJournalPath $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'JOURNAL_DELETE' $auditJournalPath $DELETE $false $true
    Add-DeniedRightTest 'JOURNAL_RENAME' $auditJournalPath $DELETE $false $true
    Add-DeniedRightTest 'JOURNAL_REPLACE' (Split-Path $auditJournalPath -Parent) $FILE_ADD_FILE $true $true
    Add-DeniedRightTest 'JOURNAL_CHANGE_ACL' $auditJournalPath $WRITE_DAC $false $true

    Add-SecurityLogAppendTest
    Add-DeniedRightTest 'SECURITY_OVERWRITE' $securityLogPath $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'SECURITY_TRUNCATE' $securityLogPath $FILE_WRITE_DATA $false $true
    Add-DeniedRightTest 'SECURITY_DELETE' $securityLogPath $DELETE $false $true
    Add-DeniedRightTest 'SECURITY_RENAME' $securityLogPath $DELETE $false $true
    Add-DeniedRightTest 'SECURITY_CREATE_OTHER' (Split-Path $securityLogPath -Parent) $FILE_ADD_FILE $true $true
    Add-DeniedRightTest 'SECURITY_REPLACE' (Split-Path $securityLogPath -Parent) $FILE_ADD_FILE $true $true

    Add-DeniedRightTest 'AGENT_STATE_READ' $agentStatePath $FILE_LIST_DIRECTORY $true $false
    Add-DeniedRightTest 'AGENT_STATE_WRITE' $agentStatePath $FILE_ADD_FILE $true $false

    Set-TestContext 'CONTROL_ISOLATION' 'DEMO_AUTH_READ'
    $demoRead = Invoke-NativeAccessProbe $demoAuthorizationPath $FILE_LIST_DIRECTORY $true
    if ($demoRead.Allowed) {
        Add-TestResult 'DEMO_AUTH_READ' 'ALLOW' 'ALLOW' 'DIRECTORY_READ_RIGHT_GRANTED'
    } elseif ($demoRead.ErrorCode -eq 5) {
        Add-TestResult 'DEMO_AUTH_READ' 'ALLOW' 'DENY' 'WIN32_ACCESS_DENIED'
    } else {
        Add-TestResult 'DEMO_AUTH_READ' 'ALLOW' 'ERROR' "WIN32_ERROR_$($demoRead.ErrorCode)"
        throw "UNEXPECTED_DEMO_AUTH_READ_ERROR:$($demoRead.ErrorCode)"
    }
    Add-DeniedRightTest 'DEMO_AUTH_CREATE' $demoAuthorizationPath $FILE_ADD_FILE $true $false
    if ([System.IO.File]::Exists($demoAuthorizationFile)) {
        Add-DeniedRightTest 'DEMO_AUTH_MODIFY' $demoAuthorizationFile $FILE_WRITE_DATA $false $false
        Add-DeniedRightTest 'DEMO_AUTH_DELETE' $demoAuthorizationFile $DELETE $false $false
    } else {
        Add-DeniedRightTest 'DEMO_AUTH_MODIFY' $demoAuthorizationPath $FILE_ADD_FILE $true $false
        Add-DeniedRightTest 'DEMO_AUTH_DELETE' $demoAuthorizationPath $FILE_DELETE_CHILD $true $false
    }

    Set-TestContext 'CONTROL_ISOLATION' 'KILL_SWITCH_DETECT'
    $killSwitchPresent = [System.IO.File]::Exists($killSwitchPath)
    Add-TestResult 'KILL_SWITCH_DETECT' 'ALLOW' 'ALLOW' $(if ($killSwitchPresent) { 'PRESENT' } else { 'ABSENT' })
    Add-DeniedRightTest 'KILL_SWITCH_CREATE' $controlPath $FILE_ADD_FILE $true $false
    if ($killSwitchPresent) {
        Add-DeniedRightTest 'KILL_SWITCH_MODIFY' $killSwitchPath $FILE_WRITE_DATA $false $false
        Add-DeniedRightTest 'KILL_SWITCH_DELETE' $killSwitchPath $DELETE $false $false
    } else {
        Add-DeniedRightTest 'KILL_SWITCH_MODIFY' $controlPath $FILE_ADD_FILE $true $false
        Add-DeniedRightTest 'KILL_SWITCH_DELETE' $controlPath $FILE_DELETE_CHILD $true $false
    }
} catch {
    $diagnostic = New-FailureDiagnostic $_
    $runtimeError = $diagnostic.exception_type
    $failureClassification = if ($criticalFail) {
        'CRITICAL_UNEXPECTED_ALLOW'
    } elseif ($failureClassification -eq 'TEST_FAILED_EXPECTATION') {
        'TEST_FAILED_EXPECTATION'
    } else {
        'TEST_INFRASTRUCTURE_ERROR'
    }
}
}

Set-TestContext 'HARNESS_CLEANUP' 'RUNTIME_TEMP_CLEANUP'
$runtimeTempCleanupAttempted = $true
$runtimeTempCleanupSucceeded = Clear-PrivateRuntimeTemp $operationalPath $runtimeTempPath
Add-TestResult `
    'RUNTIME_TEMP_CLEANUP' 'ALLOW' `
    $(if ($runtimeTempCleanupSucceeded) { 'ALLOW' } else { 'ERROR' }) `
    $(if ($runtimeTempCleanupSucceeded) { 'RUN_SCOPED_TEMP_REMOVED' } else { 'RUN_SCOPED_TEMP_CLEANUP_FAILED' })

$allPassed = -not $criticalFail -and $null -eq $runtimeError
foreach ($test in $tests.Values) {
    if (-not $test.passed) { $allPassed = $false }
}
$status = if ($criticalFail) {
    'CRITICAL_UNEXPECTED_ALLOW'
} elseif ($failureClassification -eq 'TEST_FAILED_EXPECTATION') {
    'TEST_FAILED_EXPECTATION'
} elseif ($null -ne $diagnostic -or $infrastructureFailure) {
    'TEST_INFRASTRUCTURE_ERROR'
} elseif (-not $allPassed) {
    'TEST_FAILED_EXPECTATION'
} else {
    'PASS'
}
if ($status -ne 'PASS') { $failureClassification = $status }
$report = [ordered]@{
    schema_version = 1
    role = 'AutomatonGateway'
    run_id = $normalizedRunId
    effective_sid = $effectiveSid
    status = $status
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    runtime_error = $runtimeError
    failure_classification = $failureClassification
    diagnostic = $diagnostic
    tests = $tests
    journal_evidence = $journalEvidence
    security_log_evidence = $securityLogEvidence
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
Write-Output "GATEWAY_RUNTIME_ACL_STATUS=$status"
Write-Output "GATEWAY_RUNTIME_ACL_REPORT=$reportPath"
if (-not $allPassed) { $scriptExitCode = 1 }
} finally {
    if (-not $runtimeTempCleanupAttempted) {
        $runtimeTempCleanupSucceeded = Clear-PrivateRuntimeTemp $operationalPath $runtimeTempPath
        if (-not $runtimeTempCleanupSucceeded) {
            Write-Warning 'Runtime TEMP cleanup failed after an early harness error.'
        }
    }
}
if ($scriptExitCode -ne 0) { exit $scriptExitCode }
