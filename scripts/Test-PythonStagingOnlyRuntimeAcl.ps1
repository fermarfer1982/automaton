Set-StrictMode -Version 2.0

$script:PythonStagingOnlyRoot = 'C:\automaton\.venv.new'
$script:PythonStagingOnlyExecutable = 'C:\automaton\.venv.new\Scripts\python.exe'
$script:PythonStagingOnlySitePackages = 'C:\automaton\.venv.new\Lib\site-packages'
$script:PythonStagingOnlyFastApiFile = 'C:\automaton\.venv.new\Lib\site-packages\fastapi\__init__.py'
$script:PythonStagingOnlyConfig = 'C:\automaton\.venv.new\pyvenv.cfg'
$script:PythonStagingOnlyBase = 'C:\Program Files\AutomatonPython\3.14.5'
$script:PythonStagingOnlyGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$script:PythonStagingOnlyAgentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'

function Get-PythonStagingOnlyCanonicalPath([string] $Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-PythonStagingOnlyExactPath([string] $Path, [string] $ExpectedPath) {
    try {
        return (Get-PythonStagingOnlyCanonicalPath $Path).Equals(
            (Get-PythonStagingOnlyCanonicalPath $ExpectedPath),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    } catch { return $false }
}

function Test-PythonStagingOnlyIdentity([string] $EffectiveSid, [string] $ExpectedSid) {
    return -not [string]::IsNullOrWhiteSpace($EffectiveSid) -and $EffectiveSid -eq $ExpectedSid
}

function Test-PythonStagingOnlyReparseAttributes([System.IO.FileAttributes] $Attributes) {
    return -not [bool]($Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

function Test-PythonStagingOnlyTargetPresent([string] $Path) {
    return [System.IO.Directory]::Exists($Path)
}

function Test-PythonStagingOnlyImportGate([object] $Metadata, [string] $Property) {
    try { return $null -ne $Metadata -and [bool]$Metadata.imports.$Property } catch { return $false }
}

function Test-PythonStagingOnlyMt5Metadata([object] $Metadata) {
    try {
        return $null -ne $Metadata -and $Metadata.mt5_metadata -eq '5.0.6090'
    } catch { return $false }
}

function Test-PythonStagingOnlyMt5NotImported([object] $Metadata) {
    try { return $null -ne $Metadata -and -not [bool]$Metadata.mt5_imported } catch { return $false }
}

function Test-PythonStagingOnlyConfigRecord([string[]] $Lines) {
    try {
        $values = @{}
        foreach ($line in $Lines) {
            $parts = $line -split '=', 2
            if ($parts.Count -eq 2) { $values[$parts[0].Trim().ToLowerInvariant()] = $parts[1].Trim() }
        }
        return (Test-PythonStagingOnlyExactPath $values.home $script:PythonStagingOnlyBase) -and
            (Test-PythonStagingOnlyExactPath $values.executable (Join-Path $script:PythonStagingOnlyBase 'python.exe')) -and
            $values['include-system-site-packages'] -eq 'false' -and $values.version -eq '3.14.5'
    } catch { return $false }
}

function Test-PythonStagingOnlyPathConfined([string] $Path, [string] $Root) {
    try {
        $candidate = Get-PythonStagingOnlyCanonicalPath $Path
        $canonicalRoot = Get-PythonStagingOnlyCanonicalPath $Root
        return $candidate.Equals($canonicalRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            $candidate.StartsWith($canonicalRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Resolve-PythonStagingOnlyAccessExpectation(
    [bool] $Allowed,
    [int] $ErrorCode,
    [bool] $ExpectedAllow
) {
    if ($ExpectedAllow) {
        if ($Allowed) {
            return [pscustomobject]@{ passed = $true; observed = 'ALLOW'; critical = $false; infrastructure_error = $false }
        }
        if ($ErrorCode -eq 5) {
            return [pscustomobject]@{ passed = $false; observed = 'DENY'; critical = $false; infrastructure_error = $false }
        }
        return [pscustomobject]@{ passed = $false; observed = 'ERROR'; critical = $false; infrastructure_error = $true }
    }
    if ($Allowed) {
        return [pscustomobject]@{ passed = $false; observed = 'ALLOW'; critical = $true; infrastructure_error = $false }
    }
    if ($ErrorCode -eq 5) {
        return [pscustomobject]@{ passed = $true; observed = 'DENY'; critical = $false; infrastructure_error = $false }
    }
    return [pscustomobject]@{ passed = $false; observed = 'ERROR'; critical = $false; infrastructure_error = $true }
}

function Resolve-AgentPythonStagingExecutionExpectation(
    [bool] $ProcessStarted,
    [Nullable[int]] $ExitCode,
    [bool] $SuccessMarkerObserved,
    [int] $StartErrorCode
) {
    if ($SuccessMarkerObserved -or ($ProcessStarted -and $null -ne $ExitCode -and $ExitCode -eq 0)) {
        return [pscustomobject]@{
            passed = $false
            observed = 'ALLOW'
            critical = $true
            infrastructure_error = $false
            evidence = 'FUNCTIONAL_STAGING_PYTHON_EXECUTION_ALLOWED'
        }
    }
    if (-not $ProcessStarted) {
        if ($StartErrorCode -eq 5) {
            return [pscustomobject]@{
                passed = $true
                observed = 'DENY'
                critical = $false
                infrastructure_error = $false
                evidence = 'PROCESS_START_ACCESS_DENIED'
            }
        }
        return [pscustomobject]@{
            passed = $false
            observed = 'ERROR'
            critical = $false
            infrastructure_error = $true
            evidence = "PROCESS_START_ERROR_$StartErrorCode"
        }
    }
    return [pscustomobject]@{
        passed = $true
        observed = 'DENY'
        critical = $false
        infrastructure_error = $false
        evidence = "PROCESS_NONZERO_WITHOUT_SUCCESS_MARKER_$ExitCode"
    }
}

function Assert-PythonStagingOnlyConfinedPath([string] $Path) {
    if (-not (Test-PythonStagingOnlyPathConfined $Path $script:PythonStagingOnlyRoot)) {
        throw "PYTHON_STAGING_PATH_OUTSIDE_EXACT_TARGET:$Path"
    }
}

function Assert-PythonStagingOnlyNoReparsePoint([string] $Path) {
    Assert-PythonStagingOnlyConfinedPath $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not (Test-PythonStagingOnlyReparseAttributes $item.Attributes)) {
        throw "PYTHON_STAGING_REPARSE_POINT_FAIL_CLOSED:$($item.FullName)"
    }
}

function Assert-PythonStagingOnlyReportPath([string] $Path, [string] $AuthorizedRoot) {
    $candidate = Get-PythonStagingOnlyCanonicalPath $Path
    $root = Get-PythonStagingOnlyCanonicalPath $AuthorizedRoot
    if (-not $candidate.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "PYTHON_STAGING_REPORT_PATH_OUTSIDE_AUTHORIZED_ROOT:$candidate"
    }
}

function Assert-PythonStagingOnlyReportDirectory([string] $Path, [string] $AuthorizedRoot) {
    Assert-PythonStagingOnlyReportPath $Path $AuthorizedRoot
    if (-not [System.IO.Directory]::Exists($Path)) {
        [void][System.IO.Directory]::CreateDirectory($Path)
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or -not (Test-PythonStagingOnlyReparseAttributes $item.Attributes)) {
        throw "PYTHON_STAGING_REPORT_DIRECTORY_INVALID:$Path"
    }
}

function Initialize-PythonStagingOnlyPrivateTemp(
    [string] $ReportRoot,
    [string] $AuthorizedRoot,
    [string] $RunId
) {
    Assert-PythonStagingOnlyReportDirectory $ReportRoot $AuthorizedRoot
    $tempPath = Join-Path $ReportRoot ".python-staging-only-tmp-$RunId"
    Assert-PythonStagingOnlyReportPath $tempPath $ReportRoot
    if ([System.IO.Directory]::Exists($tempPath) -or [System.IO.File]::Exists($tempPath)) {
        throw 'PYTHON_STAGING_ONLY_TEMP_COLLISION: inspect it and use a new RunId.'
    }
    [void][System.IO.Directory]::CreateDirectory($tempPath)
    $item = Get-Item -LiteralPath $tempPath -Force -ErrorAction Stop
    if (-not (Test-PythonStagingOnlyReparseAttributes $item.Attributes)) {
        throw 'PYTHON_STAGING_ONLY_TEMP_REPARSE_POINT'
    }
    $env:TEMP = Get-PythonStagingOnlyCanonicalPath $tempPath
    $env:TMP = $env:TEMP
    $canary = Join-Path $tempPath '.writable.canary'
    $stream = [System.IO.File]::Open(
        $canary, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None
    )
    try { $stream.WriteByte(1); $stream.Flush() } finally { $stream.Dispose() }
    [System.IO.File]::Delete($canary)
    return $tempPath
}

function Clear-PythonStagingOnlyPrivateTemp([string] $TempPath, [string] $ReportRoot) {
    try {
        Assert-PythonStagingOnlyReportPath $TempPath $ReportRoot
        if (-not [System.IO.Directory]::Exists($TempPath)) { return $true }
        $rootItem = Get-Item -LiteralPath $TempPath -Force -ErrorAction Stop
        if (-not (Test-PythonStagingOnlyReparseAttributes $rootItem.Attributes)) { return $false }
        foreach ($item in Get-ChildItem -LiteralPath $TempPath -Force -Recurse -ErrorAction Stop) {
            if (-not (Test-PythonStagingOnlyReparseAttributes $item.Attributes)) { return $false }
        }
        [System.IO.Directory]::Delete($TempPath, $true)
        return -not [System.IO.Directory]::Exists($TempPath)
    } catch { return $false }
}

function Add-PythonStagingOnlyResult(
    [object] $Context,
    [string] $Name,
    [string] $Expected,
    [string] $Observed,
    [string] $Evidence,
    [bool] $Critical = $false,
    [bool] $InfrastructureError = $false
) {
    $passed = $Expected -eq $Observed
    $Context.tests[$Name] = [ordered]@{
        expected = $Expected
        observed = $Observed
        passed = $passed
        evidence = $Evidence
    }
    if (-not $passed -and $Critical) { $Context.critical_unexpected_allow = $true }
    if (-not $passed -and $InfrastructureError) { $Context.infrastructure_error = $true }
}

function Initialize-PythonStagingOnlyNativeProbe {
    if ('Automaton.RuntimeAcl.PythonStagingOnlyNativeMethods' -as [type]) { return }
    # Native access checks request individual NTFS rights without mutating real files.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Automaton.RuntimeAcl {
    public static class PythonStagingOnlyNativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateDirectory(
            string path,
            IntPtr securityAttributes
        );

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

function Invoke-PythonStagingOnlyNativeAccessProbe(
    [string] $Path,
    [uint32] $DesiredAccess,
    [bool] $Directory
) {
    Assert-PythonStagingOnlyConfinedPath $Path
    $flags = if ($Directory) { [uint32]33554432 } else { [uint32]128 }
    $handle = [Automaton.RuntimeAcl.PythonStagingOnlyNativeMethods]::CreateFile(
        $Path, $DesiredAccess, [uint32]7, [IntPtr]::Zero,
        [uint32]3, $flags, [IntPtr]::Zero
    )
    if ($handle.IsInvalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $handle.Dispose()
        return [pscustomobject]@{ Allowed = $false; ErrorCode = $errorCode }
    }
    $handle.Dispose()
    return [pscustomobject]@{ Allowed = $true; ErrorCode = 0 }
}

function Add-PythonStagingOnlyNativeDeniedTest(
    [object] $Context,
    [string] $Name,
    [string] $Path,
    [uint32] $DesiredAccess,
    [bool] $Directory
) {
    $probe = Invoke-PythonStagingOnlyNativeAccessProbe $Path $DesiredAccess $Directory
    $resolved = Resolve-PythonStagingOnlyAccessExpectation $probe.Allowed $probe.ErrorCode $false
    Add-PythonStagingOnlyResult $Context $Name 'DENY' $resolved.observed `
        $(if ($resolved.observed -eq 'DENY') { 'WIN32_ACCESS_DENIED' } elseif ($resolved.observed -eq 'ALLOW') { 'FORBIDDEN_RIGHT_GRANTED_WITHOUT_MUTATION' } else { "WIN32_ERROR_$($probe.ErrorCode)" }) `
        $resolved.critical $resolved.infrastructure_error
}

function Add-PythonStagingOnlyFileReadTest(
    [object] $Context,
    [string] $Name,
    [string] $Path
) {
    Assert-PythonStagingOnlyConfinedPath $Path
    $stream = $null
    $allowed = $false
    $errorCode = 0
    try {
        $stream = [System.IO.File]::Open(
            $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        )
        $allowed = $stream.Length -gt 0
    } catch [System.UnauthorizedAccessException] {
        $errorCode = 5
    } catch {
        $errorCode = -1
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $resolved = Resolve-PythonStagingOnlyAccessExpectation $allowed $errorCode $true
    Add-PythonStagingOnlyResult $Context $Name 'ALLOW' $resolved.observed `
        $(if ($resolved.observed -eq 'ALLOW') { 'READ_SUCCEEDED_CONTENT_NOT_REPORTED' } elseif ($resolved.observed -eq 'DENY') { 'WIN32_ACCESS_DENIED' } else { 'FILE_READ_INFRASTRUCTURE_ERROR' }) `
        $resolved.critical $resolved.infrastructure_error
}

function Add-PythonStagingOnlyDeniedFileCreateTest(
    [object] $Context,
    [string] $Name,
    [string] $Path
) {
    Assert-PythonStagingOnlyConfinedPath $Path
    $stream = $null
    $created = $false
    $observed = 'ERROR'
    try {
        $stream = [System.IO.File]::Open(
            $Path, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None
        )
        $created = $true
        $Context.filesystem_staging_modified = $true
        $observed = 'ALLOW'
    } catch [System.UnauthorizedAccessException] {
        $observed = 'DENY'
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($created) {
            try { [System.IO.File]::Delete($Path) } catch { $Context.infrastructure_error = $true }
        }
    }
    Add-PythonStagingOnlyResult $Context $Name 'DENY' $observed `
        $(if ($observed -eq 'DENY') { 'CREATE_NEW_ACCESS_DENIED' } elseif ($observed -eq 'ALLOW') { 'CRITICAL_CANARY_CREATION_ALLOWED_AND_CLEANUP_ATTEMPTED' } else { 'CREATE_NEW_INFRASTRUCTURE_ERROR' }) `
        ($observed -eq 'ALLOW') ($observed -eq 'ERROR')
}

function Add-PythonStagingOnlyDeniedDirectoryCreateTest(
    [object] $Context,
    [string] $Name,
    [string] $Path
) {
    Assert-PythonStagingOnlyConfinedPath $Path
    $created = $false
    $observed = 'ERROR'
    $errorCode = -1
    try {
        $created = [Automaton.RuntimeAcl.PythonStagingOnlyNativeMethods]::CreateDirectory(
            $Path, [IntPtr]::Zero
        )
        if ($created) {
            $errorCode = 0
            $Context.filesystem_staging_modified = $true
            $observed = 'ALLOW'
        } else {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($errorCode -eq 5) { $observed = 'DENY' }
        }
    } finally {
        if ($created) {
            try { [System.IO.Directory]::Delete($Path, $false) } catch { $Context.infrastructure_error = $true }
        }
    }
    Add-PythonStagingOnlyResult $Context $Name 'DENY' $observed `
        $(if ($observed -eq 'DENY') { 'CREATE_DIRECTORY_ACCESS_DENIED' } elseif ($observed -eq 'ALLOW') { 'CRITICAL_CANARY_DIRECTORY_ALLOWED_AND_CLEANUP_ATTEMPTED' } else { "CREATE_DIRECTORY_WIN32_ERROR_$errorCode" }) `
        ($observed -eq 'ALLOW') ($observed -eq 'ERROR')
}

function Get-PythonStagingOnlyTreeSnapshot {
    $root = Get-PythonStagingOnlyCanonicalPath $script:PythonStagingOnlyRoot
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($root)
    $count = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        Assert-PythonStagingOnlyNoReparsePoint $current
        $count++
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (-not $item.PSIsContainer) { continue }
        foreach ($childPath in [System.IO.Directory]::EnumerateFileSystemEntries($current)) {
            Assert-PythonStagingOnlyConfinedPath $childPath
            $child = Get-Item -LiteralPath $childPath -Force -ErrorAction Stop
            if (-not (Test-PythonStagingOnlyReparseAttributes $child.Attributes)) {
                throw "PYTHON_STAGING_REPARSE_POINT_FAIL_CLOSED:$($child.FullName)"
            }
            if ($child.PSIsContainer) { $pending.Enqueue($child.FullName) } else { $count++ }
        }
    }
    return $count
}

function Invoke-PythonStagingOnlyProcess(
    [string] $Source,
    [string] $SuccessMarker,
    [bool] $ParseJson
) {
    $process = $null
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $script:PythonStagingOnlyExecutable
        $startInfo.Arguments = '-B -I -'
        $startInfo.WorkingDirectory = $env:TEMP
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.EnvironmentVariables['TEMP'] = $env:TEMP
        $startInfo.EnvironmentVariables['TMP'] = $env:TMP
        $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
        $startInfo.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            return [pscustomobject]@{
                ProcessStarted = $false; ExitCode = $null; StartErrorCode = -1
                SuccessMarkerObserved = $false; Value = $null; StandardErrorPresent = $false
            }
        }
        $process.StandardInput.Write($Source)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $markerObserved = -not [string]::IsNullOrEmpty($SuccessMarker) -and
            $stdout.IndexOf($SuccessMarker, [System.StringComparison]::Ordinal) -ge 0
        $value = $null
        if ($ParseJson -and $process.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($stdout)) {
            try { $value = $stdout.Trim() | ConvertFrom-Json } catch { $value = $null }
        }
        return [pscustomobject]@{
            ProcessStarted = $true
            ExitCode = [int]$process.ExitCode
            StartErrorCode = 0
            SuccessMarkerObserved = [bool]$markerObserved
            Value = $value
            StandardErrorPresent = -not [string]::IsNullOrWhiteSpace($stderr)
        }
    } catch [System.ComponentModel.Win32Exception] {
        return [pscustomobject]@{
            ProcessStarted = $false; ExitCode = $null; StartErrorCode = $_.Exception.NativeErrorCode
            SuccessMarkerObserved = $false; Value = $null; StandardErrorPresent = $false
        }
    } catch [System.UnauthorizedAccessException] {
        return [pscustomobject]@{
            ProcessStarted = $false; ExitCode = $null; StartErrorCode = 5
            SuccessMarkerObserved = $false; Value = $null; StandardErrorPresent = $false
        }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Add-PythonStagingOnlyReadAndPathTests([object] $Context) {
    $pathExact = Test-PythonStagingOnlyExactPath $script:PythonStagingOnlyRoot 'C:\automaton\.venv.new'
    Add-PythonStagingOnlyResult $Context 'STAGING_PATH_EXACT' 'PASS' `
        $(if ($pathExact) { 'PASS' } else { 'FAIL' }) 'EXACT_STAGING_TARGET_REQUIRED'
    if (-not $pathExact) { return }
    foreach ($requiredPath in @(
        $script:PythonStagingOnlyRoot,
        $script:PythonStagingOnlyExecutable,
        $script:PythonStagingOnlySitePackages,
        $script:PythonStagingOnlyFastApiFile,
        $script:PythonStagingOnlyConfig
    )) {
        Assert-PythonStagingOnlyNoReparsePoint $requiredPath
    }
    $treeCount = Get-PythonStagingOnlyTreeSnapshot
    Add-PythonStagingOnlyResult $Context 'STAGING_ENUMERATE' 'PASS' `
        $(if ($treeCount -gt 0) { 'PASS' } else { 'FAIL' }) "ITEMS_ENUMERATED_$treeCount"
    $pythonPathExact = Test-PythonStagingOnlyExactPath `
        $script:PythonStagingOnlyExecutable 'C:\automaton\.venv.new\Scripts\python.exe'
    Add-PythonStagingOnlyResult $Context 'STAGING_PYTHON_PATH_EXACT' 'PASS' `
        $(if ($pythonPathExact) { 'PASS' } else { 'FAIL' }) 'EXACT_STAGING_PYTHON_REQUIRED'
    $configRecord = [System.IO.File]::ReadAllLines($script:PythonStagingOnlyConfig)
    $configPass = Test-PythonStagingOnlyConfigRecord $configRecord
    Add-PythonStagingOnlyResult $Context 'STAGING_BASE_REFERENCE_EXACT' 'PASS' `
        $(if ($configPass) { 'PASS' } else { 'FAIL' }) 'PYVENV_CFG_MACHINE_BASE_NO_SYSTEM_SITE_PACKAGES'
    Add-PythonStagingOnlyFileReadTest $Context 'STAGING_PYTHON_READ' $script:PythonStagingOnlyExecutable
    Add-PythonStagingOnlyFileReadTest $Context 'STAGING_SITE_PACKAGES_READ' $script:PythonStagingOnlyFastApiFile
}

function Add-GatewayPythonStagingOnlyExecutionTests([object] $Context) {
    $gatewaySource = @'
import importlib
import importlib.metadata
import json
import site
import struct
import sys
import venv

def can_import(name):
    try:
        importlib.import_module(name)
        return True
    except Exception:
        return False

print(json.dumps({
    "architecture_bits": struct.calcsize("P") * 8,
    "base_prefix": sys.base_prefix,
    "executable": sys.executable,
    "imports": {
        "fastapi": can_import("fastapi"),
        "pydantic": can_import("pydantic"),
        "yaml": can_import("yaml"),
        "uvicorn": can_import("uvicorn"),
    },
    "mt5_imported": "MetaTrader5" in sys.modules,
    "mt5_metadata": importlib.metadata.version("MetaTrader5"),
    "prefix": sys.prefix,
    "sys_path": sys.path,
    "user_site_enabled": bool(site.ENABLE_USER_SITE),
    "venv_import": True,
    "version": ".".join(str(part) for part in sys.version_info[:3]),
}, sort_keys=True, separators=(",", ":")))
'@
    $execution = Invoke-PythonStagingOnlyProcess $gatewaySource '' $true
    $Context.execution = [ordered]@{
        process_started = [bool]$execution.ProcessStarted
        exit_code = $execution.ExitCode
        success_marker_observed = [bool]$execution.SuccessMarkerObserved
    }
    $value = $execution.Value
    $noUserProfilePath = $false
    if ($null -ne $value) {
        $forbiddenProfile = 'C:' + '\' + 'Users' + '\' + 'Proyecto IA'
        $noUserProfilePath = @($value.sys_path | Where-Object {
            ([string]$_).StartsWith($forbiddenProfile, [System.StringComparison]::OrdinalIgnoreCase)
        }).Count -eq 0
    }
    $executePass = $execution.ProcessStarted -and $execution.ExitCode -eq 0 -and
        -not $execution.StandardErrorPresent -and $null -ne $value -and
        $value.version -eq '3.14.5' -and $value.architecture_bits -eq 64 -and
        (Test-PythonStagingOnlyExactPath $value.executable $script:PythonStagingOnlyExecutable) -and
        (Test-PythonStagingOnlyExactPath $value.prefix $script:PythonStagingOnlyRoot) -and
        (Test-PythonStagingOnlyExactPath $value.base_prefix $script:PythonStagingOnlyBase) -and
        -not [bool]$value.user_site_enabled -and $noUserProfilePath -and [bool]$value.venv_import
    Add-PythonStagingOnlyResult $Context 'STAGING_PYTHON_EXECUTE' 'PASS' `
        $(if ($executePass) { 'PASS' } else { 'FAIL' }) `
        $(if ($executePass) { 'PYTHON_3_14_5_X64_ISOLATED_EXACT_STAGING_AND_BASE' } else { 'STAGING_PYTHON_EXECUTION_OR_METADATA_MISMATCH' }) `
        $false (-not $execution.ProcessStarted -and $execution.StartErrorCode -ne 5)

    foreach ($importGate in @(
        [pscustomobject]@{ Name = 'STAGING_FASTAPI_IMPORT'; Property = 'fastapi' },
        [pscustomobject]@{ Name = 'STAGING_PYDANTIC_IMPORT'; Property = 'pydantic' },
        [pscustomobject]@{ Name = 'STAGING_PYYAML_IMPORT'; Property = 'yaml' },
        [pscustomobject]@{ Name = 'STAGING_UVICORN_IMPORT'; Property = 'uvicorn' }
    )) {
        $passed = Test-PythonStagingOnlyImportGate $value $importGate.Property
        Add-PythonStagingOnlyResult $Context $importGate.Name 'PASS' `
            $(if ($passed) { 'PASS' } else { 'FAIL' }) 'NORMAL_GATEWAY_IMPORT'
    }
    $metadataPass = Test-PythonStagingOnlyMt5Metadata $value
    Add-PythonStagingOnlyResult $Context 'STAGING_METATRADER5_METADATA' 'PASS' `
        $(if ($metadataPass) { 'PASS' } else { 'FAIL' }) 'DISTRIBUTION_METADATA_ONLY'
    $notImported = Test-PythonStagingOnlyMt5NotImported $value
    Add-PythonStagingOnlyResult $Context 'STAGING_METATRADER5_IMPORTED' 'false' `
        $(if ($notImported) { 'false' } else { 'true' }) 'SYS_MODULES_OBSERVATION'
}

function Add-AgentPythonStagingOnlyExecutionTest(
    [object] $Context,
    [string] $RunId
) {
    $marker = "AUTOMATON_STAGING_AGENT_SUCCESS_$RunId"
    $agentSource = "print('$marker')`n"
    $execution = Invoke-PythonStagingOnlyProcess $agentSource $marker $false
    $Context.execution = [ordered]@{
        process_started = [bool]$execution.ProcessStarted
        exit_code = $execution.ExitCode
        success_marker_observed = [bool]$execution.SuccessMarkerObserved
    }
    $resolved = Resolve-AgentPythonStagingExecutionExpectation `
        $execution.ProcessStarted $execution.ExitCode $execution.SuccessMarkerObserved $execution.StartErrorCode
    Add-PythonStagingOnlyResult $Context 'STAGING_PYTHON_FUNCTIONAL_EXECUTION_DENY' 'DENY' `
        $resolved.observed $resolved.evidence $resolved.critical $resolved.infrastructure_error
}

function Add-PythonStagingOnlyMutationTests(
    [object] $Context,
    [string] $RunId,
    [string] $Role
) {
    $stem = if ($Role -eq 'AutomatonGateway') { 'gateway' } else { 'agent' }
    $fileCanary = Join-Path $script:PythonStagingOnlyRoot ".python-staging-$stem-$RunId.canary"
    $directoryCanary = Join-Path $script:PythonStagingOnlyRoot ".python-staging-$stem-$RunId.directory"
    Add-PythonStagingOnlyDeniedFileCreateTest $Context 'STAGING_CREATE_FILE_DENY' $fileCanary
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonStagingOnlyDeniedDirectoryCreateTest $Context 'STAGING_CREATE_DIRECTORY_DENY' $directoryCanary
    if ($Context.critical_unexpected_allow) { return }
    $createDenied = $Context.tests.STAGING_CREATE_FILE_DENY.passed -and
        $Context.tests.STAGING_CREATE_DIRECTORY_DENY.passed
    Add-PythonStagingOnlyResult $Context 'STAGING_CREATE_DENY' 'PASS' `
        $(if ($createDenied) { 'PASS' } else { 'FAIL' }) 'FILE_AND_DIRECTORY_CREATE_DENIED'

    Add-PythonStagingOnlyNativeDeniedTest $Context 'STAGING_WRITE_DENY' $script:PythonStagingOnlyExecutable ([uint32]2) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonStagingOnlyNativeDeniedTest $Context 'STAGING_APPEND_DENY' $script:PythonStagingOnlyExecutable ([uint32]4) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonStagingOnlyNativeDeniedTest $Context 'STAGING_TRUNCATE_DENY' $script:PythonStagingOnlyExecutable ([uint32]2) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonStagingOnlyNativeDeniedTest $Context 'STAGING_RENAME_DENY' $script:PythonStagingOnlyRoot ([uint32]64) $true
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonStagingOnlyNativeDeniedTest $Context 'STAGING_DELETE_DENY' $script:PythonStagingOnlyExecutable ([uint32]65536) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonStagingOnlyNativeDeniedTest $Context 'STAGING_WRITE_ATTRIBUTES_DENY' $script:PythonStagingOnlyExecutable ([uint32]256) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonStagingOnlyNativeDeniedTest $Context 'STAGING_CHANGE_ACL_DENY' $script:PythonStagingOnlyRoot ([uint32]262144) $true
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonStagingOnlyNativeDeniedTest $Context 'STAGING_TAKE_OWNERSHIP_DENY' $script:PythonStagingOnlyRoot ([uint32]524288) $true
}

function Write-PythonStagingOnlyExclusiveReport([string] $Path, [object] $Report) {
    $json = $Report | ConvertTo-Json -Depth 10
    $stream = [System.IO.File]::Open(
        $Path, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($json); $writer.Flush() } finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
}

function Write-PythonStagingOnlySummary([object] $Report, [string] $ReportPath) {
    foreach ($test in $Report.tests.GetEnumerator()) {
        Write-Output "$($test.Key)=$(if ($test.Value.passed) { 'PASS' } else { 'FAIL' })"
    }
    Write-Output "MODE=$($Report.mode)"
    Write-Output "TRADING_MODE=$($Report.boundaries.trading_mode)"
    Write-Output "BUILD_VENV=$($Report.boundaries.build_venv.ToString().ToLowerInvariant())"
    Write-Output "PROMOTE_VENV=$($Report.boundaries.promote_venv.ToString().ToLowerInvariant())"
    Write-Output "ACTIVE_VENV_ACCESSED=$($Report.boundaries.active_venv_accessed.ToString().ToLowerInvariant())"
    Write-Output "ACTIVE_VENV_MODIFIED=$($Report.boundaries.active_venv_modified.ToString().ToLowerInvariant())"
    Write-Output "MT5_IMPORTED=$($Report.boundaries.mt5_imported.ToString().ToLowerInvariant())"
    Write-Output "MT5_ACCESSED=$($Report.boundaries.mt5_accessed.ToString().ToLowerInvariant())"
    Write-Output "ORDER_CHECK=$($Report.boundaries.order_check_called.ToString().ToLowerInvariant())"
    Write-Output "ORDER_SEND=$($Report.boundaries.order_send_called.ToString().ToLowerInvariant())"
    Write-Output "ACL_MODIFIED=$($Report.boundaries.acl_modified.ToString().ToLowerInvariant())"
    Write-Output "FILESYSTEM_STAGING_MODIFIED=$($Report.boundaries.filesystem_staging_modified.ToString().ToLowerInvariant())"
    Write-Output "PYTHON_STAGING_ONLY_STATUS=$($Report.status)"
    Write-Output "PYTHON_STAGING_ONLY_REPORT=$ReportPath"
}

function Invoke-TradingLabPythonStagingOnlyRuntimeAcl(
    [ValidateSet('AutomatonGateway', 'AutomatonAgent')]
    [string] $Role,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [string] $EffectiveSid,
    [bool] $AdministrativeToken
) {
    $expectedSid = if ($Role -eq 'AutomatonGateway') {
        $script:PythonStagingOnlyGatewaySid
    } else { $script:PythonStagingOnlyAgentSid }
    if (-not (Test-PythonStagingOnlyIdentity $EffectiveSid $expectedSid)) {
        throw "PYTHON_STAGING_ONLY_WRONG_EFFECTIVE_SID:$EffectiveSid"
    }
    if ($AdministrativeToken) { throw 'PYTHON_STAGING_ONLY_REFUSES_ADMINISTRATIVE_TOKEN' }
    if (-not (Test-PythonStagingOnlyExactPath $script:PythonStagingOnlyRoot 'C:\automaton\.venv.new')) {
        throw 'PYTHON_STAGING_ONLY_TARGET_PATH_MISMATCH'
    }
    if (-not (Test-PythonStagingOnlyTargetPresent $script:PythonStagingOnlyRoot)) {
        throw 'PYTHON_STAGING_ONLY_TARGET_MISSING'
    }

    $authorizedRoot = if ($Role -eq 'AutomatonGateway') {
        'C:\ProgramData\AutomatonMT5Lab\operational'
    } else { 'C:\Users\AutomatonAgent\.automaton' }
    $reportRoot = Join-Path $authorizedRoot 'acl-runtime-results'
    $roleStem = if ($Role -eq 'AutomatonGateway') { 'gateway' } else { 'agent' }
    $reportPath = Join-Path $reportRoot "$roleStem-python-staging-$RunId.json"
    $context = [pscustomobject]@{
        tests = [ordered]@{}
        execution = $null
        critical_unexpected_allow = $false
        infrastructure_error = $false
        filesystem_staging_modified = $false
        runtime_error = $null
    }
    $tempPath = $null
    $tempCleanupSucceeded = $false
    try {
        Add-PythonStagingOnlyResult $context 'IDENTITY' $expectedSid $EffectiveSid 'EFFECTIVE_WINDOWS_TOKEN_SID'
        $tempPath = Initialize-PythonStagingOnlyPrivateTemp $reportRoot $authorizedRoot $RunId
        Initialize-PythonStagingOnlyNativeProbe
        Add-PythonStagingOnlyReadAndPathTests $context
        if (-not $context.tests.STAGING_PATH_EXACT.passed) {
            throw 'PYTHON_STAGING_ONLY_TARGET_PATH_MISMATCH'
        }
        if ($Role -eq 'AutomatonGateway') {
            Add-GatewayPythonStagingOnlyExecutionTests $context
        } else {
            Add-AgentPythonStagingOnlyExecutionTest $context $RunId
        }
        if (-not $context.critical_unexpected_allow) {
            Add-PythonStagingOnlyMutationTests $context $RunId $Role
        }
    } catch {
        $context.infrastructure_error = $true
        $context.runtime_error = $_.Exception.GetType().FullName + ':' + $_.Exception.Message
    } finally {
        if ($null -ne $tempPath) {
            $tempCleanupSucceeded = Clear-PythonStagingOnlyPrivateTemp $tempPath $reportRoot
            if (-not $tempCleanupSucceeded) { $context.infrastructure_error = $true }
        }
    }

    $allPassed = -not $context.critical_unexpected_allow -and -not $context.infrastructure_error
    foreach ($test in $context.tests.Values) { if (-not $test.passed) { $allPassed = $false } }
    $status = if ($context.critical_unexpected_allow) {
        'CRITICAL_UNEXPECTED_ALLOW'
    } elseif ($context.infrastructure_error) {
        'TEST_INFRASTRUCTURE_ERROR'
    } elseif (-not $allPassed) {
        'TEST_FAILED_EXPECTATION'
    } else { 'PASS' }
    $report = [ordered]@{
        schema_version = 1
        mode = 'PYTHON_STAGING_ONLY'
        role = $Role
        run_id = $RunId
        effective_sid = $EffectiveSid
        status = $status
        completed_at_utc = [DateTime]::UtcNow.ToString('o')
        runtime_error = $context.runtime_error
        tests = $context.tests
        execution = $context.execution
        boundaries = [ordered]@{
            trading_mode = 'OBSERVE_ONLY'
            build_venv = $false
            promote_venv = $false
            active_venv_accessed = $false
            active_venv_modified = $false
            mt5_imported = $false
            mt5_accessed = $false
            order_check_called = $false
            order_send_called = $false
            gateway_started = $false
            automaton_started = $false
            acl_modified = $false
            filesystem_staging_modified = [bool]$context.filesystem_staging_modified
            report_directory_modified = $true
            report_temp_cleanup_succeeded = $tempCleanupSucceeded
        }
    }
    Write-PythonStagingOnlyExclusiveReport $reportPath $report
    Write-PythonStagingOnlySummary $report $reportPath
    return [pscustomobject]@{
        status = $status
        exit_code = if ($status -eq 'PASS') { 0 } else { 1 }
        report_path = $reportPath
    }
}
