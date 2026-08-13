Set-StrictMode -Version 2.0

$script:PythonBaseOnlyRoot = 'C:\Program Files\AutomatonPython\3.14.5'
$script:PythonBaseOnlyExecutable = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'
$script:PythonBaseOnlyDll = 'C:\Program Files\AutomatonPython\3.14.5\python314.dll'
$script:PythonBaseOnlyStdlib = 'C:\Program Files\AutomatonPython\3.14.5\Lib\os.py'
$script:PythonBaseOnlyGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$script:PythonBaseOnlyAgentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'

function Get-PythonBaseOnlyCanonicalPath([string] $Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-PythonBaseOnlyExactPath([string] $Path, [string] $ExpectedPath) {
    try {
        return (Get-PythonBaseOnlyCanonicalPath $Path).Equals(
            (Get-PythonBaseOnlyCanonicalPath $ExpectedPath),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    } catch { return $false }
}

function Test-PythonBaseOnlyIdentity([string] $EffectiveSid, [string] $ExpectedSid) {
    return -not [string]::IsNullOrWhiteSpace($EffectiveSid) -and $EffectiveSid -eq $ExpectedSid
}

function Test-PythonBaseOnlyReparseAttributes([System.IO.FileAttributes] $Attributes) {
    return -not [bool]($Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

function Resolve-PythonBaseOnlyAccessExpectation(
    [bool] $Allowed,
    [int] $ErrorCode,
    [bool] $ExpectedAllow
) {
    if ($ExpectedAllow) {
        if ($Allowed) { return [pscustomobject]@{ passed = $true; observed = 'ALLOW'; critical = $false; infrastructure_error = $false } }
        if ($ErrorCode -eq 5) { return [pscustomobject]@{ passed = $false; observed = 'DENY'; critical = $false; infrastructure_error = $false } }
        return [pscustomobject]@{ passed = $false; observed = 'ERROR'; critical = $false; infrastructure_error = $true }
    }
    if ($Allowed) { return [pscustomobject]@{ passed = $false; observed = 'ALLOW'; critical = $true; infrastructure_error = $false } }
    if ($ErrorCode -eq 5) { return [pscustomobject]@{ passed = $true; observed = 'DENY'; critical = $false; infrastructure_error = $false } }
    return [pscustomobject]@{ passed = $false; observed = 'ERROR'; critical = $false; infrastructure_error = $true }
}

function Assert-PythonBaseOnlyConfinedPath([string] $Path) {
    $candidate = Get-PythonBaseOnlyCanonicalPath $Path
    $root = Get-PythonBaseOnlyCanonicalPath $script:PythonBaseOnlyRoot
    if (-not ($candidate.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase))) {
        throw "PYTHON_BASE_PATH_OUTSIDE_EXACT_RUNTIME:$candidate"
    }
}

function Assert-PythonBaseOnlyNoReparsePoint([string] $Path) {
    Assert-PythonBaseOnlyConfinedPath $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not (Test-PythonBaseOnlyReparseAttributes $item.Attributes)) {
        throw "PYTHON_BASE_REPARSE_POINT_FAIL_CLOSED:$($item.FullName)"
    }
}

function Assert-PythonBaseOnlyReportPath([string] $Path, [string] $AuthorizedRoot) {
    $candidate = Get-PythonBaseOnlyCanonicalPath $Path
    $root = Get-PythonBaseOnlyCanonicalPath $AuthorizedRoot
    if (-not $candidate.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "PYTHON_BASE_REPORT_PATH_OUTSIDE_AUTHORIZED_ROOT:$candidate"
    }
}

function Assert-PythonBaseOnlyReportDirectory([string] $Path, [string] $AuthorizedRoot) {
    Assert-PythonBaseOnlyReportPath $Path $AuthorizedRoot
    if (-not [System.IO.Directory]::Exists($Path)) {
        [void][System.IO.Directory]::CreateDirectory($Path)
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or -not (Test-PythonBaseOnlyReparseAttributes $item.Attributes)) {
        throw "PYTHON_BASE_REPORT_DIRECTORY_INVALID:$Path"
    }
}

function Initialize-PythonBaseOnlyPrivateTemp(
    [string] $ReportRoot,
    [string] $AuthorizedRoot,
    [string] $RunId
) {
    Assert-PythonBaseOnlyReportDirectory $ReportRoot $AuthorizedRoot
    $tempPath = Join-Path $ReportRoot ".python-base-only-tmp-$RunId"
    Assert-PythonBaseOnlyReportPath $tempPath $ReportRoot
    if ([System.IO.Directory]::Exists($tempPath) -or [System.IO.File]::Exists($tempPath)) {
        throw 'PYTHON_BASE_ONLY_TEMP_COLLISION: use a new RunId after inspection.'
    }
    [void][System.IO.Directory]::CreateDirectory($tempPath)
    $item = Get-Item -LiteralPath $tempPath -Force -ErrorAction Stop
    if (-not (Test-PythonBaseOnlyReparseAttributes $item.Attributes)) {
        throw 'PYTHON_BASE_ONLY_TEMP_REPARSE_POINT'
    }
    $env:TEMP = Get-PythonBaseOnlyCanonicalPath $tempPath
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

function Clear-PythonBaseOnlyPrivateTemp([string] $TempPath, [string] $ReportRoot) {
    try {
        Assert-PythonBaseOnlyReportPath $TempPath $ReportRoot
        if (-not [System.IO.Directory]::Exists($TempPath)) { return $true }
        $rootItem = Get-Item -LiteralPath $TempPath -Force -ErrorAction Stop
        if (-not (Test-PythonBaseOnlyReparseAttributes $rootItem.Attributes)) { return $false }
        foreach ($item in Get-ChildItem -LiteralPath $TempPath -Force -Recurse -ErrorAction Stop) {
            if (-not (Test-PythonBaseOnlyReparseAttributes $item.Attributes)) { return $false }
        }
        [System.IO.Directory]::Delete($TempPath, $true)
        return -not [System.IO.Directory]::Exists($TempPath)
    } catch { return $false }
}

function Add-PythonBaseOnlyResult(
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

function Initialize-PythonBaseOnlyNativeProbe {
    if ('Automaton.RuntimeAcl.PythonBaseOnlyNativeMethods' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Automaton.RuntimeAcl {
    public static class PythonBaseOnlyNativeMethods {
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

function Invoke-PythonBaseOnlyNativeAccessProbe(
    [string] $Path,
    [uint32] $DesiredAccess,
    [bool] $Directory
) {
    Assert-PythonBaseOnlyConfinedPath $Path
    $flags = if ($Directory) { [uint32]33554432 } else { [uint32]128 }
    $handle = [Automaton.RuntimeAcl.PythonBaseOnlyNativeMethods]::CreateFile(
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

function Add-PythonBaseOnlyNativeDeniedTest(
    [object] $Context,
    [string] $Name,
    [string] $Path,
    [uint32] $DesiredAccess,
    [bool] $Directory
) {
    $probe = Invoke-PythonBaseOnlyNativeAccessProbe $Path $DesiredAccess $Directory
    $resolved = Resolve-PythonBaseOnlyAccessExpectation $probe.Allowed $probe.ErrorCode $false
    Add-PythonBaseOnlyResult $Context $Name 'DENY' $resolved.observed `
        $(if ($resolved.observed -eq 'DENY') { 'WIN32_ACCESS_DENIED' } elseif ($resolved.observed -eq 'ALLOW') { 'FORBIDDEN_RIGHT_GRANTED_WITHOUT_MUTATION' } else { "WIN32_ERROR_$($probe.ErrorCode)" }) `
        $resolved.critical $resolved.infrastructure_error
}

function Add-PythonBaseOnlyFileReadTest(
    [object] $Context,
    [string] $Name,
    [string] $Path,
    [bool] $ExpectedAllow
) {
    Assert-PythonBaseOnlyConfinedPath $Path
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
    $resolved = Resolve-PythonBaseOnlyAccessExpectation $allowed $errorCode $ExpectedAllow
    $expected = if ($ExpectedAllow) { 'ALLOW' } else { 'DENY' }
    Add-PythonBaseOnlyResult $Context $Name $expected $resolved.observed `
        $(if ($resolved.observed -eq 'ALLOW') { 'READ_SUCCEEDED_CONTENT_NOT_REPORTED' } elseif ($resolved.observed -eq 'DENY') { 'WIN32_ACCESS_DENIED' } else { 'FILE_READ_INFRASTRUCTURE_ERROR' }) `
        $resolved.critical $resolved.infrastructure_error
}

function Add-PythonBaseOnlyDeniedFileCreateTest(
    [object] $Context,
    [string] $Name,
    [string] $Path
) {
    Assert-PythonBaseOnlyConfinedPath $Path
    $stream = $null
    $created = $false
    $observed = 'ERROR'
    try {
        $stream = [System.IO.File]::Open(
            $Path, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None
        )
        $created = $true
        $Context.filesystem_runtime_modified = $true
        $observed = 'ALLOW'
    } catch [System.UnauthorizedAccessException] {
        $observed = 'DENY'
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($created) {
            try { [System.IO.File]::Delete($Path) } catch { $Context.infrastructure_error = $true }
        }
    }
    Add-PythonBaseOnlyResult $Context $Name 'DENY' $observed `
        $(if ($observed -eq 'DENY') { 'CREATE_NEW_ACCESS_DENIED' } elseif ($observed -eq 'ALLOW') { 'CRITICAL_CANARY_CREATION_ALLOWED_AND_CLEANUP_ATTEMPTED' } else { 'CREATE_NEW_INFRASTRUCTURE_ERROR' }) `
        ($observed -eq 'ALLOW') ($observed -eq 'ERROR')
}

function Add-PythonBaseOnlyDeniedDirectoryCreateTest(
    [object] $Context,
    [string] $Name,
    [string] $Path
) {
    Assert-PythonBaseOnlyConfinedPath $Path
    $created = $false
    $observed = 'ERROR'
    $errorCode = -1
    try {
        $created = [Automaton.RuntimeAcl.PythonBaseOnlyNativeMethods]::CreateDirectory(
            $Path, [IntPtr]::Zero
        )
        if ($created) {
            $errorCode = 0
            $Context.filesystem_runtime_modified = $true
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
    Add-PythonBaseOnlyResult $Context $Name 'DENY' $observed `
        $(if ($observed -eq 'DENY') { 'CREATE_DIRECTORY_ACCESS_DENIED' } elseif ($observed -eq 'ALLOW') { 'CRITICAL_CANARY_DIRECTORY_ALLOWED_AND_CLEANUP_ATTEMPTED' } else { "CREATE_DIRECTORY_WIN32_ERROR_$errorCode" }) `
        ($observed -eq 'ALLOW') ($observed -eq 'ERROR')
}

function Get-PythonBaseOnlyTreeSnapshot {
    $root = Get-PythonBaseOnlyCanonicalPath $script:PythonBaseOnlyRoot
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($root)
    $count = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        Assert-PythonBaseOnlyNoReparsePoint $current
        $count++
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (-not $item.PSIsContainer) { continue }
        foreach ($childPath in [System.IO.Directory]::EnumerateFileSystemEntries($current)) {
            Assert-PythonBaseOnlyConfinedPath $childPath
            $child = Get-Item -LiteralPath $childPath -Force -ErrorAction Stop
            if (-not (Test-PythonBaseOnlyReparseAttributes $child.Attributes)) {
                throw "PYTHON_BASE_REPARSE_POINT_FAIL_CLOSED:$($child.FullName)"
            }
            if ($child.PSIsContainer) { $pending.Enqueue($child.FullName) } else { $count++ }
        }
    }
    return $count
}

function Invoke-PythonBaseOnlyProcess(
    [string] $Source,
    [bool] $ParseJson
) {
    $process = $null
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $script:PythonBaseOnlyExecutable
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
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { return [pscustomobject]@{ Allowed = $false; ErrorCode = -1; Value = $null } }
        $process.StandardInput.Write($Source)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if (-not $ParseJson) { return [pscustomobject]@{ Allowed = $true; ErrorCode = 0; Value = $null } }
        if ($process.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($stderr)) {
            return [pscustomobject]@{ Allowed = $false; ErrorCode = -1; Value = $null }
        }
        try {
            return [pscustomobject]@{ Allowed = $true; ErrorCode = 0; Value = ($stdout.Trim() | ConvertFrom-Json) }
        } catch {
            return [pscustomobject]@{ Allowed = $false; ErrorCode = -1; Value = $null }
        }
    } catch [System.ComponentModel.Win32Exception] {
        return [pscustomobject]@{ Allowed = $false; ErrorCode = $_.Exception.NativeErrorCode; Value = $null }
    } catch [System.UnauthorizedAccessException] {
        return [pscustomobject]@{ Allowed = $false; ErrorCode = 5; Value = $null }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Add-GatewayPythonBaseOnlyTests([object] $Context, [string] $RunId) {
    Assert-PythonBaseOnlyNoReparsePoint $script:PythonBaseOnlyRoot
    Add-PythonBaseOnlyFileReadTest $Context 'MACHINE_PYTHON_READ' $script:PythonBaseOnlyExecutable $true
    $treeCount = Get-PythonBaseOnlyTreeSnapshot
    Add-PythonBaseOnlyResult $Context 'MACHINE_PYTHON_ENUMERATE' 'PASS' `
        $(if ($treeCount -gt 0) { 'PASS' } else { 'FAIL' }) "ITEMS_ENUMERATED_$treeCount"

    $source = @'
import json
import struct
import sys
import venv
print(json.dumps({
    "architecture_bits": struct.calcsize("P") * 8,
    "base_prefix": sys.base_prefix,
    "executable": sys.executable,
    "venv_import": True,
    "version": ".".join(str(part) for part in sys.version_info[:3]),
}, sort_keys=True, separators=(",", ":")))
'@
    $execution = Invoke-PythonBaseOnlyProcess $source $true
    $metadataPass = $execution.Allowed -and $null -ne $execution.Value -and
        $execution.Value.version -eq '3.14.5' -and $execution.Value.architecture_bits -eq 64 -and
        (Test-PythonBaseOnlyExactPath $execution.Value.executable $script:PythonBaseOnlyExecutable) -and
        (Test-PythonBaseOnlyExactPath $execution.Value.base_prefix $script:PythonBaseOnlyRoot) -and
        [bool]$execution.Value.venv_import
    Add-PythonBaseOnlyResult $Context 'MACHINE_PYTHON_EXECUTE' 'PASS' `
        $(if ($metadataPass) { 'PASS' } else { 'FAIL' }) `
        $(if ($metadataPass) { 'PYTHON_3_14_5_X64_EXACT_PATH_VENV_IMPORT' } else { 'PYTHON_EXECUTION_OR_METADATA_MISMATCH' }) `
        $false (-not $execution.Allowed -and $execution.ErrorCode -ne 5)

    $fileCanary = Join-Path $script:PythonBaseOnlyRoot ".python-base-only-$RunId.canary"
    $directoryCanary = Join-Path $script:PythonBaseOnlyRoot ".python-base-only-$RunId.directory"
    Add-PythonBaseOnlyDeniedFileCreateTest $Context 'MACHINE_PYTHON_CREATE_FILE_DENY' $fileCanary
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyDeniedDirectoryCreateTest $Context 'MACHINE_PYTHON_CREATE_DIRECTORY_DENY' $directoryCanary
    if ($Context.critical_unexpected_allow) { return }
    $createDenied = $Context.tests.MACHINE_PYTHON_CREATE_FILE_DENY.passed -and $Context.tests.MACHINE_PYTHON_CREATE_DIRECTORY_DENY.passed
    Add-PythonBaseOnlyResult $Context 'MACHINE_PYTHON_CREATE_DENY' 'PASS' $(if ($createDenied) { 'PASS' } else { 'FAIL' }) 'FILE_AND_DIRECTORY_CREATE_DENIED'

    Add-PythonBaseOnlyNativeDeniedTest $Context 'MACHINE_PYTHON_WRITE_DENY' $script:PythonBaseOnlyExecutable ([uint32]2) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'MACHINE_PYTHON_APPEND_DENY' $script:PythonBaseOnlyExecutable ([uint32]4) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'MACHINE_PYTHON_TRUNCATE_DENY' $script:PythonBaseOnlyExecutable ([uint32]2) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'MACHINE_PYTHON_RENAME_DENY' $script:PythonBaseOnlyRoot ([uint32]64) $true
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'MACHINE_PYTHON_DELETE_DENY' $script:PythonBaseOnlyExecutable ([uint32]65536) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'MACHINE_PYTHON_WRITE_ATTRIBUTES_DENY' $script:PythonBaseOnlyExecutable ([uint32]256) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'MACHINE_PYTHON_CHANGE_ACL_DENY' $script:PythonBaseOnlyRoot ([uint32]262144) $true
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'MACHINE_PYTHON_TAKE_OWNERSHIP_DENY' $script:PythonBaseOnlyRoot ([uint32]524288) $true
}

function Add-AgentPythonBaseOnlyTests([object] $Context, [string] $RunId) {
    Assert-PythonBaseOnlyNoReparsePoint $script:PythonBaseOnlyRoot
    Add-PythonBaseOnlyNativeDeniedTest $Context 'DIRECTORY_ENUMERATION_DENY' $script:PythonBaseOnlyRoot ([uint32]1) $true
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyFileReadTest $Context 'PYTHON_EXE_READ_DENY' $script:PythonBaseOnlyExecutable $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyFileReadTest $Context 'PYTHON_DLL_READ_DENY' $script:PythonBaseOnlyDll $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyFileReadTest $Context 'STDLIB_READ_DENY' $script:PythonBaseOnlyStdlib $false
    if ($Context.critical_unexpected_allow) { return }

    $execution = Invoke-PythonBaseOnlyProcess "import sys`nsys.exit(0)`n" $false
    $executeResolved = Resolve-PythonBaseOnlyAccessExpectation $execution.Allowed $execution.ErrorCode $false
    Add-PythonBaseOnlyResult $Context 'PYTHON_EXECUTE_DENY' 'DENY' $executeResolved.observed `
        $(if ($executeResolved.observed -eq 'DENY') { 'PROCESS_START_ACCESS_DENIED' } elseif ($executeResolved.observed -eq 'ALLOW') { 'CRITICAL_MACHINE_PYTHON_EXECUTION_ALLOWED' } else { "PROCESS_START_ERROR_$($execution.ErrorCode)" }) `
        $executeResolved.critical $executeResolved.infrastructure_error
    if ($Context.critical_unexpected_allow) { return }

    $fileCanary = Join-Path $script:PythonBaseOnlyRoot ".python-base-only-agent-$RunId.canary"
    $directoryCanary = Join-Path $script:PythonBaseOnlyRoot ".python-base-only-agent-$RunId.directory"
    Add-PythonBaseOnlyDeniedFileCreateTest $Context 'CREATE_FILE_DENY' $fileCanary
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyDeniedDirectoryCreateTest $Context 'CREATE_DIRECTORY_DENY' $directoryCanary
    if ($Context.critical_unexpected_allow) { return }
    $createDenied = $Context.tests.CREATE_FILE_DENY.passed -and $Context.tests.CREATE_DIRECTORY_DENY.passed
    Add-PythonBaseOnlyResult $Context 'CREATE_DENY' 'PASS' $(if ($createDenied) { 'PASS' } else { 'FAIL' }) 'FILE_AND_DIRECTORY_CREATE_DENIED'

    Add-PythonBaseOnlyNativeDeniedTest $Context 'WRITE_DENY' $script:PythonBaseOnlyExecutable ([uint32]2) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'DELETE_DENY' $script:PythonBaseOnlyExecutable ([uint32]65536) $false
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'CHANGE_ACL_DENY' $script:PythonBaseOnlyRoot ([uint32]262144) $true
    if ($Context.critical_unexpected_allow) { return }
    Add-PythonBaseOnlyNativeDeniedTest $Context 'TAKE_OWNERSHIP_DENY' $script:PythonBaseOnlyRoot ([uint32]524288) $true
}

function Write-PythonBaseOnlyExclusiveReport([string] $Path, [object] $Report) {
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

function Write-PythonBaseOnlySummary([object] $Report, [string] $ReportPath) {
    foreach ($test in $Report.tests.GetEnumerator()) {
        Write-Output "$($test.Key)=$(if ($test.Value.passed) { 'PASS' } else { 'FAIL' })"
    }
    Write-Output "MODE=$($Report.mode)"
    Write-Output "TRADING_MODE=$($Report.boundaries.trading_mode)"
    Write-Output "BUILD_VENV=$($Report.boundaries.build_venv.ToString().ToLowerInvariant())"
    Write-Output "VENV_ACCESSED=$($Report.boundaries.venv_accessed.ToString().ToLowerInvariant())"
    Write-Output "MT5_ACCESSED=$($Report.boundaries.mt5_accessed.ToString().ToLowerInvariant())"
    Write-Output "ORDER_CHECK=$($Report.boundaries.order_check_called.ToString().ToLowerInvariant())"
    Write-Output "ORDER_SEND=$($Report.boundaries.order_send_called.ToString().ToLowerInvariant())"
    Write-Output "ACL_MODIFIED=$($Report.boundaries.acl_modified.ToString().ToLowerInvariant())"
    Write-Output "FILESYSTEM_RUNTIME_MODIFIED=$($Report.boundaries.filesystem_runtime_modified.ToString().ToLowerInvariant())"
    Write-Output "PYTHON_BASE_ONLY_STATUS=$($Report.status)"
    Write-Output "PYTHON_BASE_ONLY_REPORT=$ReportPath"
}

function Invoke-TradingLabPythonBaseOnlyRuntimeAcl(
    [ValidateSet('AutomatonGateway', 'AutomatonAgent')]
    [string] $Role,
    [string] $RunId,
    [string] $EffectiveSid,
    [bool] $AdministrativeToken
) {
    $expectedSid = if ($Role -eq 'AutomatonGateway') { $script:PythonBaseOnlyGatewaySid } else { $script:PythonBaseOnlyAgentSid }
    if (-not (Test-PythonBaseOnlyIdentity $EffectiveSid $expectedSid)) {
        throw "PYTHON_BASE_ONLY_WRONG_EFFECTIVE_SID:$EffectiveSid"
    }
    if ($AdministrativeToken) { throw 'PYTHON_BASE_ONLY_REFUSES_ADMINISTRATIVE_TOKEN' }
    if (-not (Test-PythonBaseOnlyExactPath $script:PythonBaseOnlyRoot 'C:\Program Files\AutomatonPython\3.14.5')) {
        throw 'PYTHON_BASE_ONLY_TARGET_PATH_MISMATCH'
    }

    $authorizedRoot = if ($Role -eq 'AutomatonGateway') {
        'C:\ProgramData\AutomatonMT5Lab\operational'
    } else { 'C:\Users\AutomatonAgent\.automaton' }
    $reportRoot = Join-Path $authorizedRoot 'acl-runtime-results'
    $roleStem = if ($Role -eq 'AutomatonGateway') { 'gateway' } else { 'agent' }
    $reportPath = Join-Path $reportRoot "$roleStem-python-base-$RunId.json"
    $context = [pscustomobject]@{
        tests = [ordered]@{}
        critical_unexpected_allow = $false
        infrastructure_error = $false
        filesystem_runtime_modified = $false
        runtime_error = $null
    }
    $tempPath = $null
    $tempCleanupSucceeded = $false
    try {
        Add-PythonBaseOnlyResult $context 'IDENTITY' $expectedSid $EffectiveSid 'EFFECTIVE_WINDOWS_TOKEN_SID'
        $tempPath = Initialize-PythonBaseOnlyPrivateTemp $reportRoot $authorizedRoot $RunId
        Initialize-PythonBaseOnlyNativeProbe
        if ($Role -eq 'AutomatonGateway') {
            Add-GatewayPythonBaseOnlyTests $context $RunId
        } else {
            Add-AgentPythonBaseOnlyTests $context $RunId
        }
    } catch {
        $context.infrastructure_error = $true
        $context.runtime_error = $_.Exception.GetType().FullName + ':' + $_.Exception.Message
    } finally {
        if ($null -ne $tempPath) {
            $tempCleanupSucceeded = Clear-PythonBaseOnlyPrivateTemp $tempPath $reportRoot
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
        mode = 'PYTHON_BASE_ONLY'
        role = $Role
        run_id = $RunId
        effective_sid = $EffectiveSid
        status = $status
        completed_at_utc = [DateTime]::UtcNow.ToString('o')
        runtime_error = $context.runtime_error
        tests = $context.tests
        boundaries = [ordered]@{
            trading_mode = 'OBSERVE_ONLY'
            build_venv = $false
            mt5_accessed = $false
            order_check_called = $false
            order_send_called = $false
            gateway_started = $false
            automaton_started = $false
            venv_accessed = $false
            venv_new_accessed = $false
            acl_modified = $false
            filesystem_runtime_modified = [bool]$context.filesystem_runtime_modified
            report_directory_modified = $true
            report_temp_cleanup_succeeded = $tempCleanupSucceeded
        }
    }
    Write-PythonBaseOnlyExclusiveReport $reportPath $report
    Write-PythonBaseOnlySummary $report $reportPath
    return [pscustomobject]@{
        status = $status
        exit_code = if ($status -eq 'PASS') { 0 } else { 1 }
        report_path = $reportPath
    }
}
