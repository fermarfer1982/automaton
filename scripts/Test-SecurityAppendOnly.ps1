[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$normalizedRunId = $RunId.ToLowerInvariant()
$workspace = 'C:\automaton'
$pythonExe = 'C:\automaton\.venv\Scripts\python.exe'
$securityDirectory = 'C:\ProgramData\AutomatonMT5Lab\logs\security'
$securityLog = 'C:\ProgramData\AutomatonMT5Lab\logs\security\security.log'
$reportPath = Join-Path (
    'C:\ProgramData\AutomatonMT5Lab\operational\acl-runtime-results'
) "security-append-$normalizedRunId.json"
$expectedSid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$process = $null
$report = [ordered]@{
    schema_version = 1
    mode = 'SECURITY_APPEND_ONLY'
    run_id = $normalizedRunId
    status = 'FAIL_INITIALIZING'
    identity = $null
    SECURITY_APPEND = 'NOT_RUN'
    SECURITY_WRITE_DATA = 'NOT_RUN'
    SECURITY_TRUNCATE = 'NOT_RUN'
    SECURITY_DELETE = 'NOT_RUN'
    SECURITY_RENAME = 'NOT_RUN'
    SECURITY_CREATE_OTHER = 'NOT_RUN'
    runtime_error = $null
    boundaries = [ordered]@{
        trading_mode = 'OBSERVE_ONLY'
        mt5_imported = $false
        mt5_accessed = $false
        order_check_called = $false
        order_send_called = $false
        gateway_started = $false
        automaton_started = $false
        acl_modified = $false
        security_log_appended = $false
        security_directory_other_files_modified = $false
    }
}

function Assert-ExactNonReparsePath([string] $Path, [bool] $Directory) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Protected probe path is a reparse point: $Path"
    }
    if ($Directory -and -not $item.PSIsContainer) {
        throw "Expected directory is not a directory: $Path"
    }
    if (-not $Directory -and $item.PSIsContainer) {
        throw "Expected file is not a file: $Path"
    }
    if ([System.IO.Path]::GetFullPath($item.FullName) -ne $Path) {
        throw "Protected probe path is not exact: $Path"
    }
}

function ConvertTo-SafeError([object] $Value) {
    if ($null -eq $Value) { return $null }
    $safe = [string]$Value
    $safe = [regex]::Replace(
        $safe,
        '(?i)(password|passwd|credential|api[_-]?key|ipc[_-]?key|secret|token)\s*[:=]\s*[^\s,;]+',
        '$1=[REDACTED]'
    )
    if ($safe.Length -gt 2048) {
        $safe = $safe.Substring(0, 2048) + '...[TRUNCATED]'
    }
    return $safe
}

function Write-ExclusiveReport([string] $Path, [object] $Value) {
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [System.IO.Directory]::Exists($parent)) {
        throw "Pre-created report directory is missing: $parent"
    }
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new(
            $stream, [System.Text.UTF8Encoding]::new($false)
        )
        try {
            $writer.Write(($Value | ConvertTo-Json -Depth 8))
            $writer.Flush()
        } finally {
            $writer.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $effectiveSid = $identity.User.Value
    $report.identity = $effectiveSid
    if ($effectiveSid -ne $expectedSid) {
        throw "Wrong runtime identity. Expected SID $expectedSid; received $effectiveSid."
    }
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw 'Security append probe refuses an administrative token.'
    }

    Assert-ExactNonReparsePath $workspace $true
    Assert-ExactNonReparsePath $pythonExe $false
    Assert-ExactNonReparsePath $securityDirectory $true
    Assert-ExactNonReparsePath $securityLog $false

    $source = @'
import ctypes
import json
import logging
import pathlib
import sys
from ctypes import wintypes

workspace = pathlib.Path(r"C:\automaton")
security_directory = pathlib.Path(r"C:\ProgramData\AutomatonMT5Lab\logs\security")
security_log = security_directory / "security.log"
run_id = sys.argv[1]
sys.path.insert(0, str(workspace))
from trading_lab.windows_append_log import WindowsAppendOnlyFileHandler

FILE_LIST_DIRECTORY = 0x0001
FILE_WRITE_DATA = 0x0002
FILE_ADD_FILE = 0x0002
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000
SHARE_ALL = 0x00000007
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_ACCESS_DENIED = 5

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
create_file = kernel32.CreateFileW
create_file.argtypes = (
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
)
create_file.restype = wintypes.HANDLE
close_handle = kernel32.CloseHandle
close_handle.argtypes = (wintypes.HANDLE,)
close_handle.restype = wintypes.BOOL


def required_right_is_denied(path, access, directory=False):
    ctypes.set_last_error(0)
    handle = create_file(
        str(path),
        access,
        SHARE_ALL,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS if directory else FILE_ATTRIBUTE_NORMAL,
        None,
    )
    value = handle if isinstance(handle, int) else ctypes.cast(handle, ctypes.c_void_p).value
    if value == INVALID_HANDLE_VALUE:
        error_code = ctypes.get_last_error()
        return error_code == ERROR_ACCESS_DENIED, error_code
    close_handle(handle)
    return False, 0


before = security_log.read_bytes()
marker = "SECURITY_APPEND_PROBE " + run_id
logger = logging.getLogger("automaton.security_append_probe." + run_id)
logger.setLevel(logging.WARNING)
logger.propagate = False
handler = WindowsAppendOnlyFileHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
try:
    logger.addHandler(handler)
    logger.warning(marker)
finally:
    logger.removeHandler(handler)
    handler.close()
after = security_log.read_bytes()
expected_suffix = (marker + "\n").encode("utf-8")
append_pass = after[:len(before)] == before and after[len(before):] == expected_suffix

write_denied, write_error = required_right_is_denied(security_log, FILE_WRITE_DATA | SYNCHRONIZE)
# Truncation requires FILE_WRITE_DATA. Probe the exact required right without
# risking destructive truncation if the protected ACL has regressed.
truncate_denied, truncate_error = required_right_is_denied(security_log, FILE_WRITE_DATA | SYNCHRONIZE)
delete_denied, delete_error = required_right_is_denied(security_log, DELETE | SYNCHRONIZE)
rename_denied, rename_error = required_right_is_denied(security_log, DELETE | SYNCHRONIZE)
create_denied, create_error = required_right_is_denied(
    security_directory,
    FILE_LIST_DIRECTORY | FILE_ADD_FILE | SYNCHRONIZE,
    directory=True,
)

result = {
    "SECURITY_APPEND": "PASS" if append_pass else "FAIL",
    "SECURITY_WRITE_DATA": "DENIED" if write_denied else "CRITICAL_UNEXPECTED_ALLOW",
    "SECURITY_TRUNCATE": "DENIED" if truncate_denied else "CRITICAL_UNEXPECTED_ALLOW",
    "SECURITY_DELETE": "DENIED" if delete_denied else "CRITICAL_UNEXPECTED_ALLOW",
    "SECURITY_RENAME": "DENIED" if rename_denied else "CRITICAL_UNEXPECTED_ALLOW",
    "SECURITY_CREATE_OTHER": "DENIED" if create_denied else "CRITICAL_UNEXPECTED_ALLOW",
    "native_errors": {
        "write_data": write_error,
        "truncate": truncate_error,
        "delete": delete_error,
        "rename": rename_error,
        "create_other": create_error,
    },
    "mt5_imported": "MetaTrader5" in sys.modules,
}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'@

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pythonExe
    $startInfo.Arguments = '-B - ' + $normalizedRunId
    $startInfo.WorkingDirectory = $workspace
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'Python probe process did not start.' }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write($source)
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(30000)) {
        $process.Kill()
        [void]$process.WaitForExit(5000)
        throw 'Python probe process did not exit within 30 seconds.'
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
        throw "Python probe failed with exit code $($process.ExitCode): $(ConvertTo-SafeError $stderr)"
    }
    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        throw "Python probe emitted unexpected stderr: $(ConvertTo-SafeError $stderr)"
    }
    $result = $stdout.Trim() | ConvertFrom-Json
    foreach ($name in @(
        'SECURITY_APPEND', 'SECURITY_WRITE_DATA', 'SECURITY_TRUNCATE',
        'SECURITY_DELETE', 'SECURITY_RENAME', 'SECURITY_CREATE_OTHER'
    )) {
        $report[$name] = $result.$name
    }
    $report.boundaries.security_log_appended = $result.SECURITY_APPEND -eq 'PASS'
    $report.boundaries.mt5_imported = [bool]$result.mt5_imported
    $allPass = (
        $result.SECURITY_APPEND -eq 'PASS' -and
        $result.SECURITY_WRITE_DATA -eq 'DENIED' -and
        $result.SECURITY_TRUNCATE -eq 'DENIED' -and
        $result.SECURITY_DELETE -eq 'DENIED' -and
        $result.SECURITY_RENAME -eq 'DENIED' -and
        $result.SECURITY_CREATE_OTHER -eq 'DENIED' -and
        -not $result.mt5_imported
    )
    $report.status = if ($allPass) { 'PASS' } else { 'CRITICAL_FAIL' }
} catch {
    $report.status = 'FAIL'
    $report.runtime_error = ConvertTo-SafeError $_.Exception.Message
} finally {
    if ($null -ne $process) { $process.Dispose() }
    Write-ExclusiveReport $reportPath $report
}

$report | ConvertTo-Json -Depth 8
if ($report.status -ne 'PASS') { exit 1 }
