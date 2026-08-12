[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId
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

if (-not ('Automaton.RuntimeAcl.GatewayNativeMethods' -as [type])) {
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
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$controlPath = Join-Path $labRoot 'control'
$configPath = Join-Path $controlPath 'trading.yaml'
$demoAuthorizationPath = Join-Path $controlPath 'demo-authorization'
$demoAuthorizationFile = Join-Path $demoAuthorizationPath 'authorization.json'
$killSwitchPath = Join-Path $controlPath 'STOP_TRADING'
$ipcPath = Join-Path $labRoot 'ipc'
$ipcKeyPath = Join-Path $ipcPath 'automaton.key'
$operationalPath = Join-Path $labRoot 'operational'
$researchPath = Join-Path $labRoot 'research'
$auditSqlitePath = Join-Path $labRoot 'audit\sqlite'
$auditJournalPath = Join-Path $labRoot 'audit\journal\audit.jsonl'
$securityLogPath = Join-Path $labRoot 'logs\security\security.log'
$agentStatePath = 'C:\Users\AutomatonAgent\.automaton'
$normalizedRunId = $RunId.ToLowerInvariant()
$reportPath = Join-Path $operationalPath "acl-runtime-results\gateway-$normalizedRunId.json"
$tests = [ordered]@{}
$journalEvidence = $null
$securityLogEvidence = $null
$criticalFail = $false
$runtimeError = $null

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
}

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
            try { [System.IO.File]::Delete($Path) } catch {}
        }
    }
}

function Add-MutableDirectoryCanaryTest([string] $Name, [string] $Directory) {
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
    } finally {
        foreach ($candidate in @($first, $renamed)) {
            try { if ([System.IO.File]::Exists($candidate)) { [System.IO.File]::Delete($candidate) } } catch {}
        }
    }
}

function Invoke-LocalPythonJson([string] $Source, [string[]] $Arguments) {
    if (-not [System.IO.File]::Exists($pythonExe)) {
        return [pscustomobject]@{ Success = $false; Evidence = 'PINNED_LOCAL_PYTHON_NOT_FOUND'; Value = $null }
    }
    $output = @(& $pythonExe -I -c $Source @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or $output.Count -eq 0) {
        return [pscustomobject]@{ Success = $false; Evidence = "PYTHON_EXIT_$exitCode"; Value = $null }
    }
    try {
        $value = ($output[-1] | ConvertFrom-Json)
        return [pscustomobject]@{ Success = $true; Evidence = 'LOCAL_PYTHON_COMPLETED'; Value = $value }
    } catch {
        return [pscustomobject]@{ Success = $false; Evidence = 'PYTHON_OUTPUT_INVALID'; Value = $null }
    }
}

function Add-SqliteWalCanaryTest {
    $databasePath = Join-Path $auditSqlitePath "runtime-acl-$normalizedRunId.db"
    $source = @'
import json
import pathlib
import sqlite3
import sys

path = pathlib.Path(sys.argv[1])
artifacts = [path, pathlib.Path(str(path) + "-wal"), pathlib.Path(str(path) + "-shm")]
if any(item.exists() for item in artifacts):
    raise RuntimeError("CANARY_ALREADY_EXISTS")
connection = None
try:
    connection = sqlite3.connect(path)
    mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    connection.execute("CREATE TABLE canary (value TEXT NOT NULL)")
    connection.execute("INSERT INTO canary(value) VALUES (?)", ("runtime-acl",))
    connection.commit()
    wal_seen = pathlib.Path(str(path) + "-wal").is_file()
    shm_seen = pathlib.Path(str(path) + "-shm").is_file()
    value = connection.execute("SELECT value FROM canary").fetchone()[0]
    result = {"mode": mode, "wal_seen": wal_seen, "shm_seen": shm_seen, "read_back": value == "runtime-acl"}
finally:
    if connection is not None:
        connection.close()
    cleanup = True
    for item in artifacts:
        try:
            if item.exists():
                item.unlink()
        except OSError:
            cleanup = False
if not cleanup:
    raise RuntimeError("CANARY_CLEANUP_FAILED")
result["cleanup"] = True
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'@
    $invocation = Invoke-LocalPythonJson $source @($databasePath)
    if (-not $invocation.Success) {
        Add-TestResult 'SQLITE_WAL' 'ALLOW' 'ERROR' $invocation.Evidence
        return
    }
    $value = $invocation.Value
    if ($value.mode -eq 'wal' -and $value.wal_seen -and $value.shm_seen -and $value.read_back -and $value.cleanup) {
        Add-TestResult 'SQLITE_WAL' 'ALLOW' 'ALLOW' 'DB_WAL_SHM_COMMIT_READ_CLEANUP_SUCCEEDED'
    } else {
        Add-TestResult 'SQLITE_WAL' 'ALLOW' 'ERROR' 'SQLITE_WAL_INCOMPLETE'
    }
}

function Add-AuditJournalAppendTest {
    $source = @'
import datetime
import hashlib
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
run_id = sys.argv[2]
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
    $invocation = Invoke-LocalPythonJson $source @($auditJournalPath, $normalizedRunId)
    if ($invocation.Success) {
        $script:journalEvidence = $invocation.Value
        Add-TestResult 'JOURNAL_APPEND' 'ALLOW' 'ALLOW' 'CPYTHON_APPEND_FLUSH_FSYNC_SUCCEEDED'
    } else {
        Add-TestResult 'JOURNAL_APPEND' 'ALLOW' 'ERROR' $invocation.Evidence
    }
}

function Add-SecurityLogAppendTest {
    $source = @'
import hashlib
import json
import logging
import os
import pathlib
import sys
import time

path = pathlib.Path(sys.argv[1])
run_id = sys.argv[2]
before = path.read_bytes()
logger = logging.getLogger("automaton.runtime_acl_canary." + run_id)
logger.setLevel(logging.WARNING)
logger.propagate = False
handler = logging.FileHandler(path, mode="a", encoding="utf-8")
formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
formatter.converter = time.gmtime
handler.setFormatter(formatter)
try:
    logger.addHandler(handler)
    logger.warning("RUNTIME_ACL_CANARY run_id=%s", run_id)
    handler.flush()
    os.fsync(handler.stream.fileno())
finally:
    logger.removeHandler(handler)
    handler.close()
after = path.read_bytes()
if after[:len(before)] != before or len(after) <= len(before):
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
    $invocation = Invoke-LocalPythonJson $source @($securityLogPath, $normalizedRunId)
    if ($invocation.Success) {
        $script:securityLogEvidence = $invocation.Value
        Add-TestResult 'SECURITY_APPEND' 'ALLOW' 'ALLOW' 'PYTHON_FILEHANDLER_APPEND_FLUSH_FSYNC_SUCCEEDED'
    } else {
        Add-TestResult 'SECURITY_APPEND' 'ALLOW' 'ERROR' $invocation.Evidence
    }
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

try {
    Add-TestResult 'IDENTITY' $expectedSid $effectiveSid 'EFFECTIVE_WINDOWS_TOKEN_SID'
    Add-AllowedFileReadTest 'WORKSPACE_READ' (Join-Path $workspace 'package.json') $true
    Add-DeniedCanaryCreateTest 'WORKSPACE_CREATE' (Join-Path $workspace ".acl-runtime-$normalizedRunId.canary")
    Add-DeniedRightTest 'WORKSPACE_MODIFY_CODE' (Join-Path $workspace 'package.json') $FILE_WRITE_DATA $false $false
    Add-DeniedRightTest 'WORKSPACE_DELETE_CODE' (Join-Path $workspace 'package.json') $DELETE $false $false

    Add-AllowedFileReadTest 'CONFIG_READ' $configPath $true
    $configText = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
    if ($configText -notmatch '(?m)^\s*trading_mode\s*:\s*OBSERVE_ONLY\s*$') {
        Add-TestResult 'CONFIG_OBSERVE_ONLY' 'OBSERVE_ONLY' 'ERROR' 'CONFIG_MODE_NOT_OBSERVE_ONLY'
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
    Add-DeniedRightTest 'SECURITY_REPLACE' (Split-Path $securityLogPath -Parent) $FILE_ADD_FILE $true $true

    Add-DeniedRightTest 'AGENT_STATE_READ' $agentStatePath $FILE_LIST_DIRECTORY $true $false
    Add-DeniedRightTest 'AGENT_STATE_WRITE' $agentStatePath $FILE_ADD_FILE $true $false

    $demoRead = Invoke-NativeAccessProbe $demoAuthorizationPath $FILE_LIST_DIRECTORY $true
    if ($demoRead.Allowed) {
        Add-TestResult 'DEMO_AUTH_READ' 'ALLOW' 'ALLOW' 'DIRECTORY_READ_RIGHT_GRANTED'
    } elseif ($demoRead.ErrorCode -eq 5) {
        Add-TestResult 'DEMO_AUTH_READ' 'ALLOW' 'DENY' 'WIN32_ACCESS_DENIED'
    } else {
        Add-TestResult 'DEMO_AUTH_READ' 'ALLOW' 'ERROR' "WIN32_ERROR_$($demoRead.ErrorCode)"
    }
    Add-DeniedRightTest 'DEMO_AUTH_CREATE' $demoAuthorizationPath $FILE_ADD_FILE $true $false
    if ([System.IO.File]::Exists($demoAuthorizationFile)) {
        Add-DeniedRightTest 'DEMO_AUTH_MODIFY' $demoAuthorizationFile $FILE_WRITE_DATA $false $false
        Add-DeniedRightTest 'DEMO_AUTH_DELETE' $demoAuthorizationFile $DELETE $false $false
    } else {
        Add-DeniedRightTest 'DEMO_AUTH_MODIFY' $demoAuthorizationPath $FILE_ADD_FILE $true $false
        Add-DeniedRightTest 'DEMO_AUTH_DELETE' $demoAuthorizationPath $FILE_DELETE_CHILD $true $false
    }

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
    $runtimeError = if ($criticalFail) { 'CRITICAL_PROTECTED_RIGHT_GRANTED' } else { $_.Exception.GetType().Name }
}

$allPassed = -not $criticalFail -and $null -eq $runtimeError
foreach ($test in $tests.Values) {
    if (-not $test.passed) { $allPassed = $false }
}
$status = if ($criticalFail) { 'CRITICAL_FAIL' } elseif ($allPassed) { 'PASS' } else { 'FAIL' }
$report = [ordered]@{
    schema_version = 1
    role = 'AutomatonGateway'
    run_id = $normalizedRunId
    effective_sid = $effectiveSid
    status = $status
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    runtime_error = $runtimeError
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
if (-not $allPassed) { exit 1 }
