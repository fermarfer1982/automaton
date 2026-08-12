#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$normalizedRunId = $RunId.ToLowerInvariant()
$expectedAgentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$expectedGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$workspace = 'C:\automaton'
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$agentReportPath = "C:\Users\AutomatonAgent\.automaton\acl-runtime-results\agent-$normalizedRunId.json"
$gatewayReportPath = Join-Path $labRoot "operational\acl-runtime-results\gateway-$normalizedRunId.json"
$journalPath = Join-Path $labRoot 'audit\journal\audit.jsonl'
$securityLogPath = Join-Path $labRoot 'logs\security\security.log'
$configPath = Join-Path $labRoot 'control\trading.yaml'
$pythonExe = Join-Path $workspace '.venv\Scripts\python.exe'
if (-not $OutputPath) {
    $OutputPath = Join-Path $env:TEMP "automaton-runtime-acl-gate-$normalizedRunId.json"
}
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    throw 'OutputPath must be absolute.'
}

function Read-RuntimeReport([string] $Path, [string] $Role, [string] $ExpectedSid) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing $Role runtime report."
    }
    $item = Get-Item -LiteralPath $Path -Force
    $parentItem = Get-Item -LiteralPath $item.DirectoryName -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        ($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "$Role runtime report path cannot be a reparse point."
    }
    if ($item.Length -le 0 -or $item.Length -gt 1048576) {
        throw "$Role runtime report size is outside the accepted range."
    }
    $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ($raw -match '(?i)password|passwd|credential|api[_-]?key|private[_-]?key|secret') {
        throw "$Role runtime report contains a forbidden secret-related field."
    }
    $report = $raw | ConvertFrom-Json
    if ($report.schema_version -ne 1 -or $report.role -ne $Role) {
        throw "$Role runtime report schema or role is invalid."
    }
    if ($report.run_id -ne $normalizedRunId -or $report.effective_sid -ne $ExpectedSid) {
        throw "$Role runtime report identity binding is invalid."
    }
    return $report
}

function Get-Test([object] $Report, [string] $Name) {
    $property = $Report.tests.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "Runtime report is missing test $Name." }
    return $property.Value
}

function Assert-TestSet([object] $Report, [hashtable] $ExpectedTests) {
    foreach ($name in $ExpectedTests.Keys) {
        $test = Get-Test $Report $name
        if ($test.expected -ne $ExpectedTests[$name]) {
            throw "Runtime report test $name changed its expected result."
        }
    }
}

function Test-ObservedSet([object] $Report, [string[]] $Names, [string] $Expected) {
    foreach ($name in $Names) {
        $test = Get-Test $Report $name
        if (-not $test.passed -or $test.observed -ne $Expected) { return $false }
    }
    return $true
}

function Get-Sha256Hex([byte[]] $Bytes) {
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Test-AppendEvidence(
    [string] $Path,
    [object] $Evidence,
    [bool] $StructuredJournal
) {
    if ($null -eq $Evidence) {
        return [pscustomobject]@{ Valid = $false; PrefixIntact = $false; Detail = 'EVIDENCE_MISSING' }
    }
    try {
        $beforeSize = [int64]$Evidence.before_size
        $appendSize = [int64]$Evidence.append_size
        if ($beforeSize -lt 0 -or $appendSize -le 0) { throw 'INVALID_LENGTHS' }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.LongLength -ne ($beforeSize + $appendSize)) { throw 'FINAL_LENGTH_MISMATCH' }
        $prefix = [byte[]]::new($beforeSize)
        $tail = [byte[]]::new($appendSize)
        if ($beforeSize -gt 0) { [Array]::Copy($bytes, 0, $prefix, 0, $beforeSize) }
        [Array]::Copy($bytes, $beforeSize, $tail, 0, $appendSize)
        $prefixValid = (Get-Sha256Hex $prefix) -eq [string]$Evidence.before_sha256
        $tailValid = (Get-Sha256Hex $tail) -eq [string]$Evidence.append_sha256
        if (-not $prefixValid -or -not $tailValid) { throw 'PREFIX_OR_SUFFIX_HASH_MISMATCH' }
        if ($StructuredJournal) {
            $tailText = [System.Text.Encoding]::UTF8.GetString($tail)
            if (-not $tailText.EndsWith("`n") -or $tailText.IndexOf("`n") -ne ($tailText.Length - 1)) {
                throw 'JOURNAL_SUFFIX_NOT_ONE_JSONL_RECORD'
            }
            $record = $tailText.TrimEnd([char[]]"`r`n") | ConvertFrom-Json
            if ($record.event -ne 'runtime_acl_canary' -or
                $record.payload.purpose -ne 'runtime_acl_append_probe' -or
                $record.payload.run_id -ne $normalizedRunId -or
                $record.record_hash -ne $Evidence.record_hash) {
                throw 'JOURNAL_CANARY_BINDING_INVALID'
            }
        } else {
            $tailText = [System.Text.Encoding]::UTF8.GetString($tail)
            if (-not $tailText.Contains("RUNTIME_ACL_CANARY run_id=$normalizedRunId")) {
                throw 'SECURITY_CANARY_BINDING_INVALID'
            }
        }
        return [pscustomobject]@{ Valid = $true; PrefixIntact = $true; Detail = 'PREFIX_AND_EXACT_SUFFIX_VERIFIED' }
    } catch {
        return [pscustomobject]@{ Valid = $false; PrefixIntact = $false; Detail = $_.Exception.Message }
    }
}

function Test-JournalHashChain([string] $Path) {
    if (-not [System.IO.File]::Exists($pythonExe)) { return $false }
    $source = @'
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
previous_hash = "0" * 64
valid = True
records = 0
try:
    for raw_line in path.read_bytes().splitlines():
        if not raw_line.strip():
            continue
        record = json.loads(raw_line.decode("utf-8"))
        claimed_hash = record.pop("record_hash")
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        calculated = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if record.get("previous_hash") != previous_hash or calculated != claimed_hash:
            valid = False
            break
        previous_hash = claimed_hash
        records += 1
except Exception:
    valid = False
print(json.dumps({"valid": valid, "records": records}, sort_keys=True, separators=(",", ":")))
'@
    $output = @(& $pythonExe -I -c $source $Path 2>&1)
    if ($LASTEXITCODE -ne 0 -or $output.Count -eq 0) { return $false }
    try {
        $result = $output[-1] | ConvertFrom-Json
        return [bool]$result.valid
    } catch {
        return $false
    }
}

function Test-Boundaries([object] $Report) {
    foreach ($name in @(
        'mt5_accessed', 'automaton_started', 'gateway_started',
        'order_check_executed', 'order_send_executed',
        'demo_execution_enabled', 'trading_mode_changed'
    )) {
        $property = $Report.boundaries.PSObject.Properties[$name]
        if ($null -eq $property -or [bool]$property.Value) { return $false }
    }
    return $true
}

function Write-ExclusiveJsonReport([string] $Path, [object] $Value) {
    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
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

$agentExpected = @{
    IDENTITY = $expectedAgentSid
    RUNTIME_TEMP_PRIVATE = 'ALLOW'; RUNTIME_TEMP_CLEANUP = 'ALLOW'
    WORKSPACE_READ = 'ALLOW'; WORKSPACE_CREATE = 'DENY'; WORKSPACE_MODIFY_CODE = 'DENY'; WORKSPACE_DELETE_CODE = 'DENY'
    CONFIG_READ = 'DENY'; IPC_READ = 'ALLOW'; IPC_WRITE = 'DENY'; IPC_TRUNCATE = 'DENY'; IPC_DELETE = 'DENY'; IPC_CHANGE_ACL = 'DENY'
    OPERATIONAL_ACCESS = 'DENY'; RESEARCH_ACCESS = 'DENY'; AUDIT_SQLITE_ACCESS = 'DENY'; AUDIT_JOURNAL_ACCESS = 'DENY'; SECURITY_LOG_ACCESS = 'DENY'
    STATE_CREATE_WRITE_READ_DELETE = 'ALLOW'
    DEMO_AUTH_CREATE = 'DENY'; DEMO_AUTH_MODIFY = 'DENY'; DEMO_AUTH_DELETE = 'DENY'
    KILL_SWITCH_CREATE = 'DENY'; KILL_SWITCH_MODIFY = 'DENY'; KILL_SWITCH_DELETE = 'DENY'
}
$gatewayExpected = @{
    IDENTITY = $expectedGatewaySid
    RUNTIME_TEMP_PRIVATE = 'ALLOW'; RUNTIME_TEMP_CLEANUP = 'ALLOW'
    WORKSPACE_READ = 'ALLOW'; WORKSPACE_CREATE = 'DENY'; WORKSPACE_MODIFY_CODE = 'DENY'; WORKSPACE_DELETE_CODE = 'DENY'
    CONFIG_READ = 'ALLOW'; CONFIG_OBSERVE_ONLY = 'OBSERVE_ONLY'; CONFIG_WRITE = 'DENY'; CONFIG_TRUNCATE = 'DENY'; CONFIG_DELETE = 'DENY'; CONFIG_REPLACE = 'DENY'
    IPC_READ = 'ALLOW'; IPC_WRITE = 'DENY'; IPC_TRUNCATE = 'DENY'; IPC_DELETE = 'DENY'; IPC_REPLACE = 'DENY'; IPC_CHANGE_ACL = 'DENY'
    OPERATIONAL_MODIFY = 'ALLOW'; RESEARCH_MODIFY = 'ALLOW'; SQLITE_WAL = 'ALLOW'
    JOURNAL_APPEND = 'ALLOW'; JOURNAL_READ = 'ALLOW'; JOURNAL_OVERWRITE = 'DENY'; JOURNAL_TRUNCATE = 'DENY'; JOURNAL_CREATE_OVERWRITE = 'DENY'
    JOURNAL_DELETE = 'DENY'; JOURNAL_RENAME = 'DENY'; JOURNAL_REPLACE = 'DENY'; JOURNAL_CHANGE_ACL = 'DENY'
    SECURITY_APPEND = 'ALLOW'; SECURITY_OVERWRITE = 'DENY'; SECURITY_TRUNCATE = 'DENY'; SECURITY_DELETE = 'DENY'; SECURITY_RENAME = 'DENY'; SECURITY_REPLACE = 'DENY'
    AGENT_STATE_READ = 'DENY'; AGENT_STATE_WRITE = 'DENY'; DEMO_AUTH_READ = 'ALLOW'; DEMO_AUTH_CREATE = 'DENY'; DEMO_AUTH_MODIFY = 'DENY'; DEMO_AUTH_DELETE = 'DENY'
    KILL_SWITCH_DETECT = 'ALLOW'; KILL_SWITCH_CREATE = 'DENY'; KILL_SWITCH_MODIFY = 'DENY'; KILL_SWITCH_DELETE = 'DENY'
}

$agentReport = Read-RuntimeReport $agentReportPath 'AutomatonAgent' $expectedAgentSid
$gatewayReport = Read-RuntimeReport $gatewayReportPath 'AutomatonGateway' $expectedGatewaySid
Assert-TestSet $agentReport $agentExpected
Assert-TestSet $gatewayReport $gatewayExpected
$journalValidation = Test-AppendEvidence $journalPath $gatewayReport.journal_evidence $true
$securityValidation = Test-AppendEvidence $securityLogPath $gatewayReport.security_log_evidence $false
$journalChainValid = $journalValidation.Valid -and (Test-JournalHashChain $journalPath)
$configText = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
$observeOnly = $configText -match '(?m)^\s*trading_mode\s*:\s*OBSERVE_ONLY\s*$'
$boundariesValid = (Test-Boundaries $agentReport) -and (Test-Boundaries $gatewayReport)
$runningProcesses = @(Get-CimInstance Win32_Process)
$runningGatewayProcesses = @($runningProcesses | Where-Object {
    $_.CommandLine -match 'trading_lab\.service'
})
$runningAutomatonProcesses = @($runningProcesses | Where-Object {
    $_.CommandLine -match 'dist[\\/]index\.js.*--run'
})
$gatewayStopped = $runningGatewayProcesses.Count -eq 0
$automatonStopped = $runningAutomatonProcesses.Count -eq 0
$labProcessesStopped = $gatewayStopped -and $automatonStopped

$summary = [ordered]@{
    RUNTIME_ACL_GATE = 'FAIL'
    AGENT_IDENTITY = if ((Test-ObservedSet $agentReport @('IDENTITY') $expectedAgentSid)) { 'PASS' } else { 'FAIL' }
    AGENT_WORKSPACE_READ = if ((Test-ObservedSet $agentReport @('WORKSPACE_READ') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    AGENT_WORKSPACE_WRITE = if ((Test-ObservedSet $agentReport @('WORKSPACE_CREATE','WORKSPACE_MODIFY_CODE','WORKSPACE_DELETE_CODE') 'DENY')) { 'DENY' } else { 'FAIL' }
    AGENT_CONFIG_READ = if ((Test-ObservedSet $agentReport @('CONFIG_READ') 'DENY')) { 'DENY' } else { 'FAIL' }
    AGENT_IPC_READ = if ((Test-ObservedSet $agentReport @('IPC_READ') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    AGENT_IPC_WRITE = if ((Test-ObservedSet $agentReport @('IPC_WRITE','IPC_TRUNCATE','IPC_DELETE','IPC_CHANGE_ACL') 'DENY')) { 'DENY' } else { 'FAIL' }
    AGENT_OPERATIONAL_ACCESS = if ((Test-ObservedSet $agentReport @('OPERATIONAL_ACCESS') 'DENY')) { 'DENY' } else { 'FAIL' }
    AGENT_RESEARCH_ACCESS = if ((Test-ObservedSet $agentReport @('RESEARCH_ACCESS') 'DENY')) { 'DENY' } else { 'FAIL' }
    AGENT_AUDIT_ACCESS = if ((Test-ObservedSet $agentReport @('AUDIT_SQLITE_ACCESS','AUDIT_JOURNAL_ACCESS') 'DENY')) { 'DENY' } else { 'FAIL' }
    AGENT_SECURITY_LOG_ACCESS = if ((Test-ObservedSet $agentReport @('SECURITY_LOG_ACCESS') 'DENY')) { 'DENY' } else { 'FAIL' }
    AGENT_STATE_MODIFY = if ((Test-ObservedSet $agentReport @('STATE_CREATE_WRITE_READ_DELETE') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    AGENT_DEMO_AUTH_WRITE = if ((Test-ObservedSet $agentReport @('DEMO_AUTH_CREATE','DEMO_AUTH_MODIFY','DEMO_AUTH_DELETE') 'DENY')) { 'DENY' } else { 'FAIL' }
    AGENT_KILL_SWITCH_WRITE = if ((Test-ObservedSet $agentReport @('KILL_SWITCH_CREATE','KILL_SWITCH_MODIFY','KILL_SWITCH_DELETE') 'DENY')) { 'DENY' } else { 'FAIL' }
    GATEWAY_IDENTITY = if ((Test-ObservedSet $gatewayReport @('IDENTITY') $expectedGatewaySid)) { 'PASS' } else { 'FAIL' }
    GATEWAY_WORKSPACE_READ = if ((Test-ObservedSet $gatewayReport @('WORKSPACE_READ') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    GATEWAY_WORKSPACE_WRITE = if ((Test-ObservedSet $gatewayReport @('WORKSPACE_CREATE','WORKSPACE_MODIFY_CODE','WORKSPACE_DELETE_CODE') 'DENY')) { 'DENY' } else { 'FAIL' }
    GATEWAY_CONFIG_READ = if ((Test-ObservedSet $gatewayReport @('CONFIG_READ') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    GATEWAY_CONFIG_WRITE = if ((Test-ObservedSet $gatewayReport @('CONFIG_WRITE','CONFIG_TRUNCATE','CONFIG_DELETE','CONFIG_REPLACE') 'DENY')) { 'DENY' } else { 'FAIL' }
    GATEWAY_IPC_READ = if ((Test-ObservedSet $gatewayReport @('IPC_READ') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    GATEWAY_IPC_WRITE = if ((Test-ObservedSet $gatewayReport @('IPC_WRITE','IPC_TRUNCATE','IPC_DELETE','IPC_REPLACE','IPC_CHANGE_ACL') 'DENY')) { 'DENY' } else { 'FAIL' }
    GATEWAY_OPERATIONAL_MODIFY = if ((Test-ObservedSet $gatewayReport @('OPERATIONAL_MODIFY') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    GATEWAY_RESEARCH_MODIFY = if ((Test-ObservedSet $gatewayReport @('RESEARCH_MODIFY') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    GATEWAY_SQLITE_WAL = if ((Test-ObservedSet $gatewayReport @('SQLITE_WAL') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    AUDIT_JOURNAL_APPEND = if ((Test-ObservedSet $gatewayReport @('JOURNAL_APPEND') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    AUDIT_JOURNAL_PREFIX_INTACT = if ($journalChainValid) { 'PASS' } else { 'FAIL' }
    AUDIT_JOURNAL_OVERWRITE = if ((Test-ObservedSet $gatewayReport @('JOURNAL_OVERWRITE','JOURNAL_CREATE_OVERWRITE') 'DENY')) { 'DENY' } else { 'FAIL' }
    AUDIT_JOURNAL_TRUNCATE = if ((Test-ObservedSet $gatewayReport @('JOURNAL_TRUNCATE') 'DENY')) { 'DENY' } else { 'FAIL' }
    AUDIT_JOURNAL_DELETE = if ((Test-ObservedSet $gatewayReport @('JOURNAL_DELETE') 'DENY')) { 'DENY' } else { 'FAIL' }
    AUDIT_JOURNAL_RENAME = if ((Test-ObservedSet $gatewayReport @('JOURNAL_RENAME') 'DENY')) { 'DENY' } else { 'FAIL' }
    AUDIT_JOURNAL_REPLACE = if ((Test-ObservedSet $gatewayReport @('JOURNAL_REPLACE') 'DENY')) { 'DENY' } else { 'FAIL' }
    AUDIT_JOURNAL_CHANGE_ACL = if ((Test-ObservedSet $gatewayReport @('JOURNAL_CHANGE_ACL') 'DENY')) { 'DENY' } else { 'FAIL' }
    SECURITY_LOG_APPEND = if ((Test-ObservedSet $gatewayReport @('SECURITY_APPEND') 'ALLOW')) { 'ALLOW' } else { 'FAIL' }
    SECURITY_LOG_OVERWRITE = if ((Test-ObservedSet $gatewayReport @('SECURITY_OVERWRITE') 'DENY')) { 'DENY' } else { 'FAIL' }
    SECURITY_LOG_TRUNCATE = if ((Test-ObservedSet $gatewayReport @('SECURITY_TRUNCATE') 'DENY')) { 'DENY' } else { 'FAIL' }
    SECURITY_LOG_DELETE = if ((Test-ObservedSet $gatewayReport @('SECURITY_DELETE') 'DENY')) { 'DENY' } else { 'FAIL' }
    SECURITY_LOG_REPLACE = if ((Test-ObservedSet $gatewayReport @('SECURITY_RENAME','SECURITY_REPLACE') 'DENY')) { 'DENY' } else { 'FAIL' }
    GATEWAY_AGENT_STATE_ACCESS = if ((Test-ObservedSet $gatewayReport @('AGENT_STATE_READ','AGENT_STATE_WRITE') 'DENY')) { 'DENY' } else { 'FAIL' }
    GATEWAY_DEMO_AUTH_WRITE = if ((Test-ObservedSet $gatewayReport @('DEMO_AUTH_CREATE','DEMO_AUTH_MODIFY','DEMO_AUTH_DELETE') 'DENY')) { 'DENY' } else { 'FAIL' }
    GATEWAY_KILL_SWITCH_WRITE = if ((Test-ObservedSet $gatewayReport @('KILL_SWITCH_CREATE','KILL_SWITCH_MODIFY','KILL_SWITCH_DELETE') 'DENY')) { 'DENY' } else { 'FAIL' }
    MT5_ACCESSED = $false
    AUTOMATON_STARTED = -not $automatonStopped
    GATEWAY_STARTED = -not $gatewayStopped
    ORDER_CHECK_EXECUTED = $false
    ORDER_SEND_EXECUTED = $false
    DEMO_EXECUTION_ENABLED = $false
    TRADING_MODE = if ($observeOnly) { 'OBSERVE_ONLY' } else { 'INVALID' }
}

$gatePassed = $agentReport.status -eq 'PASS' -and
    $gatewayReport.status -eq 'PASS' -and
    $journalValidation.Valid -and $journalChainValid -and
    $securityValidation.Valid -and $boundariesValid -and
    $labProcessesStopped -and $observeOnly
foreach ($property in $summary.GetEnumerator()) {
    if ($property.Key -eq 'RUNTIME_ACL_GATE' -or $property.Key -in @(
        'MT5_ACCESSED','AUTOMATON_STARTED','GATEWAY_STARTED','ORDER_CHECK_EXECUTED',
        'ORDER_SEND_EXECUTED','DEMO_EXECUTION_ENABLED','TRADING_MODE'
    )) { continue }
    if ($property.Value -eq 'FAIL') { $gatePassed = $false }
}
$summary.RUNTIME_ACL_GATE = if ($gatePassed) { 'PASS' } else { 'FAIL' }
$finalReport = [ordered]@{
    schema_version = 1
    run_id = $normalizedRunId
    collected_at_utc = [DateTime]::UtcNow.ToString('o')
    summary = $summary
    validation = [ordered]@{
        agent_report_status = $agentReport.status
        gateway_report_status = $gatewayReport.status
        journal_prefix_and_suffix = $journalValidation.Detail
        journal_hash_chain_valid = $journalChainValid
        security_log_prefix_and_suffix = $securityValidation.Detail
        runtime_boundaries_valid = $boundariesValid
        lab_processes_stopped = $labProcessesStopped
    }
}
Write-ExclusiveJsonReport $OutputPath $finalReport
foreach ($property in $summary.GetEnumerator()) {
    Write-Output "$($property.Key)=$($property.Value)"
}
Write-Output "RUNTIME_ACL_REPORT=$OutputPath"
if (-not $gatePassed) { exit 1 }
