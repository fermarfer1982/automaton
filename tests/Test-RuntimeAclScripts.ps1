[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$agentPath = Join-Path $workspace 'scripts\Test-AgentRuntimeAcl.ps1'
$gatewayPath = Join-Path $workspace 'scripts\Test-GatewayRuntimeAcl.ps1'
$collectorPath = Join-Path $workspace 'scripts\Collect-RuntimeAclResults.ps1'
$paths = @($agentPath, $gatewayPath, $collectorPath)

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

$sources = @{}
foreach ($path in $paths) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$tokens, [ref]$parseErrors
    )
    Assert-True ($parseErrors.Count -eq 0) "Runtime ACL script has AST errors: $path"
    $source = [System.IO.File]::ReadAllText($path)
    $sources[$path] = $source
    foreach ($forbidden in @(
        'Get-Credential', 'ConvertFrom-SecureString', 'Start-Process',
        'runas.exe', 'PsExec', 'Register-ScheduledTask', 'schtasks',
        'New-Service', 'Add-LocalGroupMember', 'Set-LocalUser',
        'Remove-LocalUser', 'Set-Acl', 'icacls', 'takeown',
        'Invoke-WebRequest', 'Invoke-RestMethod', 'HttpClient',
        'TcpClient', 'UdpClient', 'import MetaTrader5', '.order_send(',
        '.order_check(', 'DEMO_EXECUTION_ENABLED=true'
    )) {
        Assert-True (-not $source.Contains($forbidden)) "Forbidden runtime action in $path`: $forbidden"
    }
}

$agent = $sources[$agentPath]
$gateway = $sources[$gatewayPath]
$collector = $sources[$collectorPath]

Assert-True `
    ($agent.Contains('S-1-5-21-568964486-193631783-1609210587-1006')) `
    'Agent script is not bound to the exact authorized SID.'
Assert-True `
    ($gateway.Contains('S-1-5-21-568964486-193631783-1609210587-1007')) `
    'Gateway script is not bound to the exact authorized SID.'
foreach ($source in @($agent, $gateway)) {
    Assert-True `
        ($source.Contains("mt5_accessed = `$false")) `
        'Runtime boundary report must record mt5_accessed=false.'
    Assert-True `
        ($source.Contains("order_send_executed = `$false")) `
        'Runtime boundary report must record order_send_executed=false.'
    Assert-True `
        ($source.Contains("demo_execution_enabled = `$false")) `
        'Runtime boundary report must record demo_execution_enabled=false.'
    Assert-True `
        ($source.IndexOf('if ($effectiveSid -ne $expectedSid)') -lt $source.IndexOf("`$workspace =")) `
        'Runtime identity must be validated before filesystem probes.'
    Assert-True `
        ($source.Contains('refuse an administrative token')) `
        'Runtime scripts must reject elevated service-identity tokens.'
    Assert-True `
        ($source.Contains('[System.IO.FileMode]::CreateNew')) `
        'Runtime reports and safe canaries must not overwrite prior files.'
    Assert-True `
        (-not $source.Contains('[System.IO.FileMode]::Truncate')) `
        'Runtime scripts must never invoke destructive truncate mode.'
    Assert-True `
        (-not $source.Contains('[System.IO.FileMode]::Create,')) `
        'Runtime scripts must never invoke destructive create/overwrite mode.'
}

foreach ($required in @(
    'WORKSPACE_READ', 'WORKSPACE_CREATE', 'WORKSPACE_MODIFY_CODE', 'WORKSPACE_DELETE_CODE',
    'CONFIG_READ', 'IPC_READ', 'IPC_WRITE', 'IPC_TRUNCATE', 'IPC_DELETE', 'IPC_CHANGE_ACL',
    'OPERATIONAL_ACCESS', 'RESEARCH_ACCESS', 'AUDIT_SQLITE_ACCESS', 'AUDIT_JOURNAL_ACCESS',
    'SECURITY_LOG_ACCESS', 'STATE_CREATE_WRITE_READ_DELETE',
    'DEMO_AUTH_CREATE', 'DEMO_AUTH_MODIFY', 'DEMO_AUTH_DELETE',
    'KILL_SWITCH_CREATE', 'KILL_SWITCH_MODIFY', 'KILL_SWITCH_DELETE'
)) {
    Assert-True ($agent.Contains("'$required'")) "Agent runtime test missing case: $required"
}
Assert-True `
    ($agent.Contains('READ_SUCCEEDED_CONTENT_NOT_REPORTED')) `
    'Agent IPC read must report success without key content.'
Assert-True `
    (-not $agent.Contains('ReadAllText($ipcKeyPath')) `
    'Agent script must not materialize the IPC key as text.'

foreach ($required in @(
    'WORKSPACE_READ', 'WORKSPACE_CREATE', 'WORKSPACE_MODIFY_CODE', 'WORKSPACE_DELETE_CODE',
    'CONFIG_READ', 'CONFIG_OBSERVE_ONLY', 'CONFIG_WRITE', 'CONFIG_TRUNCATE', 'CONFIG_DELETE', 'CONFIG_REPLACE',
    'IPC_READ', 'IPC_WRITE', 'IPC_TRUNCATE', 'IPC_DELETE', 'IPC_REPLACE', 'IPC_CHANGE_ACL',
    'OPERATIONAL_MODIFY', 'RESEARCH_MODIFY', 'SQLITE_WAL',
    'JOURNAL_APPEND', 'JOURNAL_READ', 'JOURNAL_OVERWRITE', 'JOURNAL_TRUNCATE',
    'JOURNAL_CREATE_OVERWRITE', 'JOURNAL_DELETE', 'JOURNAL_RENAME', 'JOURNAL_REPLACE', 'JOURNAL_CHANGE_ACL',
    'SECURITY_APPEND', 'SECURITY_OVERWRITE', 'SECURITY_TRUNCATE', 'SECURITY_DELETE', 'SECURITY_RENAME', 'SECURITY_REPLACE',
    'AGENT_STATE_READ', 'AGENT_STATE_WRITE', 'DEMO_AUTH_READ', 'DEMO_AUTH_CREATE', 'DEMO_AUTH_MODIFY', 'DEMO_AUTH_DELETE',
    'KILL_SWITCH_DETECT', 'KILL_SWITCH_CREATE', 'KILL_SWITCH_MODIFY', 'KILL_SWITCH_DELETE'
)) {
    Assert-True ($gateway.Contains("'$required'")) "Gateway runtime test missing case: $required"
}
foreach ($required in @(
    'sqlite3.connect', 'PRAGMA journal_mode=WAL', '"-wal"', '"-shm"',
    'path.open("a", encoding="utf-8", newline="\n")', 'handle.flush()',
    'os.fsync(handle.fileno())', 'logging.FileHandler(path, mode="a", encoding="utf-8")',
    'CRITICAL_FAIL:', 'PROTECTED_RIGHT_GRANTED_NO_MUTATION_PERFORMED'
)) {
    Assert-True ($gateway.Contains($required)) "Gateway runtime primitive is missing: $required"
}
Assert-True `
    (-not $gateway.Contains('ReadAllText($ipcKeyPath')) `
    'Gateway script must not materialize the IPC key as text.'
Assert-True `
    ($gateway.Contains("trading_mode\s*:\s*OBSERVE_ONLY")) `
    'Gateway runtime test must fail closed unless config remains OBSERVE_ONLY.'

Assert-True ($collector.Contains('#Requires -RunAsAdministrator')) 'Collector must require elevation.'
foreach ($required in @(
    'before_sha256', 'append_sha256', 'PREFIX_OR_SUFFIX_HASH_MISMATCH',
    'runtime_acl_canary', 'runtime_acl_append_probe', 'Test-JournalHashChain',
    'Get-CimInstance Win32_Process', 'lab_processes_stopped',
    'trading_mode\s*:\s*OBSERVE_ONLY', 'RUNTIME_ACL_GATE',
    'MT5_ACCESSED', 'ORDER_CHECK_EXECUTED', 'ORDER_SEND_EXECUTED',
    'DEMO_EXECUTION_ENABLED', 'TRADING_MODE'
)) {
    Assert-True ($collector.Contains($required)) "Collector validation is missing: $required"
}
Assert-True `
    ($collector.Contains('[System.IO.FileMode]::CreateNew')) `
    'Collector final report must not overwrite a prior administrative result.'

[pscustomobject]@{
    powershell_ast = 'PASS'
    exact_runtime_sids = 'PASS'
    wrong_identity_abort = 'PASS'
    no_credentials_or_identity_execution = 'PASS'
    no_acl_or_group_mutation = 'PASS'
    no_mt5_or_network = 'PASS'
    protected_operations_non_destructive = 'PASS'
    canary_scope = 'PASS'
    sqlite_wal_smoke_design = 'PASS'
    cpython_append_design = 'PASS'
    filehandler_append_design = 'PASS'
    critical_fail_stop = 'PASS'
    administrative_prefix_validation = 'PASS'
    observe_only_boundary = 'PASS'
} | ConvertTo-Json
