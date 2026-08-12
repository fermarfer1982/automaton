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
    $identityIndex = $source.IndexOf('if ($effectiveSid -ne $expectedSid)')
    $tempInitializationIndex = $source.LastIndexOf('Initialize-PrivateRuntimeTemp ')
    $addTypeIndex = $source.IndexOf('Add-Type -TypeDefinition')
    Assert-True `
        ($identityIndex -ge 0 -and $tempInitializationIndex -gt $identityIndex -and $addTypeIndex -gt $tempInitializationIndex) `
        'SID validation and private TEMP initialization must precede Add-Type.'
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
    foreach ($required in @(
        'Assert-PathConfined', 'Assert-DirectoryNotReparsePoint',
        '[System.IO.FileAttributes]::ReparsePoint', '$env:TEMP =',
        '$env:TMP = $env:TEMP', '[System.IO.Path]::GetTempPath()',
        "'.runtime-temp-write.canary'", 'Clear-PrivateRuntimeTemp',
        "'RUNTIME_TEMP_PRIVATE'", "'RUNTIME_TEMP_CLEANUP'",
        'Runtime TEMP already exists for this RunId'
    )) {
        Assert-True ($source.Contains($required)) "Private runtime TEMP guard is missing: $required"
    }
    Assert-True `
        ($source.IndexOf('C:\Windows\TEMP', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) `
        'Runtime harness must never reference Windows TEMP.'
    Assert-True `
        ($source.Contains('standard File APIs cannot request WRITE_DAC or DELETE_CHILD')) `
        'The fine-grained native access probe must document why Add-Type remains necessary.'
}

Assert-True `
    ($agent.Contains("`$runtimeTempBase = Join-Path `$agentStatePath 'runtime-tmp'")) `
    'Agent private TEMP must stay inside authorized Agent state.'
Assert-True `
    ($gateway.Contains("`$runtimeTempBase = Join-Path `$operationalPath 'runtime-tmp'")) `
    'Gateway private TEMP must stay inside its authorized operational domain.'

foreach ($required in @(
    'WORKSPACE_READ', 'WORKSPACE_CREATE', 'WORKSPACE_MODIFY_CODE', 'WORKSPACE_DELETE_CODE',
    'CONFIG_READ', 'IPC_READ', 'IPC_WRITE', 'IPC_TRUNCATE', 'IPC_DELETE', 'IPC_CHANGE_ACL',
    'OPERATIONAL_ACCESS', 'RESEARCH_ACCESS', 'AUDIT_SQLITE_ACCESS', 'AUDIT_JOURNAL_ACCESS',
    'SECURITY_LOG_ACCESS', 'STATE_CREATE_WRITE_READ_DELETE',
    'DEMO_AUTH_CREATE', 'DEMO_AUTH_MODIFY', 'DEMO_AUTH_DELETE',
    'KILL_SWITCH_CREATE', 'KILL_SWITCH_MODIFY', 'KILL_SWITCH_DELETE',
    'RUNTIME_TEMP_PRIVATE', 'RUNTIME_TEMP_CLEANUP'
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
    'KILL_SWITCH_DETECT', 'KILL_SWITCH_CREATE', 'KILL_SWITCH_MODIFY', 'KILL_SWITCH_DELETE',
    'RUNTIME_TEMP_PRIVATE', 'RUNTIME_TEMP_CLEANUP'
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
foreach ($required in @(
    'Add-PythonRuntimePreflightTests', 'PYTHON_EXECUTABLE_PATH',
    'PYTHON_EXECUTE', 'PYTHON_EXECUTABLE_IDENTITY', 'PYTHON_SQLITE_IMPORT',
    'PYTHON_RUNTIME_TEMP', 'PYTHON_RUNTIME_TEMP_CONFINED',
    'PYTHON_BASE_MACHINE_WIDE', 'PYTHON_BASE_OUTSIDE_USER_PROFILE',
    'PYTHON_GATEWAY_EXECUTE', 'PYTHON_GATEWAY_MODIFY_DENY',
    'VENV_BASE_OUTSIDE_USER_PROFILE',
    'PYTHON_BASE_ROOT_MODIFY', 'PYTHON_BASE_EXE_MODIFY',
    'PYTHON_BASE_DLL_MODIFY', 'PYTHON_BASE_STDLIB_MODIFY',
    'PYTHON_VENV_EXE_MODIFY', 'PYTHON_VENV_SCRIPTS_MODIFY',
    'PYTHON_VENV_SITE_PACKAGES_MODIFY',
    'SQLITE_PROCESS', 'SQLITE_DB_CREATE', 'SQLITE_WAL_MODE',
    'SQLITE_WAL_CREATE', 'SQLITE_SHM_CREATE', 'SQLITE_COMMIT',
    'SQLITE_READ_BACK', 'SQLITE_CHECKPOINT', 'SQLITE_CLOSE', 'SQLITE_CLEANUP',
    '[System.Diagnostics.ProcessStartInfo]::new()',
    '$startInfo.RedirectStandardError = $true',
    '$process.StandardError.ReadToEnd()',
    'PYTHON_UNEXPECTED_STDERR',
    'AUTOMATON_RUNTIME_TEST_TEMP', 'AUTOMATON_RUNTIME_TEST_DB'
)) {
    Assert-True ($gateway.Contains($required)) "Gateway Python/SQLite diagnostic stage is missing: $required"
}
Assert-True `
    ($gateway.Contains("`$machinePythonBase = 'C:\Program Files\AutomatonPython\3.14.5'")) `
    'Gateway runtime must require the exact machine-wide Python base.'
Assert-True `
    ($gateway.Contains("`$startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'")) `
    'Gateway Python probes must not attempt bytecode writes into immutable runtime code.'
Assert-True `
    (-not $gateway.Contains('2>&1')) `
    'Python stderr must not be converted into a generic PowerShell RemoteException.'
Assert-True `
    (-not $gateway.Contains('$output = @(& $pythonExe')) `
    'Python must run through redirected ProcessStartInfo diagnostics.'
Assert-True `
    ($gateway.IndexOf("Add-MutableDirectoryCanaryTest 'RESEARCH_MODIFY'") -lt $gateway.LastIndexOf('Add-PythonRuntimePreflightTests')) `
    'Python preflight must immediately follow the research canary.'
Assert-True `
    ($gateway.LastIndexOf('Add-PythonRuntimePreflightTests') -lt $gateway.LastIndexOf('Add-SqliteWalCanaryTest')) `
    'Python preflight must precede the SQLite WAL canary.'
foreach ($required in @(
    'stage = $script:currentStage', 'test_name = $script:currentTestName',
    'exception_type =', 'exception_message =', 'FullyQualifiedErrorId =',
    'script_line =', 'invocation =', 'stack_trace =',
    'last_completed_test =', 'New-FailureDiagnostic $_',
    '$nativeProbeLoadError = $_',
    "Set-TestContext 'NATIVE_ACCESS_PROBE_COMPILER' 'ADD_TYPE_NATIVE_METHODS'",
    'TEST_FAILED_EXPECTATION', 'TEST_INFRASTRUCTURE_ERROR',
    'CRITICAL_UNEXPECTED_ALLOW', 'failure_classification =', 'diagnostic ='
)) {
    Assert-True ($gateway.Contains($required)) "Structured runtime diagnostic is missing: $required"
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
    AGENT_RUNTIME_TEMP_PRIVATE = 'PASS'
    GATEWAY_RUNTIME_TEMP_PRIVATE = 'PASS'
    WINDOWS_TEMP_NOT_USED = 'PASS'
    TEMP_PATH_CONFINED = 'PASS'
    REPARSE_POINT_FAIL_CLOSED = 'PASS'
    UNEXPECTED_EXCEPTION_DIAGNOSTIC = 'PASS'
    FAILURE_CLASSIFICATION = 'PASS'
    PYTHON_STDERR_CAPTURE = 'PASS'
    SQLITE_STAGE_DIAGNOSTICS = 'PASS'
    PYTHON_BASE_MACHINE_WIDE_STATIC = 'PASS'
    PYTHON_BASE_OUTSIDE_USER_PROFILE_STATIC = 'PASS'
    PYTHON_GATEWAY_MODIFY_PROBES = 'PASS'
} | ConvertTo-Json
