[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$agentPath = Join-Path $workspace 'scripts\Test-AgentRuntimeAcl.ps1'
$gatewayPath = Join-Path $workspace 'scripts\Test-GatewayRuntimeAcl.ps1'
$pythonBaseOnlyPath = Join-Path $workspace 'scripts\Test-PythonBaseOnlyRuntimeAcl.ps1'
$pythonStagingOnlyPath = Join-Path $workspace 'scripts\Test-PythonStagingOnlyRuntimeAcl.ps1'
$pythonFinalOnlyPath = Join-Path $workspace 'scripts\Test-PythonFinalOnlyRuntimeAcl.ps1'
$collectorPath = Join-Path $workspace 'scripts\Collect-RuntimeAclResults.ps1'
$paths = @(
    $agentPath, $gatewayPath, $pythonBaseOnlyPath, $pythonStagingOnlyPath,
    $pythonFinalOnlyPath, $collectorPath
)

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
$pythonBaseOnly = $sources[$pythonBaseOnlyPath]
$pythonStagingOnly = $sources[$pythonStagingOnlyPath]
$pythonFinalOnly = $sources[$pythonFinalOnlyPath]
$collector = $sources[$collectorPath]

Assert-True `
    ($agent.Contains('S-1-5-21-568964486-193631783-1609210587-1006')) `
    'Agent script is not bound to the exact authorized SID.'
Assert-True `
    ($gateway.Contains('S-1-5-21-568964486-193631783-1609210587-1007')) `
    'Gateway script is not bound to the exact authorized SID.'
Assert-True ($agent.Contains('[switch] $PythonBaseOnly')) 'Agent harness lacks the isolated PythonBaseOnly switch.'
Assert-True ($gateway.Contains('[switch] $PythonBaseOnly')) 'Gateway harness lacks the isolated PythonBaseOnly switch.'
Assert-True ($agent.Contains('[switch] $PythonStagingOnly')) 'Agent harness lacks the isolated PythonStagingOnly switch.'
Assert-True ($gateway.Contains('[switch] $PythonStagingOnly')) 'Gateway harness lacks the isolated PythonStagingOnly switch.'
Assert-True ($agent.Contains('[switch] $PythonFinalOnly')) 'Agent harness lacks the isolated PythonFinalOnly switch.'
Assert-True ($gateway.Contains('[switch] $PythonFinalOnly')) 'Gateway harness lacks the isolated PythonFinalOnly switch.'
foreach ($entry in @(
    [pscustomobject]@{ Source = $gateway; DefaultMarker = "`$labRoot = 'C:\ProgramData\AutomatonMT5Lab'"; Role = 'AutomatonGateway' },
    [pscustomobject]@{ Source = $agent; DefaultMarker = "`$agentStatePath = 'C:\Users\AutomatonAgent\.automaton'"; Role = 'AutomatonAgent' }
)) {
    $branchStart = $entry.Source.IndexOf('if ($PythonBaseOnly)')
    $stagingBranchStart = $entry.Source.IndexOf('if ($PythonStagingOnly)')
    $finalBranchStart = $entry.Source.IndexOf('if ($PythonFinalOnly)')
    $defaultStart = $entry.Source.IndexOf($entry.DefaultMarker)
    Assert-True ($branchStart -ge 0 -and $stagingBranchStart -gt $branchStart) "$($entry.Role) PythonBaseOnly branch must precede PythonStagingOnly."
    Assert-True ($finalBranchStart -gt $stagingBranchStart) "$($entry.Role) PythonStagingOnly branch must precede PythonFinalOnly."
    Assert-True ($defaultStart -gt $finalBranchStart) "$($entry.Role) PythonFinalOnly branch must precede the default harness."
    $branch = $entry.Source.Substring($branchStart, $stagingBranchStart - $branchStart)
    Assert-True ($branch.Contains("-Role '$($entry.Role)'")) "$($entry.Role) PythonBaseOnly branch uses the wrong role."
    Assert-True ($branch.Contains(". (Join-Path `$PSScriptRoot 'Test-PythonBaseOnlyRuntimeAcl.ps1')")) "$($entry.Role) PythonBaseOnly helper boundary is absent."
    Assert-True ($branch.Contains('return')) "$($entry.Role) PythonBaseOnly mode must return before the default harness."
    Assert-True (-not $branch.Contains('C:\automaton\.venv')) "$($entry.Role) PythonBaseOnly branch references the active venv."
    Assert-True (-not $branch.Contains('.venv.new')) "$($entry.Role) PythonBaseOnly branch references the staging venv."
    $stagingBranch = $entry.Source.Substring($stagingBranchStart, $finalBranchStart - $stagingBranchStart)
    Assert-True ($stagingBranch.Contains("-Role '$($entry.Role)'")) "$($entry.Role) PythonStagingOnly branch uses the wrong role."
    Assert-True ($stagingBranch.Contains(". (Join-Path `$PSScriptRoot 'Test-PythonStagingOnlyRuntimeAcl.ps1')")) "$($entry.Role) PythonStagingOnly helper boundary is absent."
    Assert-True ($stagingBranch.Contains('return')) "$($entry.Role) PythonStagingOnly mode must return before the default harness."
    Assert-True (-not $stagingBranch.Contains(".venv\Scripts")) "$($entry.Role) PythonStagingOnly branch references the active venv."
    $finalBranch = $entry.Source.Substring($finalBranchStart, $defaultStart - $finalBranchStart)
    Assert-True ($finalBranch.Contains("-Role '$($entry.Role)'")) "$($entry.Role) PythonFinalOnly branch uses the wrong role."
    Assert-True ($finalBranch.Contains(". (Join-Path `$PSScriptRoot 'Test-PythonFinalOnlyRuntimeAcl.ps1')")) "$($entry.Role) PythonFinalOnly helper boundary is absent."
    Assert-True ($finalBranch.Contains('return')) "$($entry.Role) PythonFinalOnly mode must return before the default harness."
    Assert-True (-not $finalBranch.Contains('.venv.new')) "$($entry.Role) PythonFinalOnly branch references the staging venv."
    Assert-True ($entry.Source.Contains('$isolatedModeCount -gt 1')) "$($entry.Role) isolated modes are not mutually exclusive."
}
Assert-True ($gateway.Contains("`$pythonExe = Join-Path `$workspace '.venv\Scripts\python.exe'")) 'Default Gateway harness no longer preserves its existing venv behavior.'
Assert-True ($agent.Contains("Add-AgentStateCanaryTest `$agentStatePath")) 'Default Agent harness no longer preserves its existing behavior.'
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

foreach ($forbiddenBaseOnly in @(
    'C:\automaton\.venv', '.venv.new', 'MetaTrader5', 'FastAPI', 'numpy',
    '.order_check(', '.order_send(', 'sqlite3', 'audit.jsonl', 'security.log',
    'demo-authorization', 'STOP_TRADING', 'trading.yaml', 'Start-Service',
    'Start-Process', 'Set-Acl', 'SetAccessRule', 'SetOwner', 'takeown', 'icacls'
)) {
    Assert-True (-not $pythonBaseOnly.Contains($forbiddenBaseOnly)) "PythonBaseOnly isolation violation: $forbiddenBaseOnly"
}
foreach ($requiredBaseOnly in @(
    "`$script:PythonBaseOnlyRoot = 'C:\Program Files\AutomatonPython\3.14.5'",
    "`$script:PythonBaseOnlyExecutable = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'",
    'Test-PythonBaseOnlyIdentity', 'Test-PythonBaseOnlyExactPath',
    'Test-PythonBaseOnlyReparseAttributes', 'Assert-PythonBaseOnlyConfinedPath',
    'PYTHON_BASE_REPARSE_POINT_FAIL_CLOSED', 'Resolve-PythonBaseOnlyAccessExpectation',
    '[System.Diagnostics.ProcessStartInfo]::new()',
    "`$startInfo.Arguments = '-B -I -'", 'RedirectStandardInput = $true',
    '$process.StandardInput.Write($Source)',
    'import json', 'import struct', 'import sys', 'import venv',
    'MACHINE_PYTHON_READ', 'MACHINE_PYTHON_ENUMERATE', 'MACHINE_PYTHON_EXECUTE',
    'MACHINE_PYTHON_CREATE_DENY', 'MACHINE_PYTHON_WRITE_DENY',
    'MACHINE_PYTHON_APPEND_DENY', 'MACHINE_PYTHON_TRUNCATE_DENY',
    'MACHINE_PYTHON_RENAME_DENY', 'MACHINE_PYTHON_DELETE_DENY',
    'MACHINE_PYTHON_WRITE_ATTRIBUTES_DENY', 'MACHINE_PYTHON_CHANGE_ACL_DENY',
    'MACHINE_PYTHON_TAKE_OWNERSHIP_DENY', 'DIRECTORY_ENUMERATION_DENY',
    'PYTHON_EXE_READ_DENY', 'PYTHON_DLL_READ_DENY', 'STDLIB_READ_DENY',
    'PYTHON_EXECUTE_DENY', 'CREATE_DENY', 'WRITE_DENY', 'DELETE_DENY',
    'CHANGE_ACL_DENY', 'TAKE_OWNERSHIP_DENY', 'CRITICAL_UNEXPECTED_ALLOW',
    "mode = 'PYTHON_BASE_ONLY'", "trading_mode = 'OBSERVE_ONLY'",
    'build_venv = $false', 'mt5_accessed = $false',
    'order_check_called = $false', 'order_send_called = $false',
    'gateway_started = $false', 'automaton_started = $false',
    'venv_accessed = $false', 'venv_new_accessed = $false',
    'acl_modified = $false', 'filesystem_runtime_modified ='
)) {
    Assert-True ($pythonBaseOnly.Contains($requiredBaseOnly)) "PythonBaseOnly invariant missing: $requiredBaseOnly"
}
Assert-True ($pythonBaseOnly.Contains('acl-runtime-results')) 'PythonBaseOnly report is not confined to the authorized result domain.'
Assert-True ($pythonBaseOnly.Contains('[System.IO.FileMode]::CreateNew')) 'PythonBaseOnly reports/canaries must be collision-resistant.'
Assert-True ($pythonBaseOnly.Contains('public static extern bool CreateDirectory(')) 'PythonBaseOnly directory canaries must use atomic Win32 creation.'
Assert-True ($pythonBaseOnly.Contains('if ($Context.critical_unexpected_allow) { return }')) 'PythonBaseOnly must stop immediately after a critical unexpected allow.'
Assert-True (-not $pythonBaseOnly.Contains('[System.IO.FileMode]::Truncate')) 'PythonBaseOnly must not truncate protected runtime files.'
Assert-True (-not $pythonBaseOnly.Contains('[System.IO.FileMode]::OpenOrCreate')) 'PythonBaseOnly must not open protected runtime files for mutation.'

. $pythonBaseOnlyPath
$gatewayExecution = Resolve-PythonBaseOnlyAccessExpectation $true 0 $true
Assert-True $gatewayExecution.passed 'Gateway expected Python execution success must pass.'
$gatewayMutationAllowed = Resolve-PythonBaseOnlyAccessExpectation $true 0 $false
Assert-True (-not $gatewayMutationAllowed.passed -and $gatewayMutationAllowed.critical) 'Gateway mutation success must be critical.'
$agentReadAllowed = Resolve-PythonBaseOnlyAccessExpectation $true 0 $false
Assert-True (-not $agentReadAllowed.passed -and $agentReadAllowed.critical) 'Agent read success must be critical.'
$agentExecuteAllowed = Resolve-PythonBaseOnlyAccessExpectation $true 0 $false
Assert-True (-not $agentExecuteAllowed.passed -and $agentExecuteAllowed.critical) 'Agent execute success must be critical.'
$agentAccessDenied = Resolve-PythonBaseOnlyAccessExpectation $false 5 $false
Assert-True $agentAccessDenied.passed 'Agent AccessDenied must satisfy an expected-denied test.'
Assert-True (-not (Test-PythonBaseOnlyIdentity 'S-1-5-21-wrong' $script:PythonBaseOnlyAgentSid)) 'Wrong effective SID must fail closed.'
Assert-True (-not (Test-PythonBaseOnlyExactPath 'C:\Program Files\OtherPython' $script:PythonBaseOnlyRoot)) 'A different Python path must fail closed.'
Assert-True (-not (Test-PythonBaseOnlyReparseAttributes ([System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint))) 'A reparse point must fail closed.'

foreach ($forbiddenStagingOnly in @(
    'import MetaTrader5', 'importlib.import_module("MetaTrader5")',
    '.order_check(', '.order_send(', 'initialize()', 'login()',
    'Set-Acl', 'SetAccessRule', 'SetOwner', 'takeown', 'icacls',
    'Start-Service', 'New-Service', 'runas.exe', 'Start-Process'
)) {
    Assert-True (-not $pythonStagingOnly.Contains($forbiddenStagingOnly)) "PythonStagingOnly isolation violation: $forbiddenStagingOnly"
}
Assert-True ($pythonStagingOnly.Contains('$script:PythonStagingOnlyIsFinal = $false')) 'PythonStagingOnly must default to staging mode.'
foreach ($requiredStagingOnly in @(
    "`$script:PythonStagingOnlyRoot = 'C:\automaton\.venv.new'",
    "`$script:PythonStagingOnlyExecutable = 'C:\automaton\.venv.new\Scripts\python.exe'",
    "`$script:PythonStagingOnlyBase = 'C:\Program Files\AutomatonPython\3.14.5'",
    'Test-PythonStagingOnlyExactPath', 'Test-PythonStagingOnlyTargetPresent',
    'Test-PythonStagingOnlyIdentity', 'Test-PythonStagingOnlyReparseAttributes',
    'Test-PythonStagingOnlyPathConfined', '_REPARSE_POINT_FAIL_CLOSED',
    'Resolve-PythonStagingOnlyAccessExpectation', 'Resolve-AgentPythonStagingExecutionExpectation',
    '[System.Diagnostics.ProcessStartInfo]::new()', "`$startInfo.Arguments = '-B -I -'",
    'RedirectStandardInput = $true', '$process.StandardInput.Write($Source)',
    'UseShellExecute = $false', 'importlib.metadata.version("MetaTrader5")',
    'can_import("fastapi")', 'can_import("pydantic")',
    'can_import("yaml")', 'can_import("uvicorn")',
    'STAGING_PATH_EXACT', 'STAGING_ENUMERATE', 'STAGING_PYTHON_READ',
    'STAGING_PYTHON_PATH_EXACT', 'STAGING_BASE_REFERENCE_EXACT',
    'STAGING_SITE_PACKAGES_READ', 'STAGING_PYTHON_EXECUTE',
    'STAGING_FASTAPI_IMPORT', 'STAGING_PYDANTIC_IMPORT',
    'STAGING_PYYAML_IMPORT', 'STAGING_UVICORN_IMPORT',
    'STAGING_METATRADER5_METADATA', 'STAGING_METATRADER5_IMPORTED',
    'STAGING_PYTHON_FUNCTIONAL_EXECUTION_DENY',
    'STAGING_CREATE_FILE_DENY', 'STAGING_CREATE_DIRECTORY_DENY', 'STAGING_CREATE_DENY',
    'STAGING_WRITE_DENY', 'STAGING_APPEND_DENY', 'STAGING_TRUNCATE_DENY',
    'STAGING_RENAME_DENY', 'STAGING_DELETE_DENY', 'STAGING_WRITE_ATTRIBUTES_DENY',
    'STAGING_CHANGE_ACL_DENY', 'STAGING_TAKE_OWNERSHIP_DENY',
    "`$script:PythonStagingOnlyMode = 'PYTHON_STAGING_ONLY'", "trading_mode = 'OBSERVE_ONLY'",
    'build_venv = $false', 'promote_venv = $false',
    'active_venv_accessed = $false', 'active_venv_modified = $false',
    'mt5_imported = $false', 'mt5_accessed = $false',
    'order_check_called = $false', 'order_send_called = $false',
    'gateway_started = $false', 'automaton_started = $false',
    'acl_modified = $false', 'filesystem_staging_modified ='
)) {
    Assert-True ($pythonStagingOnly.Contains($requiredStagingOnly)) "PythonStagingOnly invariant missing: $requiredStagingOnly"
}
Assert-True ($pythonStagingOnly.Contains("`$roleStem = if (`$Role -eq 'AutomatonGateway') { 'gateway' } else { 'agent' }")) 'Staging report role stem is not canonical.'
Assert-True ($pythonStagingOnly.Contains('"$roleStem-python-$reportKind-$RunId.json"')) 'Staging/final report filename builder is not canonical.'
Assert-True ($pythonStagingOnly.Contains('[System.IO.FileMode]::CreateNew')) 'PythonStagingOnly reports/canaries must be collision-resistant.'
Assert-True ($pythonStagingOnly.Contains('public static extern bool CreateDirectory(')) 'PythonStagingOnly directory canaries must use atomic Win32 creation.'
Assert-True (-not $pythonStagingOnly.Contains('[System.IO.FileMode]::Truncate')) 'PythonStagingOnly must not truncate real files.'
Assert-True (-not $pythonStagingOnly.Contains('[System.IO.FileMode]::OpenOrCreate')) 'PythonStagingOnly must not reuse canaries.'

. $pythonStagingOnlyPath
Assert-True (Test-PythonStagingOnlyExactPath 'C:\automaton\.venv.new' $script:PythonStagingOnlyRoot) 'Exact staging path should pass.'
Assert-True (-not (Test-PythonStagingOnlyExactPath 'C:\automaton\.venv.other' $script:PythonStagingOnlyRoot)) 'A different staging path must fail.'
Assert-True (-not (Test-PythonStagingOnlyTargetPresent 'C:\automaton\.python-staging-only-definitely-absent')) 'A missing staging target must fail.'
Assert-True (-not (Test-PythonStagingOnlyReparseAttributes ([System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint))) 'A staging reparse point must fail.'
Assert-True (-not (Test-PythonStagingOnlyIdentity 'S-1-5-21-wrong' $script:PythonStagingOnlyGatewaySid)) 'A wrong Gateway SID must fail.'
Assert-True (-not (Test-PythonStagingOnlyIdentity 'S-1-5-21-wrong' $script:PythonStagingOnlyAgentSid)) 'A wrong Agent SID must fail.'
Assert-True (-not (Test-PythonStagingOnlyPathConfined 'C:\automaton\outside.canary' $script:PythonStagingOnlyRoot)) 'A canary path outside staging must fail.'
$validConfig = @(
    'home = C:\Program Files\AutomatonPython\3.14.5',
    'include-system-site-packages = false',
    'version = 3.14.5',
    'executable = C:\Program Files\AutomatonPython\3.14.5\python.exe'
)
Assert-True (Test-PythonStagingOnlyConfigRecord $validConfig) 'Exact machine-base pyvenv.cfg should pass.'
$wrongConfig = @(
    'home = C:\Users\unexpected\Python',
    'include-system-site-packages = false',
    'version = 3.14.5',
    'executable = C:\Users\unexpected\Python\python.exe'
)
Assert-True (-not (Test-PythonStagingOnlyConfigRecord $wrongConfig)) 'A user-profile pyvenv.cfg must fail.'

$gatewayRead = Resolve-PythonStagingOnlyAccessExpectation $true 0 $true
Assert-True $gatewayRead.passed 'Expected staging read success must pass.'
$gatewayExecute = Resolve-PythonStagingOnlyAccessExpectation $true 0 $true
Assert-True $gatewayExecute.passed 'Expected Gateway staging execution success must pass.'
$mutationAllowed = Resolve-PythonStagingOnlyAccessExpectation $true 0 $false
Assert-True (-not $mutationAllowed.passed -and $mutationAllowed.critical) 'Any staging mutation success must be critical.'

$validMetadata = [pscustomobject]@{
    imports = [pscustomobject]@{ fastapi = $true; pydantic = $true; yaml = $true; uvicorn = $true }
    mt5_metadata = '5.0.6090'
    mt5_imported = $false
}
foreach ($property in @('fastapi', 'pydantic', 'yaml', 'uvicorn')) {
    Assert-True (Test-PythonStagingOnlyImportGate $validMetadata $property) "Valid $property import should pass."
    $failedMetadata = [pscustomobject]@{
        imports = [pscustomobject]@{ fastapi = $true; pydantic = $true; yaml = $true; uvicorn = $true }
        mt5_metadata = '5.0.6090'
        mt5_imported = $false
    }
    $failedMetadata.imports.$property = $false
    Assert-True (-not (Test-PythonStagingOnlyImportGate $failedMetadata $property)) "Failed $property import must fail."
}
Assert-True (Test-PythonStagingOnlyMt5Metadata $validMetadata) 'Exact MetaTrader5 metadata should pass.'
$wrongMt5 = [pscustomobject]@{ mt5_metadata = '0.0.0'; mt5_imported = $false }
Assert-True (-not (Test-PythonStagingOnlyMt5Metadata $wrongMt5)) 'Wrong MetaTrader5 metadata must fail.'
$importedMt5 = [pscustomobject]@{ mt5_metadata = '5.0.6090'; mt5_imported = $true }
Assert-True (-not (Test-PythonStagingOnlyMt5NotImported $importedMt5)) 'A loaded MetaTrader5 module must fail.'

$agentAccessDenied = Resolve-AgentPythonStagingExecutionExpectation $false $null $false 5
Assert-True $agentAccessDenied.passed 'Agent process-start AccessDenied must pass the denial gate.'
$agentNonzero = Resolve-AgentPythonStagingExecutionExpectation $true 1 $false 0
Assert-True $agentNonzero.passed 'Agent nonzero execution without marker must pass the denial gate.'
$agentExitZero = Resolve-AgentPythonStagingExecutionExpectation $true 0 $false 0
Assert-True (-not $agentExitZero.passed -and $agentExitZero.critical) 'Agent exit code zero must fail critically.'
$agentMarker = Resolve-AgentPythonStagingExecutionExpectation $true 1 $true 0
Assert-True (-not $agentMarker.passed -and $agentMarker.critical) 'Agent success marker must fail critically.'
$agentStartError = Resolve-AgentPythonStagingExecutionExpectation $false $null $false 2
Assert-True (-not $agentStartError.passed -and $agentStartError.infrastructure_error) 'Unexpected Agent process-start errors must be infrastructure failures.'

$pythonFinalImplementation = $pythonStagingOnly + [Environment]::NewLine + $pythonFinalOnly
foreach ($forbiddenFinalOnly in @(
    'import MetaTrader5', 'importlib.import_module("MetaTrader5")',
    '.order_check(', '.order_send(', 'initialize()', 'login()',
    'Set-Acl', 'SetAccessRule', 'SetOwner', 'takeown', 'icacls',
    'Start-Service', 'New-Service', 'runas.exe', 'Start-Process'
)) {
    Assert-True (-not $pythonFinalImplementation.Contains($forbiddenFinalOnly)) "PythonFinalOnly isolation violation: $forbiddenFinalOnly"
}
Assert-True (-not $pythonFinalOnly.Contains('C:\automaton\.venv.new')) 'PythonFinalOnly wrapper references the staging venv.'
Assert-True (-not $pythonFinalOnly.Contains('C:\automaton\.venv.backup.')) 'PythonFinalOnly wrapper references a backup venv.'
foreach ($requiredFinalOnly in @(
    "`$script:PythonStagingOnlyMode = 'PYTHON_FINAL_ONLY'",
    "`$script:PythonStagingOnlyRoot = 'C:\automaton\.venv'",
    "`$script:PythonStagingOnlyExecutable = 'C:\automaton\.venv\Scripts\python.exe'",
    "`$script:PythonStagingOnlyBase = 'C:\Program Files\AutomatonPython\3.14.5'",
    'Invoke-TradingLabPythonFinalOnlyRuntimeAcl', 'Test-PythonFinalOnlyExactPath',
    'Test-PythonFinalOnlyTargetPresent', 'Test-PythonFinalOnlyIdentity',
    'Test-PythonFinalOnlyReparseAttributes', 'Test-PythonFinalOnlyPathConfined',
    'Test-PythonFinalOnlyConfigRecord', 'Test-PythonFinalOnlyExecutionMetadata',
    'Resolve-AgentPythonFinalExecutionExpectation', 'Test-PythonFinalOnlyBoundaryRecord',
    'staging_venv_accessed', 'staging_venv_modified',
    'backup_venv_accessed', 'backup_venv_modified', 'cleanup = $false',
    'filesystem_final_modified', 'trading_mode = ''OBSERVE_ONLY''',
    'build_venv = $false', 'promote_venv = $false',
    'mt5_imported = $false', 'mt5_accessed = $false',
    'order_check_called = $false', 'order_send_called = $false',
    'gateway_started = $false', 'automaton_started = $false', 'acl_modified = $false',
    'importlib.metadata.version("MetaTrader5")', "`$startInfo.Arguments = '-B -I -'"
)) {
    Assert-True ($pythonFinalImplementation.Contains($requiredFinalOnly)) "PythonFinalOnly invariant missing: $requiredFinalOnly"
}

. $pythonFinalOnlyPath
$finalRunId = '00000000-0000-0000-0000-000000000301'
foreach ($finalGate in @(
    'FINAL_PATH_EXACT', 'FINAL_ENUMERATE', 'FINAL_PYTHON_READ',
    'FINAL_SITE_PACKAGES_READ', 'FINAL_PYTHON_EXECUTE',
    'FINAL_PYTHON_FUNCTIONAL_EXECUTION_DENY', 'FINAL_CREATE_DENY',
    'FINAL_WRITE_DENY', 'FINAL_APPEND_DENY', 'FINAL_TRUNCATE_DENY',
    'FINAL_RENAME_DENY', 'FINAL_DELETE_DENY', 'FINAL_WRITE_ATTRIBUTES_DENY',
    'FINAL_CHANGE_ACL_DENY', 'FINAL_TAKE_OWNERSHIP_DENY',
    'FINAL_NO_STAGING_CONFIG_REFERENCE', 'FINAL_NO_STAGING_FUNCTIONAL_REFERENCE'
)) {
    $stagingGate = 'STAGING_' + $finalGate.Substring('FINAL_'.Length)
    Assert-True ((Get-PythonStagingOnlyGateName $stagingGate) -eq $finalGate) "Final gate name mapping failed: $finalGate"
}
Assert-True (Test-PythonFinalOnlyExactPath 'C:\automaton\.venv' $script:PythonStagingOnlyRoot) 'Exact final target must pass.'
Assert-True (-not (Test-PythonFinalOnlyExactPath 'C:\automaton\.venv.other' $script:PythonStagingOnlyRoot)) 'Wrong final target must fail.'
Assert-True (-not (Test-PythonFinalOnlyExactPath 'C:\automaton\.venv\python.exe' $script:PythonStagingOnlyExecutable)) 'Wrong final Python path must fail.'
Assert-True (-not (Test-PythonFinalOnlyTargetPresent 'C:\automaton\.python-final-only-definitely-absent')) 'Missing final target must fail.'
Assert-True (-not (Test-PythonFinalOnlyReparseAttributes ([System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint))) 'Final reparse point must fail.'
Assert-True (-not (Test-PythonFinalOnlyIdentity 'S-1-5-21-wrong' $script:PythonStagingOnlyGatewaySid)) 'Wrong final Gateway SID must fail.'
Assert-True (-not (Test-PythonFinalOnlyIdentity 'S-1-5-21-wrong' $script:PythonStagingOnlyAgentSid)) 'Wrong final Agent SID must fail.'
Assert-True (-not (Test-PythonFinalOnlyPathConfined 'C:\automaton\.venv.new\outside.canary')) 'Final canary must not escape into staging.'
Assert-True (-not (Test-PythonFinalOnlyPathConfined 'C:\automaton\.venv.backup.test\outside.canary')) 'Final canary must not escape into backup.'
Assert-True ((Get-PythonFinalOnlyReportFileName 'AutomatonGateway' $finalRunId) -eq "gateway-python-final-$finalRunId.json") 'Gateway final report filename is not exact.'
Assert-True ((Get-PythonFinalOnlyReportFileName 'AutomatonAgent' $finalRunId) -eq "agent-python-final-$finalRunId.json") 'Agent final report filename is not exact.'
Assert-True ((Get-PythonFinalOnlyReportPath 'AutomatonGateway' $finalRunId) -eq "C:\ProgramData\AutomatonMT5Lab\operational\acl-runtime-results\gateway-python-final-$finalRunId.json") 'Gateway final report path is not exact.'
Assert-True ((Get-PythonFinalOnlyReportPath 'AutomatonAgent' $finalRunId) -eq "C:\Users\AutomatonAgent\.automaton\acl-runtime-results\agent-python-final-$finalRunId.json") 'Agent final report path is not exact.'

$validFinalConfig = @(
    'home = C:\Program Files\AutomatonPython\3.14.5',
    'include-system-site-packages = false',
    'version = 3.14.5',
    'executable = C:\Program Files\AutomatonPython\3.14.5\python.exe'
)
Assert-True (Test-PythonFinalOnlyConfigRecord $validFinalConfig) 'Exact final pyvenv.cfg must pass.'
$stagingReferenceConfig = @($validFinalConfig) + 'command = C:\automaton\.venv.new\Scripts\python.exe -m venv C:\automaton\.venv'
Assert-True (-not (Test-PythonFinalOnlyConfigRecord $stagingReferenceConfig)) 'Final pyvenv.cfg staging reference must fail.'

$validFinalExecution = [pscustomobject]@{
    ProcessStarted = $true; ExitCode = 0; StandardErrorPresent = $false
}
$validFinalMetadata = [pscustomobject]@{
    architecture_bits = 64
    base_prefix = 'C:\Program Files\AutomatonPython\3.14.5'
    executable = 'C:\automaton\.venv\Scripts\python.exe'
    imports = [pscustomobject]@{ fastapi = $true; pydantic = $true; yaml = $true; uvicorn = $true }
    mt5_metadata = '5.0.6090'
    mt5_imported = $false
    prefix = 'C:\automaton\.venv'
    sys_path = @('C:\Program Files\AutomatonPython\3.14.5\python314.zip', 'C:\automaton\.venv\Lib\site-packages')
    user_site_enabled = $false
    venv_import = $true
    version = '3.14.5'
}
Assert-True (Test-PythonFinalOnlyExecutionMetadata $validFinalExecution $validFinalMetadata) 'Gateway final functional execution must pass.'
foreach ($property in @('fastapi', 'pydantic', 'yaml', 'uvicorn')) {
    Assert-True (Test-PythonFinalOnlyImportGate $validFinalMetadata $property) "Gateway final $property import must pass."
}
$failedFinalImport = $validFinalMetadata | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$failedFinalImport.imports.fastapi = $false
Assert-True (-not (Test-PythonFinalOnlyImportGate $failedFinalImport 'fastapi')) 'Gateway final dependency import failure must fail.'
Assert-True (Test-PythonFinalOnlyMt5Metadata $validFinalMetadata) 'Final MetaTrader5 metadata version must pass.'
Assert-True (Test-PythonFinalOnlyMt5NotImported $validFinalMetadata) 'Final MetaTrader5 must remain unimported.'

$wrongFinalPrefix = $validFinalMetadata | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$wrongFinalPrefix.prefix = 'C:\automaton\.venv.new'
Assert-True (-not (Test-PythonFinalOnlyExecutionMetadata $validFinalExecution $wrongFinalPrefix)) 'Wrong final prefix must fail.'
$wrongFinalBasePrefix = $validFinalMetadata | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$wrongFinalBasePrefix.base_prefix = 'C:\Users\Proyecto IA\Python'
Assert-True (-not (Test-PythonFinalOnlyExecutionMetadata $validFinalExecution $wrongFinalBasePrefix)) 'Wrong final base_prefix must fail.'
$stagingFunctionalReference = $validFinalMetadata | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$stagingFunctionalReference.sys_path = @($stagingFunctionalReference.sys_path) + 'C:\automaton\.venv.new\Lib\site-packages'
Assert-True (-not (Test-PythonFinalOnlyExecutionMetadata $validFinalExecution $stagingFunctionalReference)) 'Functional staging reference from FinalOnly must fail.'

$gatewayFinalMutation = Resolve-PythonFinalOnlyAccessExpectation $true 0 $false
Assert-True (-not $gatewayFinalMutation.passed -and $gatewayFinalMutation.critical) 'Gateway final mutation success must fail critically.'
$agentFinalExecution = Resolve-AgentPythonFinalExecutionExpectation $true 0 $false 0
Assert-True (-not $agentFinalExecution.passed -and $agentFinalExecution.critical) 'Agent final functional execution success must fail critically.'
$agentFinalMarker = Resolve-AgentPythonFinalExecutionExpectation $true 1 $true 0
Assert-True (-not $agentFinalMarker.passed -and $agentFinalMarker.critical) 'Agent final success marker must fail critically.'
$agentFinalNonzero = Resolve-AgentPythonFinalExecutionExpectation $true 1 $false 0
Assert-True $agentFinalNonzero.passed 'Agent final nonzero/no-marker execution must pass the denial gate.'
$agentFinalAccessDenied = Resolve-AgentPythonFinalExecutionExpectation $false $null $false 5
Assert-True $agentFinalAccessDenied.passed 'Agent final AccessDenied must pass the denial gate.'
$agentFinalMutation = Resolve-PythonFinalOnlyAccessExpectation $true 0 $false
Assert-True (-not $agentFinalMutation.passed -and $agentFinalMutation.critical) 'Agent final mutation success must fail critically.'

$validFinalBoundaries = [pscustomobject]@{
    trading_mode = 'OBSERVE_ONLY'; build_venv = $false; promote_venv = $false; cleanup = $false
    staging_venv_accessed = $false; staging_venv_modified = $false
    backup_venv_accessed = $false; backup_venv_modified = $false
    mt5_imported = $false; mt5_accessed = $false
    order_check_called = $false; order_send_called = $false
    gateway_started = $false; automaton_started = $false
    acl_modified = $false; filesystem_final_modified = $false
}
Assert-True (Test-PythonFinalOnlyBoundaryRecord $validFinalBoundaries) 'Exact final boundaries must pass.'
$stagingBoundaryViolation = $validFinalBoundaries | ConvertTo-Json | ConvertFrom-Json
$stagingBoundaryViolation.staging_venv_accessed = $true
Assert-True (-not (Test-PythonFinalOnlyBoundaryRecord $stagingBoundaryViolation)) 'Staging access from FinalOnly must fail the boundary.'
$backupBoundaryViolation = $validFinalBoundaries | ConvertTo-Json | ConvertFrom-Json
$backupBoundaryViolation.backup_venv_accessed = $true
Assert-True (-not (Test-PythonFinalOnlyBoundaryRecord $backupBoundaryViolation)) 'Backup access from FinalOnly must fail the boundary.'
$finalFilesystemMutation = $validFinalBoundaries | ConvertTo-Json | ConvertFrom-Json
$finalFilesystemMutation.filesystem_final_modified = $true
Assert-True (-not (Test-PythonFinalOnlyBoundaryRecord $finalFilesystemMutation)) 'Final filesystem mutation must fail the boundary.'

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
    PYTHON_BASE_ONLY_DEFAULT_GATEWAY_UNCHANGED = 'PASS'
    PYTHON_BASE_ONLY_DEFAULT_AGENT_UNCHANGED = 'PASS'
    PYTHON_BASE_ONLY_VENV_ISOLATED = 'PASS'
    PYTHON_BASE_ONLY_NO_MT5_OR_ORDERS = 'PASS'
    PYTHON_BASE_ONLY_GATEWAY_EXECUTION_EXPECTED = 'PASS'
    PYTHON_BASE_ONLY_GATEWAY_MUTATION_FAIL_CLOSED = 'PASS'
    PYTHON_BASE_ONLY_AGENT_READ_EXECUTE_FAIL_CLOSED = 'PASS'
    PYTHON_BASE_ONLY_AGENT_ACCESS_DENIED_PASS = 'PASS'
    PYTHON_BASE_ONLY_IDENTITY_PATH_REPARSE_FAIL_CLOSED = 'PASS'
    PYTHON_BASE_ONLY_NO_ACL_OR_SERVICE_MUTATION = 'PASS'
    PYTHON_BASE_ONLY_CRITICAL_FAIL_STOP = 'PASS'
    PYTHON_BASE_ONLY_ATOMIC_DIRECTORY_CANARY = 'PASS'
    PYTHON_STAGING_ONLY_DEFAULT_GATEWAY_UNCHANGED = 'PASS'
    PYTHON_STAGING_ONLY_DEFAULT_AGENT_UNCHANGED = 'PASS'
    PYTHON_STAGING_ONLY_BASE_MODE_UNCHANGED = 'PASS'
    PYTHON_STAGING_ONLY_ACTIVE_VENV_ISOLATED = 'PASS'
    PYTHON_STAGING_ONLY_IDENTITY_PATH_REPARSE_FAIL_CLOSED = 'PASS'
    PYTHON_STAGING_ONLY_GATEWAY_READ_EXECUTE = 'PASS'
    PYTHON_STAGING_ONLY_GATEWAY_IMPORTS = 'PASS'
    PYTHON_STAGING_ONLY_MT5_METADATA_WITHOUT_IMPORT = 'PASS'
    PYTHON_STAGING_ONLY_AGENT_DENIAL_SEMANTICS = 'PASS'
    PYTHON_STAGING_ONLY_MUTATION_FAIL_CLOSED = 'PASS'
    PYTHON_STAGING_ONLY_NO_ACL_SERVICE_MT5_ORDERS = 'PASS'
    PYTHON_FINAL_ONLY_DEFAULT_GATEWAY_UNCHANGED = 'PASS'
    PYTHON_FINAL_ONLY_DEFAULT_AGENT_UNCHANGED = 'PASS'
    PYTHON_FINAL_ONLY_PRIOR_MODES_UNCHANGED = 'PASS'
    PYTHON_FINAL_ONLY_EXACT_TARGET_AND_REPORTS = 'PASS'
    PYTHON_FINAL_ONLY_IDENTITY_PATH_REPARSE_FAIL_CLOSED = 'PASS'
    PYTHON_FINAL_ONLY_GATEWAY_READ_EXECUTE_IMPORTS = 'PASS'
    PYTHON_FINAL_ONLY_MT5_METADATA_WITHOUT_IMPORT = 'PASS'
    PYTHON_FINAL_ONLY_AGENT_DENIAL_SEMANTICS = 'PASS'
    PYTHON_FINAL_ONLY_MUTATION_FAIL_CLOSED = 'PASS'
    PYTHON_FINAL_ONLY_STAGING_BACKUP_BOUNDARIES = 'PASS'
    PYTHON_FINAL_ONLY_NO_ACL_SERVICE_MT5_ORDERS = 'PASS'
} | ConvertTo-Json
