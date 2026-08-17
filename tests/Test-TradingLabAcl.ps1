$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Initialize-TradingLabAcl.ps1'
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) {
    throw "ACL script has PowerShell AST errors: $($errors -join '; ')"
}

$source = [System.IO.File]::ReadAllText($scriptPath)
$applyGatePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Apply-TradingLabAclGate.ps1'
$applyTokens = $null
$applyErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $applyGatePath, [ref]$applyTokens, [ref]$applyErrors
)
if ($applyErrors.Count -ne 0) {
    throw "ACL apply gate has PowerShell AST errors: $($applyErrors -join '; ')"
}
$applySource = [System.IO.File]::ReadAllText($applyGatePath)
$authorizationAclPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Set-MT5ReadOnlyAuthorizationAcl.ps1'
$protectedIdentityPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Set-MT5ReadOnlyProtectedIdentity.ps1'
foreach ($maintenanceScript in @($authorizationAclPath, $protectedIdentityPath)) {
    $maintenanceTokens = $null
    $maintenanceErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $maintenanceScript, [ref]$maintenanceTokens, [ref]$maintenanceErrors
    )
    if ($maintenanceErrors.Count -ne 0) {
        throw "MT5 precondition script has PowerShell AST errors: $($maintenanceErrors -join '; ')"
    }
}
$authorizationAclSource = [System.IO.File]::ReadAllText($authorizationAclPath)
$protectedIdentitySource = [System.IO.File]::ReadAllText($protectedIdentityPath)
foreach ($forbidden in @('Start-Process -Credential', 'runas.exe', '.order_send(', '.order_check(', 'import MetaTrader5')) {
    if ($applySource.Contains($forbidden)) {
        throw "ACL apply gate contains forbidden runtime action: $forbidden"
    }
}
foreach ($requiredApply in @(
    '#Requires -RunAsAdministrator',
    'S-1-5-21-568964486-193631783-1609210587-1006',
    'S-1-5-21-568964486-193631783-1609210587-1007',
    'trading.bootstrap-observe-only.yaml',
    '-Apply | Out-Null',
    "service_identities_executed = `$false",
    "mt5_accessed = `$false"
)) {
    if (-not $applySource.Contains($requiredApply)) {
        throw "ACL apply gate lacks required boundary: $requiredApply"
    }
}
if ($applySource.Contains('RandomNumberGenerator]::Fill')) {
    throw 'ACL apply boundary reintroduced a Windows PowerShell 5.1-incompatible RNG API.'
}
foreach ($transactional in @(
    "acl_apply = 'IN_PROGRESS'",
    'Resolve-AclApplyFailureStatus',
    'security_descriptors_applied',
    '-ProgressPath $progressPath',
    'Write-GateReport'
)) {
    if (-not $applySource.Contains($transactional)) {
        throw "ACL apply gate lacks transactional reporting: $transactional"
    }
}
foreach ($required in @(
    "Join-Path `$root 'operational'",
    "Join-Path `$root 'research'",
    "Join-Path `$audit 'sqlite'",
    "Join-Path `$audit 'journal'",
    "Join-Path `$logs 'gateway'",
    "Join-Path `$logs 'security'",
    "Join-Path `$control 'STOP_TRADING'",
    "Join-Path `$control 'demo-authorization'",
    "Read,AppendData,Synchronize",
    "Get-LocalUser -SID `$runtimeIdentity.Sid",
    "S-1-5-32-545",
    "Get-DirectLocalGroupSids",
    "SetAccessRuleProtection(`$true, `$false)",
    "`$protectedSourceDirectories",
    "Protected source tree contains a reparse point",
    "sqlite_immutable = `$false",
    "deny_aces_used = `$false"
    'Read-TradingLabWindowsAclPolicy'
    'Maintenance identity must be an enabled local direct Administrator.'
    "'lab_root'"
    "'operational'"
    "'logs_root'"
    "'gateway_logs'"
    "'security_logs'"
    "'automaton_state'"
)) {
    if (-not $source.Contains($required)) {
        throw "ACL source is missing required invariant: $required"
    }
}
foreach ($requiredPolicyBoundary in @(
    'config\windows-acl-policy.json',
    'Resolve-TradingLabAclIdentitySid',
    '$maintenanceTargetKeys.Contains($MaintenancePolicyKey)',
    'New-AccessRule $maintenanceSid ([System.Security.AccessControl.FileSystemRights]::FullControl'
)) {
    if (-not $source.Contains($requiredPolicyBoundary)) {
        throw "ACL source does not consume the canonical maintenance policy: $requiredPolicyBoundary"
    }
}
if ($source.Contains('S-1-5-21-568964486-193631783-1609210587-1001')) {
    throw 'Maintenance SID must be resolved from the configured account name, not hardcoded.'
}
if ($source.Contains("gateway_writable_data") -or $source.Contains("Join-Path `$root 'data'")) {
    throw 'ACL source reintroduced a globally writable data domain.'
}
if ($source.Contains('WriteAllText($killSwitchFile') -or $source.Contains('WriteAllText($demoAuthorizationFile')) {
    throw 'ACL bootstrap must not assert the presence-based kill switch or DEMO authorization.'
}

foreach ($requiredAuthorizationPolicy in @(
    "[System.Security.AccessControl.InheritanceFlags]::ObjectInherit",
    "[System.Security.AccessControl.PropagationFlags]::InheritOnly",
    "[System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'",
    'mt5-read-only-authorization-<UUID>.json',
    'Set-ExactDemoAuthorizationAcl'
)) {
    if (-not $source.Contains($requiredAuthorizationPolicy)) {
        throw "Canonical ACL source lacks RunId authorization policy: $requiredAuthorizationPolicy"
    }
}
if ($source.Contains("New-AclProposal `$demoAuthorizationFile") -or
    $source.Contains("Join-Path `$demoAuthorization 'authorization.json'")) {
    throw 'Canonical ACL source still models legacy authorization.json as an artifact.'
}
foreach ($requiredTargeted in @(
    '#Requires -RunAsAdministrator',
    'C:\ProgramData\AutomatonMT5Lab\control\demo-authorization',
    'KNOWN_LEGACY_DIRECTORY_ONLY',
    'CANONICAL_RUN_ID_ARTIFACTS',
    "[System.Security.AccessControl.InheritanceFlags]::ObjectInherit",
    "[System.Security.AccessControl.PropagationFlags]::InheritOnly",
    'Set-Acl -LiteralPath $target',
    'rollback_attempted',
    'gateway_mutation_rights',
    'agent_access',
    'FileMode]::CreateNew'
)) {
    if (-not $authorizationAclSource.Contains($requiredTargeted)) {
        throw "Targeted authorization ACL gate lacks boundary: $requiredTargeted"
    }
}
foreach ($forbiddenTargeted in @(
    'icacls', '/reset', 'MetaTrader5', 'initialize()', 'order_check', 'order_send',
    'Start-Process', 'trading_lab.service'
)) {
    if ($authorizationAclSource.Contains($forbiddenTargeted)) {
        throw "Targeted authorization ACL gate contains forbidden action: $forbiddenTargeted"
    }
}
$readOnlyRights = 1179785L
$forbiddenMutation = 2L -bor 4L -bor 16L -bor 64L -bor 256L -bor 65536L -bor 262144L -bor 524288L
if (($readOnlyRights -band $forbiddenMutation) -ne 0) {
    throw 'Gateway inherited Read+Synchronize unexpectedly permits create/write/append/delete/security mutation.'
}
foreach ($requiredConfigGate in @(
    '#Requires -RunAsAdministrator',
    "mode = 'MT5_READ_ONLY_PROTECTED_IDENTITY'",
    'trading_lab.protected_identity_config inspect',
    'trading_lab.protected_identity_config render',
    'trading_lab.protected_identity_config validate',
    '[System.IO.File]::Replace',
    'Set-Acl -LiteralPath $configPath -AclObject $originalAcl',
    '[System.IO.File]::Replace($backupPath, $configPath, $failedPath, $true)',
    'Assert-ExactConfigAcl $restoredAcl',
    'real_loader_validated',
    'rollback_attempted',
    'hash_before',
    'hash_after',
    "trading_mode = 'OBSERVE_ONLY'",
    'mt5_access_enabled = $false'
)) {
    if (-not $protectedIdentitySource.Contains($requiredConfigGate)) {
        throw "Protected identity gate lacks transaction boundary: $requiredConfigGate"
    }
}
foreach ($forbiddenConfigGate in @(
    'MetaTrader5', 'initialize()', 'login(', 'order_check', 'order_send',
    'trading_lab.service', 'start_gateway', 'start_automaton', 'Invoke-Expression'
)) {
    if ($protectedIdentitySource.Contains($forbiddenConfigGate)) {
        throw "Protected identity gate contains forbidden action: $forbiddenConfigGate"
    }
}
foreach ($legacyApplySemantic in @(
    'demo_authorization_file_exists = $false',
    'demo_authorization_gateway_write = $false'
)) {
    if ($applySource.Contains($legacyApplySemantic)) {
        throw "ACL apply gate retains legacy authorization semantics: $legacyApplySemantic"
    }
}
foreach ($newApplySemantic in @(
    'Assert-ExactAuthorizationDirectoryAcl',
    'Assert-ExactAuthorizationArtifactAcl',
    'mt5-read-only-authorization-<UUID>.json',
    'demo_authorization_artifacts_verified = $true',
    'demo_authorization_gateway_mutation = $false'
)) {
    if (-not $applySource.Contains($newApplySemantic)) {
        throw "ACL apply gate lacks RunId artifact verification: $newApplySemantic"
    }
}

$dryRunIndex = $source.IndexOf('if (-not $Apply)')
if ($dryRunIndex -lt 0) { throw 'ACL script has no explicit dry-run exit.' }
foreach ($mutation in @('New-Item -ItemType Directory', 'WriteAllText', 'Set-Acl -LiteralPath')) {
    $mutationIndex = $source.IndexOf($mutation)
    if ($mutationIndex -ge 0 -and $mutationIndex -lt $dryRunIndex) {
        throw "ACL dry-run can reach mutation before its exit: $mutation"
    }
}

Write-Host 'ACL PowerShell AST and static least-privilege checks passed.'
