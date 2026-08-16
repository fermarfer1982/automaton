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

$dryRunIndex = $source.IndexOf('if (-not $Apply)')
if ($dryRunIndex -lt 0) { throw 'ACL script has no explicit dry-run exit.' }
foreach ($mutation in @('New-Item -ItemType Directory', 'WriteAllText', 'Set-Acl -LiteralPath')) {
    $mutationIndex = $source.IndexOf($mutation)
    if ($mutationIndex -ge 0 -and $mutationIndex -lt $dryRunIndex) {
        throw "ACL dry-run can reach mutation before its exit: $mutation"
    }
}

Write-Host 'ACL PowerShell AST and static least-privilege checks passed.'
