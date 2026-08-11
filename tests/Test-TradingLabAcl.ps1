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
)) {
    if (-not $source.Contains($required)) {
        throw "ACL source is missing required invariant: $required"
    }
}
if ($source.Contains("gateway_writable_data") -or $source.Contains("Join-Path `$root 'data'")) {
    throw 'ACL source reintroduced a globally writable data domain.'
}

$dryRunIndex = $source.IndexOf('if (-not $Apply)')
if ($dryRunIndex -lt 0) { throw 'ACL script has no explicit dry-run exit.' }
foreach ($mutation in @('New-Item -ItemType Directory', 'WriteAllText', 'Set-Acl -LiteralPath')) {
    if ($source.IndexOf($mutation) -lt $dryRunIndex) {
        throw "ACL dry-run can reach mutation before its exit: $mutation"
    }
}

Write-Host 'ACL PowerShell AST and static least-privilege checks passed.'
