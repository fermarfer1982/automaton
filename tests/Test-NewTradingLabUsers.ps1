[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptPath = Join-Path $workspace 'scripts\New-TradingLabUsers.ps1'
$source = Get-Content -Raw -Encoding UTF8 -LiteralPath $scriptPath

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$parseErrors
)
Assert-True ($parseErrors.Count -eq 0) 'Provisioning script has PowerShell parse errors.'

Assert-True `
    ($source.Contains("`$localUser = Get-LocalUser -Name `$User.Name -ErrorAction Stop")) `
    'Users membership must refresh a LocalUser object.'
Assert-True `
    ($source.Contains('Add-LocalGroupMember -SID $usersGroupSid -Member $localUser')) `
    'Add-LocalGroupMember must receive a LocalPrincipal object.'
Assert-True `
    (-not $source.Contains('Add-LocalGroupMember -SID $usersGroupSid -Member $User.SID')) `
    'Regression: a SecurityIdentifier must not be passed as -Member.'
Assert-True `
    ($source.Contains("S-1-5-32-545")) `
    'The localized Users group must be selected by its well-known SID.'
Assert-True `
    ($source.Contains("`$existing = Get-LocalUser -Name `$definition.Name -ErrorAction Stop")) `
    'Existing and newly-created accounts must converge through Get-LocalUser.'
Assert-True `
    ($source.Contains("`$existing.PrincipalSource.ToString() -ne 'Local'")) `
    'The provisioning flow must reject non-local principals.'
Assert-True `
    ($source.IndexOf('$unexpected.Count -gt 0') -lt $source.IndexOf('Add-LocalGroupMember')) `
    'Unexpected or privileged groups must fail before Users membership changes.'
Assert-True `
    ($source.IndexOf('if ($null -eq $existing)') -lt $source.IndexOf('Read-Host')) `
    'Password prompting must remain inside the missing-user branch.'
Assert-True `
    (-not ($source -match 'Set-LocalUser|Remove-LocalUser|Set-Acl')) `
    'The provisioning script must not reset users, passwords, or ACLs.'

# Reproduce the original binder mismatch without changing any group. The
# currently executing local account is used only as a read-only typed fixture.
$fixture = Get-LocalUser -Name $env:USERNAME -ErrorAction Stop
function Test-LocalPrincipalBinding(
    [Microsoft.PowerShell.Commands.LocalPrincipal[]] $Member
) {
    return $Member[0].SID.Value
}
$boundSid = Test-LocalPrincipalBinding -Member $fixture
Assert-True ($boundSid -eq $fixture.SID.Value) 'LocalUser did not bind as LocalPrincipal.'
$sidBindingFailed = $false
try {
    [void](Test-LocalPrincipalBinding -Member $fixture.SID)
} catch {
    $sidBindingFailed = $true
}
Assert-True $sidBindingFailed 'SecurityIdentifier unexpectedly bound as LocalPrincipal.'

[pscustomobject]@{
    powershell_ast = 'PASS'
    local_principal_binding = 'PASS'
    security_identifier_regression = 'PASS'
    users_group_sid = 'S-1-5-32-545'
    idempotent_resume_guards = 'PASS'
    privileged_group_fail_closed = 'PASS'
} | ConvertTo-Json
