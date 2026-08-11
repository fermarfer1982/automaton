#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$usersGroupSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$accountDefinitions = @(
    [pscustomobject]@{
        Name = 'AutomatonAgent'
        Description = 'Automaton MT5 Lab agent identity'
    },
    [pscustomobject]@{
        Name = 'AutomatonGateway'
        Description = 'Automaton MT5 Lab gateway and interactive MT5 identity'
    }
)

function Get-DirectLocalGroups(
    [System.Security.Principal.SecurityIdentifier] $UserSid
) {
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($group in Get-LocalGroup) {
        try {
            $members = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop)
        } catch {
            throw "Unable to verify membership of local group $($group.Name): $($_.Exception.Message)"
        }
        if ($members | Where-Object { $null -ne $_.SID -and $_.SID.Value -eq $UserSid.Value }) {
            $result.Add([pscustomobject]@{
                name = $group.Name
                sid = $group.SID.Value
            })
        }
    }
    return @($result)
}

function Assert-MinimumGroupMembership(
    [Microsoft.PowerShell.Commands.LocalUser] $User
) {
    $memberships = @(Get-DirectLocalGroups $User.SID)
    $unexpected = @($memberships | Where-Object { $_.sid -ne $usersGroupSid.Value })
    if ($unexpected.Count -gt 0) {
        $details = ($unexpected | ForEach-Object { "$($_.name) [$($_.sid)]" }) -join ', '
        throw "$($User.Name) belongs to non-minimal local groups: $details"
    }
    if (-not ($memberships | Where-Object { $_.sid -eq $usersGroupSid.Value })) {
        Add-LocalGroupMember -SID $usersGroupSid -Member $User.SID
        $memberships = @(Get-DirectLocalGroups $User.SID)
    }
    if (
        $memberships.Count -ne 1 -or
        $memberships[0].sid -ne $usersGroupSid.Value
    ) {
        throw "$($User.Name) does not have the required Users-only membership."
    }
    return $memberships
}

$results = [System.Collections.Generic.List[object]]::new()
foreach ($definition in $accountDefinitions) {
    $existing = Get-LocalUser -Name $definition.Name -ErrorAction SilentlyContinue
    $created = $false
    if ($null -eq $existing) {
        Write-Host "Creating local standard user $($definition.Name)."
        $password = Read-Host "Enter the Windows password for $($definition.Name)" -AsSecureString
        try {
            if ($password.Length -eq 0) {
                throw 'An empty password is forbidden for laboratory identities.'
            }
            $existing = New-LocalUser `
                -Name $definition.Name `
                -Password $password `
                -Description $definition.Description `
                -PasswordNeverExpires:$false `
                -UserMayNotChangePassword:$false
            $created = $true
        } finally {
            if ($null -ne $password) { $password.Dispose() }
        }
    }
    if (-not $existing.Enabled) {
        throw "$($definition.Name) exists but is disabled; refusing to change it automatically."
    }
    $groups = @(Assert-MinimumGroupMembership $existing)
    $results.Add([pscustomobject]@{
        name = $existing.Name
        sid = $existing.SID.Value
        enabled = $existing.Enabled
        created = $created
        administrator = $false
        direct_local_groups = $groups
    })
}

[pscustomobject]@{
    users = @($results)
    allowed_direct_local_group = [pscustomobject]@{
        name = (Get-LocalGroup -SID $usersGroupSid).Name
        sid = $usersGroupSid.Value
    }
    passwords_logged_or_persisted = $false
    acl_applied = $false
} | ConvertTo-Json -Depth 6
