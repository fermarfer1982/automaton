#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$workspace = 'C:\automaton'
$target = 'C:\ProgramData\AutomatonMT5Lab\control\demo-authorization'
$reportRoot = 'C:\ProgramData\AutomatonMT5Lab\maintenance\mt5-read-only-preconditions'
$policyPath = 'C:\automaton\config\windows-acl-policy.json'
$normalizedRunId = ([guid]::ParseExact($RunId, 'D')).ToString('D').ToLowerInvariant()
$reportPath = Join-Path $reportRoot "authorization-acl-$normalizedRunId.json"
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
$gatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$agentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$fullControl = 2032127L
$readRights = 1179785L
$readExecuteRights = 1179817L
$mutationRights = 2L -bor 4L -bor 16L -bor 64L -bor 256L -bor 65536L -bor 262144L -bor 524288L

$report = [ordered]@{
    schema_version = 1
    mode = 'MT5_READ_ONLY_AUTHORIZATION_ACL'
    run_id = $normalizedRunId
    apply_requested = [bool]$Apply
    status = 'FAIL_INITIALIZING'
    target = $target
    report_path = $reportPath
    maintenance_identity = $null
    maintenance_sid = $null
    before_state = $null
    before_snapshot = $null
    proposed_snapshot = $null
    after_snapshot = $null
    artifact_count = 0
    artifacts_verified_without_modification = $false
    set_acl_call_count = 0
    rollback_attempted = $false
    rollback_succeeded = $false
    gateway_directory_read_execute = $false
    gateway_child_read_inheritance = $false
    gateway_mutation_rights = $false
    agent_access = $false
    mt5_accessed = $false
    gateway_started = $false
    automaton_started = $false
    trading_mode = 'OBSERVE_ONLY'
    error = $null
    started_at_utc = [DateTime]::UtcNow.ToString('o')
    completed_at_utc = $null
}

function Get-CanonicalPath([string] $Path) {
    if (-not [System.IO.Path]::IsPathRooted($Path)) { throw "Path must be absolute: $Path" }
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Resolve-OwnerSid([string] $Owner) {
    try {
        return ([System.Security.Principal.NTAccount]::new($Owner)).Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    } catch { return $Owner }
}

function Get-AclSnapshot([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return [pscustomobject]@{
        path = $Path
        is_directory = [bool]$item.PSIsContainer
        reparse = [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
        owner_sid = Resolve-OwnerSid $acl.Owner
        protected = [bool]$acl.AreAccessRulesProtected
        sddl = $acl.Sddl
        rules = @($acl.Access | ForEach-Object {
            $sid = try {
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch { 'UNRESOLVED:' + $_.IdentityReference.Value }
            [pscustomobject]@{
                sid = $sid
                type = $_.AccessControlType.ToString()
                rights = [int64]$_.FileSystemRights
                inherited = [bool]$_.IsInherited
                inheritance_flags = $_.InheritanceFlags.ToString()
                propagation_flags = $_.PropagationFlags.ToString()
            }
        })
    }
}

function Get-AclSnapshotFromObject([System.Security.AccessControl.DirectorySecurity] $Acl) {
    $rules = @($Acl.GetAccessRules(
        $true,
        $false,
        [System.Security.Principal.SecurityIdentifier]
    ) | ForEach-Object {
        [pscustomobject]@{
            sid = $_.IdentityReference.Value
            type = $_.AccessControlType.ToString()
            rights = [int64]$_.FileSystemRights
            inherited = [bool]$_.IsInherited
            inheritance_flags = $_.InheritanceFlags.ToString()
            propagation_flags = $_.PropagationFlags.ToString()
        }
    })
    return [pscustomobject]@{
        path = $target
        is_directory = $true
        reparse = $false
        owner_sid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        protected = [bool]$Acl.AreAccessRulesProtected
        sddl = $Acl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::All
        )
        rules = $rules
    }
}

function Test-ExactRule($Rule, [string] $Sid, [int64] $Rights, [bool] $Inherited,
    [string] $Inheritance, [string] $Propagation) {
    return $Rule.sid -eq $Sid -and $Rule.type -eq 'Allow' -and
        [int64]$Rule.rights -eq $Rights -and [bool]$Rule.inherited -eq $Inherited -and
        $Rule.inheritance_flags -eq $Inheritance -and $Rule.propagation_flags -eq $Propagation
}

function Test-RuleSet($Snapshot, [object[]] $Expected) {
    if (@($Snapshot.rules).Count -ne $Expected.Count) { return $false }
    $remaining = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $Snapshot.rules) { $remaining.Add($rule) }
    foreach ($item in $Expected) {
        $match = @($remaining | Where-Object {
            Test-ExactRule $_ $item.sid ([int64]$item.rights) ([bool]$item.inherited) `
                $item.inheritance $item.propagation
        } | Select-Object -First 1)
        if ($match.Count -ne 1) { return $false }
        [void]$remaining.Remove($match[0])
    }
    return $remaining.Count -eq 0
}

function Get-ParentState($Snapshot) {
    if (-not $Snapshot.is_directory -or $Snapshot.reparse -or
        $Snapshot.owner_sid -ne $administratorsSid -or -not $Snapshot.protected) {
        return 'UNKNOWN'
    }
    $base = @(
        [pscustomobject]@{ sid = $systemSid; rights = $fullControl; inherited = $false; inheritance = 'ContainerInherit, ObjectInherit'; propagation = 'None' },
        [pscustomobject]@{ sid = $administratorsSid; rights = $fullControl; inherited = $false; inheritance = 'ContainerInherit, ObjectInherit'; propagation = 'None' },
        [pscustomobject]@{ sid = $gatewaySid; rights = $readExecuteRights; inherited = $false; inheritance = 'None'; propagation = 'None' }
    )
    if (Test-RuleSet $Snapshot $base) { return 'KNOWN_LEGACY_DIRECTORY_ONLY' }
    $canonical = @($base) + @(
        [pscustomobject]@{ sid = $gatewaySid; rights = $readRights; inherited = $false; inheritance = 'ObjectInherit'; propagation = 'InheritOnly' }
    )
    if (Test-RuleSet $Snapshot $canonical) { return 'CANONICAL_RUN_ID_ARTIFACTS' }
    return 'UNKNOWN'
}

function Assert-ArtifactPolicy([string] $Path) {
    $name = [System.IO.Path]::GetFileName($Path)
    if ($name -cnotmatch '^mt5-read-only-authorization-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$' -or
        (Get-CanonicalPath ([System.IO.Path]::GetDirectoryName($Path))) -ne (Get-CanonicalPath $target)) {
        throw "Unexpected authorization artifact: $Path"
    }
    $snapshot = Get-AclSnapshot $Path
    $expected = @(
        [pscustomobject]@{ sid = $systemSid; rights = $fullControl; inherited = $true; inheritance = 'None'; propagation = 'None' },
        [pscustomobject]@{ sid = $administratorsSid; rights = $fullControl; inherited = $true; inheritance = 'None'; propagation = 'None' },
        [pscustomobject]@{ sid = $gatewaySid; rights = $readRights; inherited = $true; inheritance = 'None'; propagation = 'None' }
    )
    if ($snapshot.is_directory -or $snapshot.reparse -or $snapshot.protected -or
        $snapshot.owner_sid -ne $administratorsSid -or -not (Test-RuleSet $snapshot $expected)) {
        throw "Authorization artifact ACL is not canonical: $Path"
    }
}

function New-CanonicalAcl {
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new($administratorsSid))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($sid),
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new($gatewaySid),
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    ))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new($gatewaySid),
        [System.Security.AccessControl.FileSystemRights]::Read,
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [System.Security.AccessControl.PropagationFlags]::InheritOnly,
        [System.Security.AccessControl.AccessControlType]::Allow
    ))
    return $acl
}

function Write-DurableReport {
    if (-not (Test-Path -LiteralPath $reportRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $reportRoot -ErrorAction Stop | Out-Null
    }
    $item = Get-Item -LiteralPath $reportRoot -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'Maintenance report root cannot be a reparse point.'
    }
    $stream = [System.IO.File]::Open(
        $reportPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write(($report | ConvertTo-Json -Depth 12)) } finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
}

$beforeAcl = $null
try {
    if ((Get-CanonicalPath $target) -ne 'C:\ProgramData\AutomatonMT5Lab\control\demo-authorization') {
        throw 'Target path is not the exact protected authorization directory.'
    }
    foreach ($path in @($workspace, $target, $policyPath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Required path is a reparse point: $path"
        }
    }
    $policy = [System.IO.File]::ReadAllText($policyPath, [System.Text.Encoding]::UTF8) |
        ConvertFrom-Json -ErrorAction Stop
    $maintenanceIdentity = [string]$policy.maintenance_identity
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $current.Name.Equals($maintenanceIdentity, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Current token is not the canonical maintenance identity.'
    }
    $maintenanceUser = Get-LocalUser -SID $current.User -ErrorAction Stop
    $adminMembers = @(Get-LocalGroupMember -SID ([System.Security.Principal.SecurityIdentifier]::new($administratorsSid)) |
        ForEach-Object { $_.SID.Value })
    if (-not $maintenanceUser.Enabled -or $maintenanceUser.PrincipalSource.ToString() -ne 'Local' -or
        $adminMembers -notcontains $current.User.Value) {
        throw 'Maintenance identity must be an enabled local direct Administrator.'
    }
    $report.maintenance_identity = $maintenanceIdentity
    $report.maintenance_sid = $current.User.Value

    $beforeAcl = Get-Acl -LiteralPath $target -ErrorAction Stop
    $before = Get-AclSnapshot $target
    $state = Get-ParentState $before
    if ($state -eq 'UNKNOWN') { throw 'Authorization directory ACL is not a known migration state.' }
    $report.before_state = $state
    $report.before_snapshot = $before
    $report.proposed_snapshot = Get-AclSnapshotFromObject (New-CanonicalAcl)

    $children = @(Get-ChildItem -LiteralPath $target -Force)
    foreach ($child in $children) { Assert-ArtifactPolicy $child.FullName }
    if ($state -eq 'KNOWN_LEGACY_DIRECTORY_ONLY' -and $children.Count -ne 0) {
        throw 'Legacy parent with existing artifacts cannot be migrated without touching child ACLs.'
    }
    $report.artifact_count = $children.Count
    $report.artifacts_verified_without_modification = $true

    if ($Apply -and $state -eq 'KNOWN_LEGACY_DIRECTORY_ONLY') {
        Set-Acl -LiteralPath $target -AclObject (New-CanonicalAcl)
        $report.set_acl_call_count = 1
    }
    $after = Get-AclSnapshot $target
    $report.after_snapshot = $after
    $afterState = Get-ParentState $after
    if ($Apply -and $afterState -ne 'CANONICAL_RUN_ID_ARTIFACTS') {
        throw 'Canonical authorization ACL postcondition failed.'
    }
    if (-not $Apply -and $after.sddl -ne $before.sddl) {
        throw 'Dry run changed the authorization ACL.'
    }
    $gatewayRights = 0L
    foreach ($rule in $after.rules | Where-Object { $_.sid -eq $gatewaySid -and $_.type -eq 'Allow' }) {
        $gatewayRights = $gatewayRights -bor [int64]$rule.rights
    }
    $report.gateway_directory_read_execute = (($gatewayRights -band $readExecuteRights) -eq $readExecuteRights)
    $report.gateway_child_read_inheritance = ($afterState -eq 'CANONICAL_RUN_ID_ARTIFACTS')
    $report.gateway_mutation_rights = (($gatewayRights -band $mutationRights) -ne 0)
    $report.agent_access = @($after.rules | Where-Object { $_.sid -eq $agentSid }).Count -ne 0
    if ($report.gateway_mutation_rights -or $report.agent_access) {
        throw 'Canonical policy grants forbidden mutation or Agent access.'
    }
    $report.status = if ($Apply) { 'PASS' } else { 'DRY_RUN_PASS' }
} catch {
    $report.error = $_.Exception.Message
    if ($Apply -and $report.set_acl_call_count -gt 0 -and $null -ne $beforeAcl) {
        $report.rollback_attempted = $true
        try {
            Set-Acl -LiteralPath $target -AclObject $beforeAcl
            $report.rollback_succeeded = ((Get-AclSnapshot $target).sddl -eq $report.before_snapshot.sddl)
        } catch { $report.rollback_succeeded = $false }
    }
    $report.status = 'FAIL_CLOSED'
} finally {
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    try { Write-DurableReport } catch {
        [Console]::Error.WriteLine("Unable to persist ACL migration report: $($_.Exception.Message)")
        throw
    }
}

$report | ConvertTo-Json -Depth 12
if ($report.status -notin @('PASS', 'DRY_RUN_PASS')) { exit 1 }
