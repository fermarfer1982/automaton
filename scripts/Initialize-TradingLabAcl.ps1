[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $GatewayIdentity,
    [Parameter(Mandatory = $true)] [string] $AutomatonIdentity,
    [string] $LabRoot = 'C:\ProgramData\AutomatonMT5Lab',
    [Parameter(Mandatory = $true)] [string] $AutomatonStateDir,
    [string] $WorkspaceRoot = 'C:\automaton',
    [string] $AclPolicyPath,
    [string] $ProgressPath,
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedExistingConfigSha256,
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TradingLabAclBootstrap.ps1')
$pinnedExistingConfig = $PSBoundParameters.ContainsKey('ExpectedExistingConfigSha256')
$normalizedExpectedConfigSha256 = if ($pinnedExistingConfig) {
    $ExpectedExistingConfigSha256.ToLowerInvariant()
} else { $null }

function Get-CanonicalPath([string] $Value) {
    if (-not [System.IO.Path]::IsPathRooted($Value)) {
        throw "All paths must be absolute: $Value"
    }
    return [System.IO.Path]::GetFullPath($Value).TrimEnd('\')
}

function Test-PathOverlap([string] $First, [string] $Second) {
    $a = (Get-CanonicalPath $First) + '\'
    $b = (Get-CanonicalPath $Second) + '\'
    return $a.StartsWith($b, [System.StringComparison]::OrdinalIgnoreCase) -or
           $b.StartsWith($a, [System.StringComparison]::OrdinalIgnoreCase)
}

function Resolve-Sid([string] $Identity) {
    return Resolve-TradingLabAclIdentitySid $Identity
}

function Test-IsElevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

$root = Get-CanonicalPath $LabRoot
$state = Get-CanonicalPath $AutomatonStateDir
$workspace = Get-CanonicalPath $WorkspaceRoot
$policyPath = if ([string]::IsNullOrWhiteSpace($AclPolicyPath)) {
    Join-Path $workspace 'config\windows-acl-policy.json'
} else { Get-CanonicalPath $AclPolicyPath }
if ($policyPath -ne (Join-Path $workspace 'config\windows-acl-policy.json')) {
    throw 'Windows ACL policy must be the reviewed workspace policy.'
}
$aclPolicy = Read-TradingLabWindowsAclPolicy $policyPath
$control = Join-Path $root 'control'
$configFile = Join-Path $control 'trading.yaml'
$killSwitchFile = Join-Path $control 'STOP_TRADING'
$demoAuthorization = Join-Path $control 'demo-authorization'
$ipc = Join-Path $root 'ipc'
$automatonKeyFile = Join-Path $ipc 'automaton.key'
$observationKeyFile = Join-Path $ipc 'observation.key'
$researchKeyFile = Join-Path $ipc 'research.key'
$operational = Join-Path $root 'operational'
$research = Join-Path $root 'research'
$audit = Join-Path $root 'audit'
$auditSqlite = Join-Path $audit 'sqlite'
$auditJournal = Join-Path $audit 'journal'
$auditJournalFile = Join-Path $auditJournal 'audit.jsonl'
$logs = Join-Path $root 'logs'
$gatewayLogs = Join-Path $logs 'gateway'
$securityLogs = Join-Path $logs 'security'
$securityLogFile = Join-Path $securityLogs 'security.log'
$driveRoot = [System.IO.Path]::GetPathRoot($root).TrimEnd('\')

if ($root -eq $driveRoot -or $root -ieq 'C:\ProgramData' -or $state -ieq 'C:\Users') {
    throw 'Refusing a broad ACL target.'
}
if (Test-PathOverlap $root $workspace -or Test-PathOverlap $state $workspace) {
    throw 'Laboratory ACL targets must remain outside the workspace.'
}
if (Test-PathOverlap $root $state) {
    throw 'Gateway paths and Automaton state must not overlap.'
}

$gatewaySid = Resolve-Sid $GatewayIdentity
$automatonSid = Resolve-Sid $AutomatonIdentity
$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$usersGroupSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$maintenanceSid = Resolve-Sid $aclPolicy.maintenance_identity
if ($gatewaySid.Value -eq $automatonSid.Value) {
    throw 'Gateway and Automaton identities must be distinct.'
}
if ($maintenanceSid.Value -in @(
    $gatewaySid.Value, $automatonSid.Value, $systemSid.Value, $administratorsSid.Value
)) {
    throw 'Maintenance identity conflicts with a protected principal.'
}
function Get-DirectLocalGroupSids(
    [System.Security.Principal.SecurityIdentifier] $UserSid
) {
    $groupSids = [System.Collections.Generic.List[string]]::new()
    foreach ($group in Get-LocalGroup) {
        $members = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop)
        if ($members | Where-Object { $null -ne $_.SID -and $_.SID.Value -eq $UserSid.Value }) {
            $groupSids.Add($group.SID.Value)
        }
    }
    return @($groupSids)
}

$identityChecks = [System.Collections.Generic.List[object]]::new()
foreach ($runtimeIdentity in @(
    [pscustomobject]@{ Name = 'Gateway'; Sid = $gatewaySid },
    [pscustomobject]@{ Name = 'Automaton'; Sid = $automatonSid }
)) {
    $localUser = Get-LocalUser -SID $runtimeIdentity.Sid -ErrorAction Stop
    if (-not $localUser.Enabled -or $localUser.PrincipalSource.ToString() -ne 'Local') {
        throw "$($runtimeIdentity.Name) identity must be an enabled local user."
    }
    $directGroups = @(Get-DirectLocalGroupSids $runtimeIdentity.Sid)
    if ($directGroups.Count -ne 1 -or $directGroups[0] -ne $usersGroupSid.Value) {
        throw "$($runtimeIdentity.Name) identity must belong directly only to BUILTIN\Users."
    }
    $identityChecks.Add([pscustomobject]@{
        role = $runtimeIdentity.Name
        sid = $runtimeIdentity.Sid.Value
        enabled = $true
        principal_source = 'Local'
        direct_local_group_sids = $directGroups
    })
}
$administratorMembers = @(Get-LocalGroupMember -SID $administratorsSid | ForEach-Object { $_.SID.Value })
if ($administratorMembers -contains $gatewaySid.Value -or $administratorMembers -contains $automatonSid.Value) {
    throw 'Gateway and Automaton identities must be non-administrators.'
}
$maintenanceUser = Get-LocalUser -SID $maintenanceSid -ErrorAction Stop
if (-not $maintenanceUser.Enabled -or $maintenanceUser.PrincipalSource.ToString() -ne 'Local' -or
    $administratorMembers -notcontains $maintenanceSid.Value) {
    throw 'Maintenance identity must be an enabled local direct Administrator.'
}
$maintenanceTargetKeys = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@($aclPolicy.maintenance_targets.PSObject.Properties.Name),
    [System.StringComparer]::Ordinal
)

function Get-MaintenanceTargetKey([string] $Path) {
    $canonical = Get-CanonicalPath $Path
    $byPath = @{}
    $byPath[(Get-CanonicalPath $root)] = 'lab_root'
    $byPath[(Get-CanonicalPath $operational)] = 'operational'
    $byPath[(Get-CanonicalPath $logs)] = 'logs_root'
    $byPath[(Get-CanonicalPath $gatewayLogs)] = 'gateway_logs'
    $byPath[(Get-CanonicalPath $securityLogs)] = 'security_logs'
    $byPath[(Get-CanonicalPath $state)] = 'automaton_state'
    if ($byPath.ContainsKey($canonical)) { return $byPath[$canonical] }
    return $null
}

function New-AclProposal(
    [string] $Path,
    [string] $Domain,
    [System.Security.Principal.SecurityIdentifier[]] $Principals,
    [string[]] $Rights,
    [string] $ChildPropagation,
    [string[]] $RepresentativeTargets
) {
    $policyKey = Get-MaintenanceTargetKey $Path
    $entries = [System.Collections.Generic.List[object]]::new()
    $entries.Add([pscustomobject]@{
        principal = 'NT AUTHORITY\SYSTEM'; sid = $systemSid.Value
        rights = 'FullControl'; type = 'Allow'
    })
    $entries.Add([pscustomobject]@{
        principal = 'BUILTIN\Administrators'; sid = $administratorsSid.Value
        rights = 'FullControl'; type = 'Allow'
    })
    if ($null -ne $policyKey -and $maintenanceTargetKeys.Contains($policyKey)) {
        $entries.Add([pscustomobject]@{
            principal = $aclPolicy.maintenance_identity; sid = $maintenanceSid.Value
            rights = 'FullControl'; type = 'Allow'
        })
    }
    for ($index = 0; $index -lt $Principals.Count; $index++) {
        $entries.Add([pscustomobject]@{
            principal = $Principals[$index].Value; sid = $Principals[$index].Value
            rights = $Rights[$index]; type = 'Allow'
        })
    }
    return [pscustomobject]@{
        path = $Path
        policy_key = $policyKey
        domain = $Domain
        inheritance_protected = $true
        inherited_aces_preserved = $false
        deny_aces = 0
        child_propagation = $ChildPropagation
        owner = 'BUILTIN\Administrators'
        entries = @($entries)
        representative_targets = $RepresentativeTargets
    }
}

function New-ControlAclProposal {
    return [pscustomobject]@{
        path = $control
        policy_key = $null
        domain = 'human_managed_control_directory'
        inheritance_protected = $true
        inherited_aces_preserved = $false
        deny_aces = 0
        child_propagation = 'Recovery principals ContainerInherit,ObjectInherit; Gateway ThisObjectOnly'
        owner = 'BUILTIN\Administrators'
        entries = @(
            [pscustomobject]@{
                principal = 'NT AUTHORITY\SYSTEM'; sid = $systemSid.Value
                rights = 'FullControl'; type = 'Allow'; inheritance_flags = 'ContainerInherit,ObjectInherit'
                propagation_flags = 'None'
            }
            [pscustomobject]@{
                principal = 'BUILTIN\Administrators'; sid = $administratorsSid.Value
                rights = 'FullControl'; type = 'Allow'; inheritance_flags = 'ContainerInherit,ObjectInherit'
                propagation_flags = 'None'
            }
            [pscustomobject]@{
                principal = $gatewaySid.Value; sid = $gatewaySid.Value
                rights = 'ReadAndExecute,Synchronize'; type = 'Allow'; inheritance_flags = 'None'
                propagation_flags = 'None'
            }
        )
        representative_targets = @('trading.yaml', 'STOP_TRADING', 'demo-authorization')
    }
}

function New-DemoAuthorizationAclProposal {
    return [pscustomobject]@{
        path = $demoAuthorization
        policy_key = $null
        domain = 'human_mt5_read_only_authorization_directory'
        inheritance_protected = $true
        inherited_aces_preserved = $false
        deny_aces = 0
        child_propagation = 'Gateway ObjectInherit+InheritOnly to files only'
        owner = 'BUILTIN\Administrators'
        entries = @(
            [pscustomobject]@{
                principal = 'NT AUTHORITY\SYSTEM'; sid = $systemSid.Value
                rights = 'FullControl'; type = 'Allow'; inheritance_flags = 'ContainerInherit,ObjectInherit'
                propagation_flags = 'None'
            }
            [pscustomobject]@{
                principal = 'BUILTIN\Administrators'; sid = $administratorsSid.Value
                rights = 'FullControl'; type = 'Allow'; inheritance_flags = 'ContainerInherit,ObjectInherit'
                propagation_flags = 'None'
            }
            [pscustomobject]@{
                principal = $gatewaySid.Value; sid = $gatewaySid.Value
                rights = 'ReadAndExecute,Synchronize'; type = 'Allow'; inheritance_flags = 'None'
                propagation_flags = 'None'
            }
            [pscustomobject]@{
                principal = $gatewaySid.Value; sid = $gatewaySid.Value
                rights = 'Read,Synchronize'; type = 'Allow'; inheritance_flags = 'ObjectInherit'
                propagation_flags = 'InheritOnly'
            }
        )
        representative_targets = @('mt5-read-only-authorization-<UUID>.json')
    }
}

$aclProposals = @(
    New-AclProposal $root 'lab_root_navigation' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) 'ThisObjectOnly' @('control', 'ipc', 'operational', 'research', 'audit', 'logs')
    New-AclProposal $workspace 'source_read_only' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) 'ContainerInherit,ObjectInherit' @(
        'trading_lab', 'src', 'scripts', 'tests', 'config', 'package files',
        'Python source', 'TypeScript source', '.runtime', '.venv'
    )
    New-ControlAclProposal
    New-AclProposal $configFile 'human_managed_config_file' @($gatewaySid) @(
        'Read'
    ) 'None' @('trading.yaml')
    New-AclProposal $killSwitchFile 'human_kill_switch_file' @($gatewaySid) @(
        'Read'
    ) 'None' @('STOP_TRADING')
    New-DemoAuthorizationAclProposal
    New-AclProposal $ipc 'shared_ipc_directory' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) 'ThisObjectOnly' @('automaton.key', 'observation.key', 'research.key')
    New-AclProposal $automatonKeyFile 'gateway_automaton_ipc_key_file' @($gatewaySid) @(
        'Read'
    ) 'None' @('automaton.key')
    New-AclProposal $observationKeyFile 'shared_observation_ipc_key_file' @($gatewaySid, $automatonSid) @(
        'Read', 'Read'
    ) 'None' @('observation.key')
    New-AclProposal $researchKeyFile 'shared_research_ipc_key_file' @($gatewaySid, $automatonSid) @(
        'Read', 'Read'
    ) 'None' @('research.key')
    New-AclProposal $operational 'gateway_operational_data' @($gatewaySid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @('gateway.lock', 'idempotency', 'lifecycle', 'reconciliation')
    New-AclProposal $research 'gateway_research_data' @($gatewaySid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @('research.db', 'research.db-wal', 'research.db-shm')
    New-AclProposal $audit 'audit_navigation' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('sqlite', 'journal')
    New-AclProposal $auditSqlite 'gateway_audit_sqlite' @($gatewaySid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @('audit.db', 'audit.db-wal', 'audit.db-shm')
    New-AclProposal $auditJournal 'gateway_audit_journal_directory' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('audit.jsonl')
    New-AclProposal $auditJournalFile 'gateway_audit_journal_append_file' @($gatewaySid) @(
        'Read,AppendData,Synchronize'
    ) 'None' @('audit.jsonl; pre-created by Administrator')
    New-AclProposal $logs 'logs_navigation' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('gateway', 'security')
    New-AclProposal $gatewayLogs 'gateway_rotating_logs' @($gatewaySid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @('gateway.log', 'trading.log', 'UTC rotations')
    New-AclProposal $securityLogs 'gateway_security_log_directory' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('security.log')
    New-AclProposal $securityLogFile 'gateway_security_log_append_file' @($gatewaySid) @(
        'Read,AppendData,Synchronize'
    ) 'None' @('security.log; pre-created by Administrator; no automatic rotation')
    New-AclProposal $state 'agent_private_state' @($automatonSid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @(
        'Automaton context', 'agent memory', 'agent logs', 'last_processed_bar_timestamp'
    )
)

$plan = [pscustomobject]@{
    apply = [bool]$Apply
    gateway_sid = $gatewaySid.Value
    automaton_sid = $automatonSid.Value
    maintenance_identity = $aclPolicy.maintenance_identity
    maintenance_sid = $maintenanceSid.Value
    identity_checks = @($identityChecks)
    owner = 'BUILTIN\Administrators'
    inheritance = 'protected; inherited ACEs removed; explicit Allow ACEs only'
    deny_aces_used = $false
    sqlite_immutable = $false
    append_acl_claim = 'risk reduction only; negative runtime tests required after ACL application'
    precreated_by_administrator = @(
        $automatonKeyFile, $observationKeyFile, $researchKeyFile,
        $auditJournalFile, $securityLogFile
    )
    optional_human_asserted_files = @($killSwitchFile)
    authorization_artifact_pattern = 'mt5-read-only-authorization-<UUID>.json'
    acl_proposals = $aclProposals
}
$plan | ConvertTo-Json -Depth 8
if (-not $Apply) {
    Write-Host 'Dry run only. No directory, file, owner, inheritance, or ACE was changed.'
    exit 0
}

if (-not (Test-IsElevated)) {
    throw 'ACL application requires an elevated Administrator console.'
}
if (-not (Test-Path -LiteralPath $configFile -PathType Leaf)) {
    throw 'Human-reviewed control\trading.yaml must exist before any ACL mutation.'
}
if (Test-Path -LiteralPath (Join-Path $state 'wallet.json')) {
    throw 'Refusing to use an Automaton state directory containing a signing wallet.'
}
foreach ($existingRoot in @($root, $state, $workspace)) {
    if (Test-Path -LiteralPath $existingRoot) {
        $rootItem = Get-Item -LiteralPath $existingRoot -Force
        if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Refusing an ACL root that is a reparse point: $existingRoot"
        }
        if ($existingRoot -ne $workspace) {
            $unsafeReparse = Get-ChildItem -LiteralPath $existingRoot -Force -Recurse |
                Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint } |
                Select-Object -First 1
            if ($null -ne $unsafeReparse) {
                throw "Refusing a protected data tree containing a reparse point: $($unsafeReparse.FullName)"
            }
        }
    }
}

$protectedSourceDirectories = @(
    'trading_lab', 'src', 'scripts', 'tests', 'config', 'docs', 'packages\cli\src'
) | ForEach-Object { Join-Path $workspace $_ }
foreach ($protectedSourceDirectory in $protectedSourceDirectories) {
    if (-not (Test-Path -LiteralPath $protectedSourceDirectory -PathType Container)) {
        throw "Protected source directory is absent: $protectedSourceDirectory"
    }
    $unsafeReparse = Get-ChildItem -LiteralPath $protectedSourceDirectory -Force -Recurse |
        Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint } |
        Select-Object -First 1
    if ($null -ne $unsafeReparse) {
        throw "Protected source tree contains a reparse point: $($unsafeReparse.FullName)"
    }
}

$bootstrapTemplate = Join-Path $workspace 'config\trading.bootstrap-observe-only.yaml'
$preparedState = if ($pinnedExistingConfig) {
    Initialize-TradingLabBootstrapState `
        $root `
        $state `
        $bootstrapTemplate `
        -ExpectedExistingConfigSha256 $ExpectedExistingConfigSha256
} else {
    Initialize-TradingLabBootstrapState $root $state $bootstrapTemplate
}
if ($pinnedExistingConfig -and (
    -not [bool]$preparedState.config_valid -or
    [string]$preparedState.config_validation_mode -cne 'PINNED_EXISTING_SHA256' -or
    [string]$preparedState.config_sha256 -cne $normalizedExpectedConfigSha256 -or
    [bool]$preparedState.config_created -or
    -not [bool]$preparedState.config_reused
)) {
    throw 'Bootstrap did not preserve the pinned existing configuration contract.'
}

$authorizationPreflightChildren = @(Get-ChildItem -LiteralPath $demoAuthorization -Force)
foreach ($authorizationPreflightChild in $authorizationPreflightChildren) {
    if ($authorizationPreflightChild.PSIsContainer -or
        $authorizationPreflightChild.Name -cnotmatch '^mt5-read-only-authorization-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$' -or
        ($authorizationPreflightChild.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Unexpected authorization artifact: $($authorizationPreflightChild.FullName)"
    }
}

function New-AccessRule(
    [System.Security.Principal.SecurityIdentifier] $Sid,
    [System.Security.AccessControl.FileSystemRights] $Rights,
    [bool] $Directory,
    [bool] $Propagate
) {
    $inheritance = if ($Directory -and $Propagate) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    return [System.Security.AccessControl.FileSystemAccessRule]::new(
        $Sid, $Rights, $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
}

function Set-ExactAcl(
    [string] $Path,
    [System.Security.Principal.SecurityIdentifier[]] $Principals,
    [System.Security.AccessControl.FileSystemRights[]] $Rights,
    [bool] $Directory,
    [bool] $RuntimeRulesPropagate,
    [string] $MaintenancePolicyKey = ''
) {
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetOwner($administratorsSid)
    $security.SetAccessRuleProtection($true, $false)
    $security.AddAccessRule((New-AccessRule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl) $Directory $Directory))
    $security.AddAccessRule((New-AccessRule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl) $Directory $Directory))
    if ($MaintenancePolicyKey) {
        if (-not $maintenanceTargetKeys.Contains($MaintenancePolicyKey)) {
            throw "Unknown maintenance ACL policy key: $MaintenancePolicyKey"
        }
        $security.AddAccessRule((New-AccessRule $maintenanceSid ([System.Security.AccessControl.FileSystemRights]::FullControl) $Directory $Directory))
    }
    for ($index = 0; $index -lt $Principals.Count; $index++) {
        $security.AddAccessRule((New-AccessRule $Principals[$index] $Rights[$index] $Directory $RuntimeRulesPropagate))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
    if ($ProgressPath) {
        $progressRecord = [pscustomobject]@{
            path = $Path
            applied_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        [System.IO.File]::AppendAllText(
            $ProgressPath,
            (($progressRecord | ConvertTo-Json -Compress) + [Environment]::NewLine),
            [System.Text.UTF8Encoding]::new($false)
        )
    }
}

function Set-ExactTreeAcl(
    [string] $Path,
    [System.Security.Principal.SecurityIdentifier[]] $Principals,
    [System.Security.AccessControl.FileSystemRights[]] $Rights,
    [string] $MaintenancePolicyKey = ''
) {
    Set-ExactAcl $Path $Principals $Rights $true $true $MaintenancePolicyKey
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse) {
        Set-ExactAcl $item.FullName $Principals $Rights ([bool]$item.PSIsContainer) ([bool]$item.PSIsContainer) $MaintenancePolicyKey
    }
}

function Set-ExactControlAcl {
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($administratorsSid)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($principal in @($systemSid, $administratorsSid)) {
        $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $gatewaySid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $control -AclObject $security
    if ($ProgressPath) {
        $progressRecord = [pscustomobject]@{
            path = $control
            applied_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        [System.IO.File]::AppendAllText(
            $ProgressPath,
            (($progressRecord | ConvertTo-Json -Compress) + [Environment]::NewLine),
            [System.Text.UTF8Encoding]::new($false)
        )
    }
}

function Get-DemoAuthorizationAclSnapshot(
    [System.Security.AccessControl.FileSystemSecurity] $Security,
    [string] $Path
) {
    $ownerSid = $Security.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    $rules = @($Security.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    ) | ForEach-Object {
        [pscustomobject]@{
            sid = $_.IdentityReference.Value
            rights = [int64]$_.FileSystemRights
            access_type = [int]$_.AccessControlType
            inherited = [bool]$_.IsInherited
            inheritance_flags = [int]$_.InheritanceFlags
            propagation_flags = [int]$_.PropagationFlags
        }
    })
    # Group SID and descriptor-control serialization are intentionally excluded:
    # they do not grant access and are not part of this exact authorization policy.
    return [pscustomobject]@{
        path = $Path
        owner_sid = $ownerSid
        protected = [bool]$Security.AreAccessRulesProtected
        rules = $rules
    }
}

function New-DemoAuthorizationAclRule(
    [System.Security.Principal.SecurityIdentifier] $Sid,
    [System.Security.AccessControl.FileSystemRights] $Rights,
    [bool] $Inherited,
    [System.Security.AccessControl.InheritanceFlags] $InheritanceFlags,
    [System.Security.AccessControl.PropagationFlags] $PropagationFlags
) {
    return [pscustomobject]@{
        sid = $Sid.Value
        rights = [int64]$Rights
        access_type = [int][System.Security.AccessControl.AccessControlType]::Allow
        inherited = $Inherited
        inheritance_flags = [int]$InheritanceFlags
        propagation_flags = [int]$PropagationFlags
    }
}

function Test-DemoAuthorizationAclRuleExact($Actual, $Expected) {
    return [string]$Actual.sid -ceq [string]$Expected.sid -and
        [int64]$Actual.rights -eq [int64]$Expected.rights -and
        [int]$Actual.access_type -eq [int]$Expected.access_type -and
        [bool]$Actual.inherited -eq [bool]$Expected.inherited -and
        [int]$Actual.inheritance_flags -eq [int]$Expected.inheritance_flags -and
        [int]$Actual.propagation_flags -eq [int]$Expected.propagation_flags
}

function Assert-DemoAuthorizationAclRuleSet(
    $Snapshot,
    [object[]] $ExpectedRules,
    [bool] $RulesMustBeInherited
) {
    $actualRules = @($Snapshot.rules)
    if ($actualRules.Count -ne $ExpectedRules.Count) {
        throw "Authorization ACL ACE count is not exact: $($Snapshot.path)"
    }
    $unmatched = [System.Collections.ArrayList]::new()
    foreach ($actualRule in $actualRules) {
        if ([int]$actualRule.access_type -ne
            [int][System.Security.AccessControl.AccessControlType]::Allow) {
            throw "Authorization ACL contains a non-Allow ACE: $($Snapshot.path)"
        }
        if ([bool]$actualRule.inherited -ne $RulesMustBeInherited) {
            throw "Authorization ACL ACE inheritance is not exact: $($Snapshot.path)"
        }
        [void]$unmatched.Add($actualRule)
    }
    foreach ($expectedRule in $ExpectedRules) {
        $matchingIndex = -1
        for ($index = 0; $index -lt $unmatched.Count; $index++) {
            if (Test-DemoAuthorizationAclRuleExact $unmatched[$index] $expectedRule) {
                $matchingIndex = $index
                break
            }
        }
        if ($matchingIndex -lt 0) {
            throw "Authorization ACL exact ACE policy mismatch: $($Snapshot.path)"
        }
        $unmatched.RemoveAt($matchingIndex)
    }
    if ($unmatched.Count -ne 0) {
        throw "Authorization ACL contains an unexpected ACE: $($Snapshot.path)"
    }
}

function Assert-DemoAuthorizationParentAclSnapshot(
    $Snapshot,
    [System.Security.Principal.SecurityIdentifier] $GatewaySid,
    [System.Security.Principal.SecurityIdentifier] $SystemSid,
    [System.Security.Principal.SecurityIdentifier] $AdministratorsSid
) {
    if ([string]$Snapshot.owner_sid -cne $AdministratorsSid.Value) {
        throw "Authorization directory owner is not BUILTIN\Administrators: $($Snapshot.path)"
    }
    if (-not [bool]$Snapshot.protected) {
        throw "Authorization directory DACL is not protected: $($Snapshot.path)"
    }
    $directoryInheritance = [System.Security.AccessControl.InheritanceFlags](
        [int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $expectedRules = @(
        New-DemoAuthorizationAclRule $SystemSid `
            ([System.Security.AccessControl.FileSystemRights]::FullControl) `
            $false $directoryInheritance `
            ([System.Security.AccessControl.PropagationFlags]::None)
        New-DemoAuthorizationAclRule $AdministratorsSid `
            ([System.Security.AccessControl.FileSystemRights]::FullControl) `
            $false $directoryInheritance `
            ([System.Security.AccessControl.PropagationFlags]::None)
        New-DemoAuthorizationAclRule $GatewaySid `
            ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) `
            $false ([System.Security.AccessControl.InheritanceFlags]::None) `
            ([System.Security.AccessControl.PropagationFlags]::None)
        New-DemoAuthorizationAclRule $GatewaySid `
            ([System.Security.AccessControl.FileSystemRights]::Read) `
            $false ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit) `
            ([System.Security.AccessControl.PropagationFlags]::InheritOnly)
    )
    Assert-DemoAuthorizationAclRuleSet $Snapshot $expectedRules $false
}

function Assert-DemoAuthorizationChildAclSnapshot(
    $Snapshot,
    [System.Security.Principal.SecurityIdentifier] $GatewaySid,
    [System.Security.Principal.SecurityIdentifier] $SystemSid,
    [System.Security.Principal.SecurityIdentifier] $AdministratorsSid
) {
    if (-not ([string]$Snapshot.owner_sid -ceq $AdministratorsSid.Value)) {
        throw "Authorization artifact owner is not BUILTIN\Administrators: $($Snapshot.path)"
    }
    if ([bool]$Snapshot.protected) {
        throw "Authorization artifact must inherit its parent ACL: $($Snapshot.path)"
    }
    $expectedRules = @(
        New-DemoAuthorizationAclRule $SystemSid `
            ([System.Security.AccessControl.FileSystemRights]::FullControl) `
            $true ([System.Security.AccessControl.InheritanceFlags]::None) `
            ([System.Security.AccessControl.PropagationFlags]::None)
        New-DemoAuthorizationAclRule $AdministratorsSid `
            ([System.Security.AccessControl.FileSystemRights]::FullControl) `
            $true ([System.Security.AccessControl.InheritanceFlags]::None) `
            ([System.Security.AccessControl.PropagationFlags]::None)
        New-DemoAuthorizationAclRule $GatewaySid `
            ([System.Security.AccessControl.FileSystemRights]::Read) `
            $true ([System.Security.AccessControl.InheritanceFlags]::None) `
            ([System.Security.AccessControl.PropagationFlags]::None)
    )
    Assert-DemoAuthorizationAclRuleSet $Snapshot $expectedRules $true
}

function ConvertTo-DemoAuthorizationChildInventory([object[]] $Children) {
    $names = [System.Collections.Generic.List[string]]::new()
    $seenNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($child in @($Children)) {
        foreach ($requiredProperty in @('Name', 'FullName', 'PSIsContainer', 'Attributes')) {
            if ($null -eq $child.PSObject.Properties[$requiredProperty]) {
                throw 'Authorization child inventory entry is incomplete or ambiguous.'
            }
        }
        if ([bool]$child.PSIsContainer -or
            [string]$child.Name -cnotmatch '^mt5-read-only-authorization-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$' -or
            ([System.IO.FileAttributes]$child.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Unexpected authorization artifact: $($child.FullName)"
        }
        if (-not $seenNames.Add([string]$child.Name)) {
            throw "Duplicate authorization artifact inventory entry: $($child.Name)"
        }
        $names.Add([string]$child.Name)
    }
    [string[]]$sortedNames = @($names)
    [array]::Sort($sortedNames, [System.StringComparer]::Ordinal)
    return [pscustomobject]@{
        children = @($Children)
        canonical_names = $sortedNames
    }
}

function Get-DemoAuthorizationChildInventory {
    $children = @(Get-ChildItem -LiteralPath $demoAuthorization -Force -ErrorAction Stop)
    return (ConvertTo-DemoAuthorizationChildInventory $children)
}

function Assert-DemoAuthorizationChildInventoryStable(
    [string[]] $ValidatedNames,
    [string[]] $FinalNames
) {
    [string[]]$validated = @($ValidatedNames)
    [string[]]$final = @($FinalNames)
    [array]::Sort($validated, [System.StringComparer]::Ordinal)
    [array]::Sort($final, [System.StringComparer]::Ordinal)
    if ($validated.Count -ne $final.Count) {
        throw 'Authorization artifact inventory changed after validation.'
    }
    for ($index = 0; $index -lt $validated.Count; $index++) {
        if ($validated[$index] -cne $final[$index]) {
            throw 'Authorization artifact inventory changed after validation.'
        }
    }
}

function Set-ExactDemoAuthorizationAcl {
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($administratorsSid)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($principal in @($systemSid, $administratorsSid)) {
        $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $gatewaySid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    ))
    $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $gatewaySid,
        [System.Security.AccessControl.FileSystemRights]::Read,
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [System.Security.AccessControl.PropagationFlags]::InheritOnly,
        [System.Security.AccessControl.AccessControlType]::Allow
    ))
    $validatedInventory = Get-DemoAuthorizationChildInventory
    if ($validatedInventory.children.Count -gt 0) {
        $current = Get-Acl -LiteralPath $demoAuthorization -ErrorAction Stop
        $parentSnapshot = Get-DemoAuthorizationAclSnapshot $current $demoAuthorization
        Assert-DemoAuthorizationParentAclSnapshot `
            $parentSnapshot $gatewaySid $systemSid $administratorsSid
        foreach ($authorizationChild in @($validatedInventory.children)) {
            $childItem = Get-Item -LiteralPath $authorizationChild.FullName `
                -Force -ErrorAction Stop
            if ($childItem.PSIsContainer -or
                $childItem.Name -cnotmatch '^mt5-read-only-authorization-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$' -or
                ($childItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw "Unexpected authorization artifact: $($childItem.FullName)"
            }
            $childSecurity = Get-Acl -LiteralPath $childItem.FullName -ErrorAction Stop
            $childSnapshot = Get-DemoAuthorizationAclSnapshot `
                $childSecurity $childItem.FullName
            Assert-DemoAuthorizationChildAclSnapshot `
                $childSnapshot $gatewaySid $systemSid $administratorsSid
        }
    } else {
        Set-Acl -LiteralPath $demoAuthorization -AclObject $security
        if ($ProgressPath) {
            $progressRecord = [pscustomobject]@{
                path = $demoAuthorization
                applied_at_utc = [DateTime]::UtcNow.ToString('o')
            }
            [System.IO.File]::AppendAllText(
                $ProgressPath,
                (($progressRecord | ConvertTo-Json -Compress) + [Environment]::NewLine),
                [System.Text.UTF8Encoding]::new($false)
            )
        }
    }
    $finalInventory = Get-DemoAuthorizationChildInventory
    Assert-DemoAuthorizationChildInventoryStable `
        $validatedInventory.canonical_names $finalInventory.canonical_names
}

$read = [System.Security.AccessControl.FileSystemRights]::Read
$readExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$modify = [System.Security.AccessControl.FileSystemRights]::Modify
$appendOnly = [System.Security.AccessControl.FileSystemRights](
    [int][System.Security.AccessControl.FileSystemRights]::Read -bor
    [int][System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [int][System.Security.AccessControl.FileSystemRights]::Synchronize
)

if ($pinnedExistingConfig) {
    $configBeforeAclMutation = Assert-PinnedExistingBootstrapConfig `
        $configFile `
        $normalizedExpectedConfigSha256
    if (-not [bool]$configBeforeAclMutation.valid -or
        [string]$configBeforeAclMutation.validation_mode -cne 'PINNED_EXISTING_SHA256' -or
        [string]$configBeforeAclMutation.sha256 -cne $normalizedExpectedConfigSha256) {
        throw 'Pinned existing trading.yaml failed final pre-ACL validation.'
    }
}
Set-ExactAcl $root @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $true $false 'lab_root'
Set-ExactAcl $workspace @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $true $true
foreach ($protectedSourceDirectory in $protectedSourceDirectories) {
    Set-ExactTreeAcl $protectedSourceDirectory @($gatewaySid, $automatonSid) @($readExecute, $readExecute)
}
foreach ($protectedRootFile in @(
    '.gitignore', 'package.json', 'pnpm-lock.yaml',
    'pnpm-workspace.yaml', 'tsconfig.json', 'vitest.config.ts',
    'requirements-gateway-win-py314.lock', 'requirements-gateway.in',
    'requirements-mt5.txt', 'packages\cli\package.json', 'packages\cli\tsconfig.json'
) | ForEach-Object { Join-Path $workspace $_ }) {
    if (-not (Test-Path -LiteralPath $protectedRootFile -PathType Leaf)) {
        throw "Protected root file is absent: $protectedRootFile"
    }
    Set-ExactAcl $protectedRootFile @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $false $false
}
Set-ExactControlAcl
Set-ExactAcl $configFile @($gatewaySid) @($read) $false $false
if (Test-Path -LiteralPath $killSwitchFile -PathType Leaf) {
    Set-ExactAcl $killSwitchFile @($gatewaySid) @($read) $false $false
}
Set-ExactDemoAuthorizationAcl
Set-ExactAcl $ipc @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $true $false
Set-ExactAcl $automatonKeyFile @($gatewaySid) @($read) $false $false
Set-ExactAcl $observationKeyFile @($gatewaySid, $automatonSid) @($read, $read) $false $false
Set-ExactAcl $researchKeyFile @($gatewaySid, $automatonSid) @($read, $read) $false $false
Set-ExactTreeAcl $operational @($gatewaySid) @($modify) 'operational'
Set-ExactTreeAcl $research @($gatewaySid) @($modify)
Set-ExactAcl $audit @($gatewaySid) @($readExecute) $true $false
Set-ExactTreeAcl $auditSqlite @($gatewaySid) @($modify)
Set-ExactAcl $auditJournal @($gatewaySid) @($readExecute) $true $false
Set-ExactAcl $auditJournalFile @($gatewaySid) @($appendOnly) $false $false
Set-ExactAcl $logs @($gatewaySid) @($readExecute) $true $false 'logs_root'
Set-ExactTreeAcl $gatewayLogs @($gatewaySid) @($modify) 'gateway_logs'
Set-ExactAcl $securityLogs @($gatewaySid) @($readExecute) $true $false 'security_logs'
Set-ExactAcl $securityLogFile @($gatewaySid) @($appendOnly) $false $false
Set-ExactTreeAcl $state @($automatonSid) @($modify) 'automaton_state'

Write-Host 'Least-privilege ACLs applied. DEMO_EXECUTION remains disabled.'
